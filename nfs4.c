#define _GNU_SOURCE
#include <errno.h>
#include <error.h>
#include <grp.h>
#include <inttypes.h>
#include <nss.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

pthread_mutex_t _nss_nfs4_mutex_p = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _nss_nfs4_mutex_g = PTHREAD_MUTEX_INITIALIZER;
FILE *_nss_nfs4_passwd = NULL;
FILE *_nss_nfs4_group = NULL;

enum nss_status _nss_nfs4_setpwent( void );
enum nss_status _nss_nfs4_endpwent( void );
enum nss_status _nss_nfs4_getpwent_r( struct passwd *result, char *buffer,
                                      size_t buflen, int *errnop );
enum nss_status _nss_nfs4_getpwuid_r( uid_t uid, struct passwd *result,
                                      char *buffer, size_t buflen,
                                      int *errnop );
enum nss_status _nss_nfs4_getpwnam_r( const char *name, struct passwd *result,
                                      char *buffer, size_t buflen,
                                      int *errnop );

enum nss_status _nss_nfs4_setgrent( void );
enum nss_status _nss_nfs4_endgrent( void );
enum nss_status _nss_nfs4_getgrent_r( struct group *result, char *buffer,
                                      size_t buflen, int *errnop );
enum nss_status _nss_nfs4_getgrgid_r( gid_t uid, struct group *result,
                                      char *buffer, size_t buflen,
                                      int *errnop );
enum nss_status _nss_nfs4_getgrnam_r( const char *name, struct group *result,
                                      char *buffer, size_t buflen,
                                      int *errnop );

enum nss_status _nss_nfs4_setpwent( void ) {
    pthread_mutex_lock( &_nss_nfs4_mutex_p );
    if ( _nss_nfs4_passwd == NULL ) {
        _nss_nfs4_passwd = fopen( "/etc/passwd-nfs4", "r" );
    }
    pthread_mutex_unlock( &_nss_nfs4_mutex_p );
    if ( _nss_nfs4_passwd == NULL ) {
        return NSS_STATUS_UNAVAIL;
    }
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_nfs4_endpwent( void ) {
    pthread_mutex_lock( &_nss_nfs4_mutex_p );
    if ( _nss_nfs4_passwd != NULL ) {
        fclose( _nss_nfs4_passwd );
        _nss_nfs4_passwd = NULL;
    }
    pthread_mutex_unlock( &_nss_nfs4_mutex_p );
    return NSS_STATUS_SUCCESS;
}

// returns pointer to element in string, elements are divided by deliminer
// pos indicates which element to choose, indexing starts at 0
char *_nss_nfs4_getDeliminer( char *input, char deliminer, int pos ) {
    for ( int i = 0; i < pos; i++ ) {
        char *temp = strchr( input, deliminer );
        if ( temp == NULL ) {
            return NULL;
        }
        input = temp;
        input++;
    }
    return input;
}

// copies element in string at position `pos` into `dest`
// elements are divided by deliminer
// returns pointer to char right after the selected element
char *_nss_nfs4_copyDeliminer( char **dest, char *input, char deliminer,
                               int pos ) {
    input = _nss_nfs4_getDeliminer( input, deliminer, pos );
    if ( input == NULL )
        return NULL;

    // last char to copy
    char *max = strchr( input, deliminer );
    if ( max == NULL ) {
        max = input;
        while ( *max != '\n' || *max != '\0' )
            max++;
        *max = '\0';
    }

    if ( *dest == NULL ) {
        char *tmp = malloc( ( max - input ) + 1 );
        if ( tmp == NULL ) {
            return NULL;
        }
        *dest = tmp;
    }
    strncpy( *dest, input, max - input );
    ( *dest )[max - input] = '\0';
    return max;
}

// return element at position `pos` in `input` string interpreted as a number
unsigned int _nss_nfs4_numDeliminer( char *input, char deliminer, int pos ) {
    input = _nss_nfs4_getDeliminer( input, deliminer, pos );
    if ( input == NULL )
        return -1;

    char *end;
    unsigned int ret = strtoumax( input, &end, 10 );
    if ( *end != deliminer && *end != '\n' && *end != '\0' ) {
        return -1;
    }
    return ret;
}

// fill struct passwd based on `line`
enum nss_status _nss_nfs4_fillPasswd( char *line, struct passwd *result,
                                      char *buffer, size_t buflen, int *errnop,
                                      FILE *fileptr ) {
    char *linestart = line;
    char *lineend = line;
    size_t name_size = 0;
    size_t passwd_size = 0;
    char *name = NULL;
    char *passwd = NULL;
    enum nss_status ret = NSS_STATUS_SUCCESS;

    lineend = _nss_nfs4_copyDeliminer( &name, linestart, ':', 0 );
    if ( lineend == NULL ) {
        *errnop = ENOENT;
        ret = NSS_STATUS_NOTFOUND;
        goto end;
    }
    name_size = ( lineend - linestart ) + 1;
    // lineend points at ':'
    linestart = lineend + 1;

    lineend = _nss_nfs4_copyDeliminer( &passwd, linestart, ':', 0 );
    if ( lineend == NULL ) {
        *errnop = ENOENT;
        ret = NSS_STATUS_NOTFOUND;
        goto end;
    }
    passwd_size = ( lineend - linestart ) + 1;
    linestart = lineend + 1;

    if ( name_size + passwd_size + 3 > buflen ) {
        *errnop = ERANGE;
        ret = NSS_STATUS_TRYAGAIN;
        goto end;
    }

    // position of start of gecos,dir,shell
    size_t gds = name_size + passwd_size;

    buffer[gds] = '\0';
    result->pw_gecos = &buffer[gds];
    buffer[gds + 1] = '\0';
    result->pw_dir = &buffer[gds + 1];
    buffer[gds + 2] = '\0';
    result->pw_shell = &buffer[gds + 2];

    // don't count ending 0
    passwd_size -= 1;
    strncpy( &buffer[name_size], passwd, passwd_size );
    buffer[name_size + passwd_size] = '\0';
    result->pw_passwd = &buffer[name_size];

    // don't count ending 0
    name_size -= 1;
    strncpy( buffer, name, name_size );
    buffer[name_size] = '\0';
    result->pw_name = buffer;

    result->pw_uid = _nss_nfs4_numDeliminer( linestart, ':', 0 );
    if ( result->pw_uid == ( unsigned int )-1 ) {
        *errnop = ENOENT;
        ret = NSS_STATUS_NOTFOUND;
        goto end;
    }

    result->pw_gid = _nss_nfs4_numDeliminer( linestart, ':', 1 );
    if ( result->pw_gid == ( unsigned int )-1 ) {
        *errnop = ENOENT;
        ret = NSS_STATUS_NOTFOUND;
        goto end;
    }

    if ( ftell( fileptr ) == SEEK_END || feof( fileptr ) ) {
        *errnop = 0;
        ret = NSS_STATUS_NOTFOUND;
    }

end:
    free( name );
    free( passwd );
    return ret;
}

enum nss_status _nss_nfs4_getpwent_r( struct passwd *result, char *buffer,
                                      size_t buflen, int *errnop ) {
    enum nss_status ret = NSS_STATUS_SUCCESS;
    pthread_mutex_lock( &_nss_nfs4_mutex_p );
    if ( _nss_nfs4_passwd == NULL ) {
        ret = NSS_STATUS_UNAVAIL;
        goto end;
    }

    long tell = ftell( _nss_nfs4_passwd );
    char *line = NULL;
    size_t line_length = 0;

    if ( getline( &line, &line_length, _nss_nfs4_passwd ) > 0 ) {
        ret = _nss_nfs4_fillPasswd( line, result, buffer, buflen, errnop,
                                    _nss_nfs4_passwd );
    } else {
        ret = NSS_STATUS_NOTFOUND;
    }

    free( line );
    if ( ret == NSS_STATUS_TRYAGAIN && *errnop == ERANGE ) {
        fseek( _nss_nfs4_passwd, tell, SEEK_SET );
    }
end:
    pthread_mutex_unlock( &_nss_nfs4_mutex_p );
    return ret;
}

char *_nss_nfs4_removeRealm( char *line ) {
    char *ret = _nss_nfs4_getDeliminer( line, ':', 1 ) - 1;
    char *name = NULL;
    char *endofname = _nss_nfs4_copyDeliminer( &name, line, '@', 0 );
    size_t name_size = endofname - line;
    ret -= name_size;
    strncpy( ret, name, name_size );
    free( name );
    return ret;
}

enum nss_status _nss_nfs4_findPasswd( uid_t uid, const char *name,
                                      struct passwd *result, char *buffer,
                                      size_t buflen, int *errnop ) {
    FILE *passwd_file = fopen( "/etc/passwd-nfs4", "r" );
    char *line = NULL;
    size_t line_length = 0;
    enum nss_status ret = NSS_STATUS_SUCCESS;
    unsigned int my_uid = uid + 1;
    char *my_name = NULL;
    char *real_line = NULL;

    if ( name != NULL ) {
        do {
            free( my_name );
            my_name = NULL;
            getline( &line, &line_length, passwd_file );
            _nss_nfs4_copyDeliminer( &my_name, line, ':', 0 );
        } while ( my_name != NULL && strcmp( my_name, name ) &&
                  !feof( passwd_file ) );
        real_line = line;
        if ( my_name == NULL || strcmp( my_name, name ) ) {
            goto fail;
        }
    } else {
        do {
            getline( &line, &line_length, passwd_file );
            my_uid = _nss_nfs4_numDeliminer( line, ':', 2 );
        } while ( my_uid != ( unsigned int )-1 && my_uid != uid &&
                  !feof( passwd_file ) );
        real_line = line;
        if ( my_uid == ( unsigned int )-1 || my_uid != uid ) {
            goto fail;
        }
        line = _nss_nfs4_removeRealm( line );
    }

    ret = _nss_nfs4_fillPasswd( line, result, buffer, buflen, errnop,
                                passwd_file );

    free( real_line );
    free( my_name );
    fclose( passwd_file );
    return ret;

fail:
    free( real_line );
    free( my_name );
    fclose( passwd_file );
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_nfs4_getpwuid_r( uid_t uid, struct passwd *result,
                                      char *buffer, size_t buflen,
                                      int *errnop ) {
    return _nss_nfs4_findPasswd( uid, NULL, result, buffer, buflen, errnop );
}

enum nss_status _nss_nfs4_getpwnam_r( const char *name, struct passwd *result,
                                      char *buffer, size_t buflen,
                                      int *errnop ) {
    return _nss_nfs4_findPasswd( 0, name, result, buffer, buflen, errnop );
}

enum nss_status _nss_nfs4_setgrent( void ) {
    pthread_mutex_lock( &_nss_nfs4_mutex_g );
    if ( _nss_nfs4_group == NULL ) {
        _nss_nfs4_group = fopen( "/etc/group-nfs4", "r" );
    }
    pthread_mutex_unlock( &_nss_nfs4_mutex_g );
    if ( _nss_nfs4_group == NULL ) {
        return NSS_STATUS_UNAVAIL;
    }
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_nfs4_endgrent( void ) {
    pthread_mutex_lock( &_nss_nfs4_mutex_g );
    if ( _nss_nfs4_group != NULL ) {
        fclose( _nss_nfs4_group );
        _nss_nfs4_group = NULL;
    }
    pthread_mutex_unlock( &_nss_nfs4_mutex_g );
    return NSS_STATUS_SUCCESS;
}

// returns number of elements in string `start` based on divider `deliminer`
// set end to end of the string
size_t numberOfElements( char *start, char **end, char deliminer ) {
    *end = start;
    if ( *start == '\n' || *start == '\0' )
        return 0;

    size_t ret = 1;
    while ( ( start = strchr( start, deliminer ) ) != NULL ) {
        ret++;
        start++;
        *end = start;
    }
    while ( **end != '\n' && **end != '\0' )
        ( *end )++;
    return ret;
}

// copy group members to `dest`, replace `deliminer` with \0 and setup
// pointers to members in `data`
void copyGroupMembers( char *dest, char **data, char *start, char *end,
                       char deliminer ) {
    *end = '\0';
    memcpy( dest, start, ( end - start ) + 1 );
    size_t pos = 0;
    while ( 1 ) {
        data[pos] = dest;
        dest = strchr( dest, deliminer );
        pos++;
        if ( dest == NULL ) {
            break;
        } else {
            *dest = '\0';
            dest++;
        }
    }
    data[pos] = NULL;
}

enum nss_status _nss_nfs4_fillGroup( char *line, struct group *result,
                                     char *buffer, size_t buflen, int *errnop,
                                     FILE *fileptr ) {
    char *linestart = line;
    char *lineend = line;
    size_t name_size = 0;
    size_t passwd_size = 0;
    char *name = NULL;
    char *passwd = NULL;
    enum nss_status ret = NSS_STATUS_SUCCESS;

    lineend = _nss_nfs4_copyDeliminer( &name, linestart, ':', 0 );
    if ( lineend == NULL ) {
        *errnop = ENOENT;
        ret = NSS_STATUS_NOTFOUND;
        goto end;
    }
    name_size = ( lineend - linestart ) + 1;
    // linestart points to ':'
    linestart = lineend + 1;

    lineend = _nss_nfs4_copyDeliminer( &passwd, linestart, ':', 0 );
    if ( lineend == NULL ) {
        *errnop = ENOENT;
        ret = NSS_STATUS_NOTFOUND;
        goto end;
    }
    passwd_size = ( lineend - linestart ) + 1;
    linestart = lineend + 1;

    if ( name_size + passwd_size > buflen ) {
        *errnop = ERANGE;
        ret = NSS_STATUS_TRYAGAIN;
        goto end;
    }

    // don't count ending 0
    passwd_size -= 1;
    strncpy( &buffer[name_size], passwd, passwd_size );
    buffer[name_size + passwd_size] = '\0';
    result->gr_passwd = &buffer[name_size];

    // don't count ending 0
    name_size -= 1;
    strncpy( buffer, name, name_size );
    buffer[name_size] = '\0';
    result->gr_name = buffer;

    result->gr_gid = _nss_nfs4_numDeliminer( linestart, ':', 0 );
    if ( result->gr_gid == ( unsigned int )-1 ) {
        *errnop = ENOENT;
        ret = NSS_STATUS_NOTFOUND;
        goto end;
    }

    linestart = strchr( linestart, ':' );
    if ( linestart == NULL ) {
        *errnop = ENOENT;
        ret = NSS_STATUS_NOTFOUND;
        goto end;
    }
    linestart++;

    // +1 because NULL terminated
    size_t num_of_groups = numberOfElements( linestart, &lineend, ',' ) + 1;
    size_t complete_size = name_size + passwd_size +
                           num_of_groups * sizeof( char * ) +
                           ( lineend - linestart ) + 1;
    char mess[1024];
    sprintf( mess, "struct group requires %zu bytes", complete_size );
    if ( complete_size > buflen ) {
        *errnop = ERANGE;
        ret = NSS_STATUS_TRYAGAIN;
        goto end;
    }

    char *user_buffer =
        &buffer[name_size + passwd_size + 2 + sizeof( char * ) * num_of_groups];
    char **group_members = ( void * )&buffer[name_size + passwd_size + 2];
    copyGroupMembers( user_buffer, group_members, linestart, lineend, ',' );
    result->gr_mem = group_members;

    if ( feof( fileptr ) ) {
        *errnop = 0;
        ret = NSS_STATUS_NOTFOUND;
    }

end:
    free( name );
    free( passwd );
    return ret;
}

enum nss_status _nss_nfs4_getgrent_r( struct group *result, char *buffer,
                                      size_t buflen, int *errnop ) {
    enum nss_status ret = NSS_STATUS_SUCCESS;
    pthread_mutex_lock( &_nss_nfs4_mutex_g );
    if ( _nss_nfs4_group == NULL ) {
        ret = NSS_STATUS_UNAVAIL;
        goto end;
    }

    long tell = ftell( _nss_nfs4_group );
    char *line = NULL;
    size_t line_length = 0;

    if ( getline( &line, &line_length, _nss_nfs4_group ) > 0 ) {
        ret = _nss_nfs4_fillGroup( line, result, buffer, buflen, errnop,
                                   _nss_nfs4_group );
    } else {
        ret = NSS_STATUS_NOTFOUND;
    }

    free( line );
    if ( ret == NSS_STATUS_TRYAGAIN && *errnop == ERANGE ) {
        fseek( _nss_nfs4_group, tell, SEEK_SET );
    }
end:
    pthread_mutex_unlock( &_nss_nfs4_mutex_g );
    return ret;
}

enum nss_status _nss_nfs4_findGroup( gid_t gid, const char *name,
                                     struct group *result, char *buffer,
                                     size_t buflen, int *errnop ) {
    FILE *group_file = fopen( "/etc/group-nfs4", "r" );
    char *line = NULL;
    size_t line_length = 0;
    enum nss_status ret = NSS_STATUS_SUCCESS;
    unsigned int my_gid = gid + 1;
    char *my_name = NULL;

    if ( name != NULL ) {
        do {
            free( my_name );
            my_name = NULL;
            getline( &line, &line_length, group_file );
            _nss_nfs4_copyDeliminer( &my_name, line, ':', 0 );
        } while ( my_name != NULL && strcmp( my_name, name ) &&
                  !feof( group_file ) );
        if ( my_name == NULL || strcmp( my_name, name ) ) {
            goto fail;
        }
    } else {
        do {
            getline( &line, &line_length, group_file );
            my_gid = _nss_nfs4_numDeliminer( line, ':', 2 );
        } while ( my_gid != ( unsigned int )-1 && my_gid != gid &&
                  !feof( group_file ) );
        if ( my_gid == ( unsigned int )-1 || my_gid != gid ) {
            goto fail;
        }
    }

    ret =
        _nss_nfs4_fillGroup( line, result, buffer, buflen, errnop, group_file );

    free( line );
    free( my_name );
    fclose( group_file );

    return ret;

fail:
    free( line );
    free( my_name );
    fclose( group_file );
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_nfs4_getgrgid_r( gid_t gid, struct group *result,
                                      char *buffer, size_t buflen,
                                      int *errnop ) {
    return _nss_nfs4_findGroup( gid, NULL, result, buffer, buflen, errnop );
}

enum nss_status _nss_nfs4_getgrnam_r( const char *name, struct group *result,
                                      char *buffer, size_t buflen,
                                      int *errnop ) {
    return _nss_nfs4_findGroup( 0, name, result, buffer, buflen, errnop );
}
