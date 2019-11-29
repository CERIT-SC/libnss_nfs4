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

pthread_key_t _nss_nfs4_passwd;
pthread_key_t _nss_nfs4_group;
#ifdef DEBUG
pthread_key_t _nss_nfs4_debug_file;
#endif

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

void __attribute__((constructor)) nfs4Constructor();
void __attribute__((destructor)) nfs4Destructor();

void nfs4Constructor() {
    int perror = 0;
    if( ( perror = pthread_key_create( &_nss_nfs4_passwd, NULL ) ) )
        error( EXIT_FAILURE, perror, "pthread_key_create" );
    if( ( perror = pthread_key_create( &_nss_nfs4_group, NULL ) ) )
        error( EXIT_FAILURE, perror, "pthread_key_create" );
#ifdef DEBUG
    if( ( perror = pthread_key_create( &_nss_nfs4_debug_file, NULL ) ) )
        error( EXIT_FAILURE, perror, "pthread_key_create" );
#endif
}

void nfs4Destructor() {
    pthread_key_delete( _nss_nfs4_passwd );
    pthread_key_delete( _nss_nfs4_group );
#ifdef DEBUG
    pthread_key_delete( _nss_nfs4_debug_file );
#endif
}

#ifdef DEBUG
void _nss_nfs4_debug( const char *message ) {
    char time_str[9];
    time_t t = time( NULL );
    struct tm *timemachine = localtime( &t );
    strftime( time_str, 9, "%H:%M:%S", timemachine );
    FILE *debug_file = pthread_getspecific( _nss_nfs4_debug_file );
    if ( debug_file != NULL ) {
        fprintf( debug_file, "nss_nfs4: %s: %s\n", time_str,
                 message );
    }
}

void _nss_nfs4_debug_passwd( const struct passwd *pw ) {
    char mess[2048];
    sprintf( mess,
             "RETURNED:\nName: %s\nPassword: %s\nUID: %i\nGID: %i\nInfo: "
             "%s\nDir: %s\nShell: %s\n",
             pw->pw_name, pw->pw_passwd, pw->pw_uid, pw->pw_gid, pw->pw_gecos,
             pw->pw_dir, pw->pw_shell );
    _nss_nfs4_debug( mess );
}

void _nss_nfs4_debug_group( struct group *gr ) {
    char mess[2048];
    sprintf( mess, "RETURNED:\nName: %s\nPassword: %s\nGID: %i\n", gr->gr_name,
             gr->gr_passwd, gr->gr_gid );
    _nss_nfs4_debug( mess );
}
#endif

enum nss_status _nss_nfs4_setpwent( void ) {
#ifdef DEBUG
    FILE *debug_file = pthread_getspecific( _nss_nfs4_debug_file );
    if ( debug_file == NULL ) {
        debug_file = fopen( "/tmp/nss_nfs4", "a+" );
        int perror = 0;
        if( ( perror = pthread_setspecific( _nss_nfs4_debug_file, debug_file ) ) )
            error( EXIT_FAILURE, perror, "pthread_setspecific" );
        chmod( "/tmp/nss_nfs4",
               S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );
    }
    if ( _nss_nfs4_debug_file == NULL )
        return NSS_STATUS_UNAVAIL;
#endif
    FILE *passwd_file = pthread_getspecific( _nss_nfs4_passwd );
    if ( passwd_file == NULL ) {
        passwd_file = fopen( "/etc/passwd-nfs4", "r" );
        int perror = 0;
        if( ( perror = pthread_setspecific( _nss_nfs4_passwd, passwd_file ) ) )
            error( EXIT_FAILURE, perror, "pthread_setspecific" );
    }
    if ( passwd_file == NULL ) {
#ifdef DEBUG
        _nss_nfs4_debug( "Couldn't open /etc/passwd-nfs4" );
#endif
        return NSS_STATUS_UNAVAIL;
    }
#ifdef DEBUG
    _nss_nfs4_debug( "Library initialized" );
#endif
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_nfs4_endpwent( void ) {
    FILE *passwd_file = pthread_getspecific( _nss_nfs4_passwd );
    if ( passwd_file != NULL ) {
        fclose( passwd_file );
        int perror = 0;
        if( ( perror = pthread_setspecific( _nss_nfs4_passwd, NULL ) ) )
            error( EXIT_FAILURE, perror, "pthread_setspecific" );
    }
#ifdef DEBUG
    FILE *debug_file = pthread_getspecific( _nss_nfs4_debug_file );
    if ( debug_file != NULL ) {
        fclose( debug_file );
        int perror = 0;
        if( ( perror = pthread_setspecific( _nss_nfs4_debug_file, NULL ) ) )
            error( EXIT_FAILURE, perror, "pthread_setspecific" );
    }
#endif
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
#ifdef DEBUG
            _nss_nfs4_debug( "Couldn't malloc pointer" );
#endif
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
#ifdef DEBUG
        _nss_nfs4_debug( "Expected a number, but didn't get a number" );
#endif
        return -1;
    }
    return ret;
}

// fill struct passwd based on `line`
enum nss_status _nss_nfs4_fillPasswd( char *line, struct passwd *result,
                                      char *buffer, size_t buflen,
                                      int *errnop ) {
    char *linestart = line;
    char *lineend = line;
    size_t name_size = 0;
    size_t passwd_size = 0;
    char *name = NULL;
    char *passwd = NULL;
    enum nss_status ret = NSS_STATUS_SUCCESS;

    lineend = _nss_nfs4_copyDeliminer( &name, linestart, ':', 0 );
    if ( lineend == NULL ) {
#ifdef DEBUG
        _nss_nfs4_debug( "Line is empty" );
#endif
        *errnop = ENOENT;
        ret = NSS_STATUS_NOTFOUND;
        goto end;
    }
    name_size = ( lineend - linestart ) + 1;
    // lineend points at ':'
    linestart = lineend + 1;

    lineend = _nss_nfs4_copyDeliminer( &passwd, linestart, ':', 0 );
    if ( lineend == NULL ) {
#ifdef DEBUG
        _nss_nfs4_debug( "Found a line withoug a passwd field" );
#endif
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
#ifdef DEBUG
        _nss_nfs4_debug( "Found a line withoug a UID field" );
#endif
        *errnop = ENOENT;
        ret = NSS_STATUS_NOTFOUND;
        goto end;
    }

    result->pw_gid = _nss_nfs4_numDeliminer( linestart, ':', 1 );
    if ( result->pw_gid == ( unsigned int )-1 ) {
#ifdef DEBUG
        _nss_nfs4_debug( "Found a line without a gid field" );
#endif
        *errnop = ENOENT;
        ret = NSS_STATUS_NOTFOUND;
        goto end;
    }

    FILE *passwd_file = pthread_getspecific( _nss_nfs4_passwd );
    if ( ftell( passwd_file ) == SEEK_END || feof( passwd_file ) ) {
#ifdef DEBUG
        _nss_nfs4_debug( "EOF" );
#endif
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
    FILE *passwd_file = pthread_getspecific( _nss_nfs4_passwd );
    if ( passwd_file == NULL )
        return NSS_STATUS_UNAVAIL;
#ifdef DEBUG
    _nss_nfs4_debug( "\nREQUEST FOR PASSWD ENTRY" );
#endif

    long tell = ftell( passwd_file );
    char *line = NULL;
    size_t line_length = 0;
    enum nss_status ret = NSS_STATUS_SUCCESS;
    if ( getline( &line, &line_length, passwd_file ) > 0 ) {
        ret = _nss_nfs4_fillPasswd( line, result, buffer, buflen, errnop );
    } else {
        ret = NSS_STATUS_NOTFOUND;
    }
    free( line );
#ifdef DEBUG
    _nss_nfs4_debug_passwd( result );
#endif
    if ( ret == NSS_STATUS_TRYAGAIN && *errnop == ERANGE ) {
        fseek( passwd_file, tell, SEEK_SET );
    }
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
    FILE *passwd_file = pthread_getspecific( _nss_nfs4_passwd );
    char *line = NULL;
    size_t line_length = 0;
    enum nss_status ret = NSS_STATUS_SUCCESS;
    long tell = ftell( passwd_file );
    fseek( passwd_file, 0, SEEK_SET );
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
#ifdef DEBUG
            _nss_nfs4_debug( "DIDN'T FIND SPECIFIED USER\n" );
#endif
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
#ifdef DEBUG
            _nss_nfs4_debug( "DIDN'T FIND SPECIFIED USER\n" );
#endif
            goto fail;
        }
        line = _nss_nfs4_removeRealm( line );
    }

    ret = _nss_nfs4_fillPasswd( line, result, buffer, buflen, errnop );

    free( real_line );
    free( my_name );
    fseek( passwd_file, tell, SEEK_SET );
    return ret;

fail:
    free( real_line );
    free( my_name );
    fseek( passwd_file, tell, SEEK_SET );
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_nfs4_getpwuid_r( uid_t uid, struct passwd *result,
                                      char *buffer, size_t buflen,
                                      int *errnop ) {
    FILE *passwd_file = pthread_getspecific( _nss_nfs4_passwd );
    enum nss_status ret = NSS_STATUS_SUCCESS;
    if ( passwd_file == NULL &&
         ( ret = _nss_nfs4_setpwent() ) != NSS_STATUS_SUCCESS ) {
        _nss_nfs4_endpwent();
        return ret;
    }
    char mess[1024];
    sprintf( mess, "\nREQUEST FOR USER BASED ON UID: %i", uid );
#ifdef DEBUG
    _nss_nfs4_debug( mess );
#endif
    ret = _nss_nfs4_findPasswd( uid, NULL, result, buffer, buflen, errnop );
#ifdef DEBUG
    if ( ret == NSS_STATUS_SUCCESS )
        _nss_nfs4_debug_passwd( result );
#endif
    _nss_nfs4_endpwent();
    return ret;
}

enum nss_status _nss_nfs4_getpwnam_r( const char *name, struct passwd *result,
                                      char *buffer, size_t buflen,
                                      int *errnop ) {
    FILE *passwd_file = pthread_getspecific( _nss_nfs4_passwd );
    enum nss_status ret = NSS_STATUS_SUCCESS;
    if ( passwd_file == NULL &&
         ( ret = _nss_nfs4_setpwent() ) != NSS_STATUS_SUCCESS ) {
        _nss_nfs4_endpwent();
        return ret;
    }
    char mess[1024];
    sprintf( mess, "\nREQUEST FOR USER BASED ON NAME: %s", name );
#ifdef DEBUG
    _nss_nfs4_debug( mess );
#endif
    ret = _nss_nfs4_findPasswd( 0, name, result, buffer, buflen, errnop );
#ifdef DEBUG
    if ( ret == NSS_STATUS_SUCCESS )
        _nss_nfs4_debug_passwd( result );
#endif
    _nss_nfs4_endpwent();
    return ret;
}

enum nss_status _nss_nfs4_setgrent( void ) {
#ifdef DEBUG
    FILE *debug_file = pthread_getspecific( _nss_nfs4_debug_file );
    if ( debug_file == NULL ) {
        debug_file = fopen( "/tmp/nss_nfs4", "a+" );
        int perror = 0;
        if( ( perror = pthread_setspecific( _nss_nfs4_debug_file, debug_file ) ) )
            error( EXIT_FAILURE, perror, "pthread_setspecific" );
        chmod( "/tmp/nss_nfs4",
               S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );
    }
    if ( _nss_nfs4_debug_file == NULL )
        return NSS_STATUS_UNAVAIL;
#endif
    FILE *group_file = pthread_getspecific( _nss_nfs4_group );
    if ( group_file == NULL ) {
        group_file = fopen( "/etc/group-nfs4", "r" );
        int perror = 0;
        if( ( perror = pthread_setspecific( _nss_nfs4_group, group_file ) ) )
            error( EXIT_FAILURE, perror, "pthread_setspecific" );
    }
    if ( group_file == NULL ) {
#ifdef DEBUG
        _nss_nfs4_debug( "Couldn't open /etc/group-nfs4" );
#endif
        return NSS_STATUS_UNAVAIL;
    }
#ifdef DEBUG
    _nss_nfs4_debug( "Library initialized" );
#endif
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_nfs4_endgrent( void ) {
    FILE *group_file = pthread_getspecific( _nss_nfs4_group );
    if ( group_file != NULL ) {
        fclose( group_file );
        int perror = 0;
        if( ( perror = pthread_setspecific( _nss_nfs4_group, NULL ) ) )
            error( EXIT_FAILURE, perror, "pthread_setspecific" );
    }
#ifdef DEBUG
    FILE *debug_file = pthread_getspecific( _nss_nfs4_debug_file );
    if ( debug_file != NULL ) {
        fclose( debug_file );
        int perror = 0;
        if( ( perror = pthread_setspecific( _nss_nfs4_debug_file, NULL ) ) )
            error( EXIT_FAILURE, perror, "pthread_setspecific" );
    }
#endif
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
                                     char *buffer, size_t buflen,
                                     int *errnop ) {
    char *linestart = line;
    char *lineend = line;
    size_t name_size = 0;
    size_t passwd_size = 0;
    char *name = NULL;
    char *passwd = NULL;
    enum nss_status ret = NSS_STATUS_SUCCESS;

    lineend = _nss_nfs4_copyDeliminer( &name, linestart, ':', 0 );
    if ( lineend == NULL ) {
#ifdef DEBUG
        _nss_nfs4_debug( "Line is empty" );
#endif
        *errnop = ENOENT;
        ret = NSS_STATUS_NOTFOUND;
        goto end;
    }
    name_size = ( lineend - linestart ) + 1;
    // linestart points to ':'
    linestart = lineend + 1;

    lineend = _nss_nfs4_copyDeliminer( &passwd, linestart, ':', 0 );
    if ( lineend == NULL ) {
#ifdef DEBUG
        _nss_nfs4_debug( "Found a line withoug a passwd field" );
#endif
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
#ifdef DEBUG
        _nss_nfs4_debug( "Found a line withoug a GID field" );
#endif
        *errnop = ENOENT;
        ret = NSS_STATUS_NOTFOUND;
        goto end;
    }

    linestart = strchr( linestart, ':' );
    if ( linestart == NULL ) {
#ifdef DEBUG
        _nss_nfs4_debug( "Well, this shouldn't happen" );
#endif
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
#ifdef DEBUG
    _nss_nfs4_debug( mess );
#endif
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

    FILE *group_file = pthread_getspecific( _nss_nfs4_group );
    if ( feof( group_file ) ) {
#ifdef DEBUG
        _nss_nfs4_debug( "EOF" );
#endif
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
    FILE *group_file = pthread_getspecific( _nss_nfs4_group );
    if ( group_file == NULL )
        return NSS_STATUS_UNAVAIL;
#ifdef DEBUG
    _nss_nfs4_debug( "\nREQUEST FOR GROUP ENTRY" );
#endif

    long tell = ftell( group_file );
    char *line = NULL;
    size_t line_length = 0;
    enum nss_status ret = NSS_STATUS_SUCCESS;

    if ( getline( &line, &line_length, group_file ) > 0 ) {
        ret = _nss_nfs4_fillGroup( line, result, buffer, buflen, errnop );
    } else {
        ret = NSS_STATUS_NOTFOUND;
    }

    free( line );
#ifdef DEBUG
    _nss_nfs4_debug_group( result );
#endif
    if ( ret == NSS_STATUS_TRYAGAIN && *errnop == ERANGE ) {
        fseek( group_file, tell, SEEK_SET );
    }
    return ret;
}

enum nss_status _nss_nfs4_findGroup( gid_t gid, const char *name,
                                     struct group *result, char *buffer,
                                     size_t buflen, int *errnop ) {
    FILE *group_file = pthread_getspecific( _nss_nfs4_group );
    char *line = NULL;
    size_t line_length = 0;
    enum nss_status ret = NSS_STATUS_SUCCESS;
    long tell = ftell( group_file );
    fseek( group_file, 0, SEEK_SET );
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
#ifdef DEBUG
            _nss_nfs4_debug( "DIDN'T FIND SPECIFIED USER\n" );
#endif
            goto fail;
        }
    } else {
        do {
            getline( &line, &line_length, group_file );
            my_gid = _nss_nfs4_numDeliminer( line, ':', 2 );
        } while ( my_gid != ( unsigned int )-1 && my_gid != gid &&
                  !feof( group_file ) );
        if ( my_gid == ( unsigned int )-1 || my_gid != gid ) {
#ifdef DEBUG
            _nss_nfs4_debug( "DIDN'T FIND SPECIFIED USER\n" );
#endif
            goto fail;
        }
    }

    ret = _nss_nfs4_fillGroup( line, result, buffer, buflen, errnop );

    free( line );
    free( my_name );
    fseek( group_file, tell, SEEK_SET );

    return ret;

fail:
    free( line );
    free( my_name );
    fseek( group_file, tell, SEEK_SET );
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_nfs4_getgrgid_r( gid_t gid, struct group *result,
                                      char *buffer, size_t buflen,
                                      int *errnop ) {
    FILE *group_file = pthread_getspecific( _nss_nfs4_group );
    enum nss_status ret = NSS_STATUS_SUCCESS;
    if ( group_file == NULL &&
         ( ret = _nss_nfs4_setgrent() ) != NSS_STATUS_SUCCESS ) {
        _nss_nfs4_endgrent();
        return ret;
    }
    char mess[1024];
    sprintf( mess, "\nREQUEST FOR GROUP BASED ON GID: %i", gid );
#ifdef DEBUG
    _nss_nfs4_debug( mess );
#endif
    ret = _nss_nfs4_findGroup( gid, NULL, result, buffer, buflen, errnop );
#ifdef DEBUG
    if ( ret == NSS_STATUS_SUCCESS )
        _nss_nfs4_debug_group( result );
#endif
    _nss_nfs4_endgrent();
    return ret;
}

enum nss_status _nss_nfs4_getgrnam_r( const char *name, struct group *result,
                                      char *buffer, size_t buflen,
                                      int *errnop ) {
    FILE *group_file = pthread_getspecific( _nss_nfs4_group );
    enum nss_status ret = NSS_STATUS_SUCCESS;
    if ( group_file == NULL &&
         ( ret = _nss_nfs4_setgrent() ) != NSS_STATUS_SUCCESS ) {
        _nss_nfs4_endgrent();
        return ret;
    }
    char mess[1024];
    sprintf( mess, "\nREQUEST FOR GROUP BASED ON NAME: %s", name );
#ifdef DEBUG
    _nss_nfs4_debug( mess );
#endif
    ret = _nss_nfs4_findGroup( 0, name, result, buffer, buflen, errnop );
#ifdef DEBUG
    if ( ret == NSS_STATUS_SUCCESS )
        _nss_nfs4_debug_group( result );
#endif
    _nss_nfs4_endgrent();
    return ret;
}
