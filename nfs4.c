#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <inttypes.h>
#include <nss.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

FILE *__nfs4_passwd = NULL;
FILE *__nfs4_group = NULL;
FILE *__debug_file = NULL;

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

void __debug( const char *message ) {
    char time_str[9];
    time_t t = time( NULL );
    struct tm *timemachine = localtime( &t );
    strftime( time_str, 9, "%H:%M:%S", timemachine );
    if ( __debug_file != NULL ) {
        fprintf( __debug_file, "nss_nfs4: %s: %s\n", time_str, message );
    }
}

void __debug_passwd( const struct passwd *pw ) {
    char mess[2048];
    sprintf( mess,
             "RETURNED:\nName: %s\nPassword: %s\nUID: %i\nGID: %i\nInfo: "
             "%s\nDir: %s\nShell: %s\n",
             pw->pw_name, pw->pw_passwd, pw->pw_uid, pw->pw_gid, pw->pw_gecos,
             pw->pw_dir, pw->pw_shell );
    __debug( mess );
}

enum nss_status _nss_nfs4_setpwent( void ) {
    if ( __debug_file == NULL ) {
        __debug_file = fopen( "/tmp/nss_nfs4", "a+" );
        chmod( "/tmp/nss_nfs4",
               S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );
    }
    if ( __debug_file == NULL )
        return NSS_STATUS_UNAVAIL;
    if ( __nfs4_passwd == NULL )
        __nfs4_passwd = fopen( "/etc/passwd-nfs4", "r" );
    if ( __nfs4_passwd == NULL ) {
        __debug( "Couldn't open /etc/passwd-nfs4" );
        return NSS_STATUS_UNAVAIL;
    }
    __debug( "Library initialized" );
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_nfs4_endpwent( void ) {
    if ( __nfs4_passwd != NULL ) {
        fclose( __nfs4_passwd );
        __nfs4_passwd = NULL;
    }
    if ( __debug_file != NULL ) {
        fclose( __debug_file );
        __debug_file = NULL;
    }
    return NSS_STATUS_SUCCESS;
}

char *__getDeliminer( char *input, char deliminer, int pos ) {
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

char *__copyDeliminer( char **dest, char *input, char deliminer, int pos ) {
    input = __getDeliminer( input, deliminer, pos );
    if ( input == NULL )
        return NULL;

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
            __debug( "Couldn't malloc pointer" );
            return NULL;
        }
        *dest = tmp;
    }
    strncpy( *dest, input, max - input );
    ( *dest )[max - input] = '\0';
    return max;
}

unsigned int __numDeliminer( char *input, char deliminer, int pos ) {
    input = __getDeliminer( input, deliminer, pos );
    if ( input == NULL )
        return -1;

    char *end;
    unsigned int ret = strtoumax( input, &end, 10 );
    if ( *end != deliminer && *end != '\n' && *end != '\0' ) {
        __debug( "Expected a number, but didn't get a number" );
        return -1;
    }
    return ret;
}

enum nss_status __fillPasswd( char *line, struct passwd *result, char *buffer,
                              size_t buflen, int *errnop ) {
    char *linestart = line;
    char *lineend = line;
    size_t name_size = 0;
    size_t passwd_size = 0;
    char *name = NULL;
    char *passwd = NULL;

    lineend = __copyDeliminer( &name, linestart, ':', 0 );
    if ( lineend == NULL ) {
        __debug( "Line is empty" );
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    name_size = ( lineend - linestart ) + 1;
    linestart = lineend + 1;

    lineend = __copyDeliminer( &passwd, linestart, ':', 0 );
    if ( lineend == NULL ) {
        __debug( "Found a line withoug a passwd field" );
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    passwd_size = ( lineend - linestart ) + 1;
    linestart = lineend + 1;

    if ( name_size + passwd_size + 3 > buflen ) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
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

    result->pw_uid = __numDeliminer( linestart, ':', 0 );
    if ( result->pw_uid == ( unsigned int )-1 ) {
        __debug( "Found a line withoug a UID field" );
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }

    result->pw_gid = __numDeliminer( linestart, ':', 1 );
    if ( result->pw_gid == ( unsigned int )-1 ) {
        __debug( "Found a line without a gid field" );
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }

    if ( ftell( __nfs4_passwd ) == SEEK_END || feof( __nfs4_passwd ) ) {
        __debug( "EOF" );
        *errnop = 0;
        return NSS_STATUS_NOTFOUND;
    }
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_nfs4_getpwent_r( struct passwd *result, char *buffer,
                                      size_t buflen, int *errnop ) {
    if ( __nfs4_passwd == NULL )
        return NSS_STATUS_UNAVAIL;
    __debug( "\nREQUEST FOR PASSWD ENTRY" );
    if ( __nfs4_passwd == NULL )
        return NSS_STATUS_UNAVAIL;
    long tell = ftell( __nfs4_passwd );
    char *line = NULL;
    size_t line_length = 0;
    enum nss_status ret = NSS_STATUS_SUCCESS;
    if ( getline( &line, &line_length, __nfs4_passwd ) > 0 ) {
        ret = __fillPasswd( line, result, buffer, buflen, errnop );
        free( line );
    } else {
        ret = NSS_STATUS_NOTFOUND;
    }
    __debug_passwd( result );
    if ( ret == NSS_STATUS_TRYAGAIN && *errnop == ERANGE ) {
        fseek( __nfs4_passwd, tell, SEEK_SET );
    }
    return ret;
}

enum nss_status __findPasswd( uid_t uid, const char *name,
                              struct passwd *result, char *buffer,
                              size_t buflen, int *errnop ) {
    char *line = NULL;
    size_t line_length = 0;
    enum nss_status ret = NSS_STATUS_SUCCESS;
    long tell = ftell( __nfs4_passwd );
    fseek( __nfs4_passwd, 0, SEEK_SET );
    unsigned int my_uid = uid + 1;
    char *my_name = NULL;

    if ( name != NULL ) {
        do {
            free( my_name );
            my_name = NULL;
            getline( &line, &line_length, __nfs4_passwd );
            __copyDeliminer( &my_name, line, ':', 0 );
        } while ( my_name != NULL && strcmp( my_name, name ) &&
                  !feof( __nfs4_passwd ) );
        if ( my_name == NULL || strcmp( my_name, name ) ) {
            __debug( "DIDN'T FIND SPECIFIED USER\n" );
            goto fail;
        }
    } else {
        do {
            getline( &line, &line_length, __nfs4_passwd );
            my_uid = __numDeliminer( line, ':', 2 );
        } while ( my_uid != ( unsigned int )-1 && my_uid != uid &&
                  !feof( __nfs4_passwd ) );
        if ( my_uid == ( unsigned int )-1 || my_uid != uid ) {
            __debug( "DIDN'T FIND SPECIFIED USER\n" );
            goto fail;
        }
    }

    ret = __fillPasswd( line, result, buffer, buflen, errnop );

    free( line );
    free( my_name );
    fseek( __nfs4_passwd, tell, SEEK_SET );

    if ( ret == NSS_STATUS_TRYAGAIN )
        return NSS_STATUS_TRYAGAIN;

    return NSS_STATUS_SUCCESS;

fail:
    free( line );
    free( my_name );
    fseek( __nfs4_passwd, tell, SEEK_SET );
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_nfs4_getpwuid_r( uid_t uid, struct passwd *result,
                                      char *buffer, size_t buflen,
                                      int *errnop ) {
    int retcode = NSS_STATUS_SUCCESS;
    if ( __nfs4_passwd == NULL &&
         ( retcode = _nss_nfs4_setpwent() ) != NSS_STATUS_SUCCESS ) {
        _nss_nfs4_endpwent();
        return retcode;
    }
    char mess[1024];
    sprintf( mess, "\nREQUEST FOR USER BASED ON UID: %i", uid );
    __debug( mess );
    enum nss_status ret =
        __findPasswd( uid, NULL, result, buffer, buflen, errnop );
    if ( ret == NSS_STATUS_SUCCESS )
        __debug_passwd( result );
    _nss_nfs4_endpwent();
    return ret;
}

enum nss_status _nss_nfs4_getpwnam_r( const char *name, struct passwd *result,
                                      char *buffer, size_t buflen,
                                      int *errnop ) {
    int retcode = NSS_STATUS_SUCCESS;
    if ( __nfs4_passwd == NULL &&
         ( retcode = _nss_nfs4_setpwent() ) != NSS_STATUS_SUCCESS ) {
        _nss_nfs4_endpwent();
        return retcode;
    }
    char mess[1024];
    sprintf( mess, "\nREQUEST FOR USER BASED ON NAME: %s", name );
    __debug( mess );
    enum nss_status ret =
        __findPasswd( 0, name, result, buffer, buflen, errnop );
    if ( ret == NSS_STATUS_SUCCESS )
        __debug_passwd( result );
    _nss_nfs4_endpwent();
    return ret;
}

enum nss_status _nss_nfs4_setgrent( void ) {
    if ( __debug_file == NULL ) {
        __debug_file = fopen( "/tmp/nss_nfs4", "a+" );
        chmod( "/tmp/nss_nfs4",
               S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );
    }
    if ( __debug_file == NULL )
        return NSS_STATUS_UNAVAIL;
    if ( __nfs4_group == NULL )
        __nfs4_group = fopen( "/etc/group-nfs4", "r" );
    if ( __nfs4_group == NULL ) {
        __debug( "Couldn't open /etc/group-nfs4" );
        return NSS_STATUS_UNAVAIL;
    }
    __debug( "Library initialized" );
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_nfs4_endgrent( void ) {
    if ( __nfs4_group != NULL ) {
        fclose( __nfs4_group );
        __nfs4_group = NULL;
    }
    if ( __debug_file != NULL ) {
        fclose( __debug_file );
        __debug_file = NULL;
    }
    return NSS_STATUS_SUCCESS;
}

size_t numberOfElements( char *start, char **end, char deliminer ) {
    if ( *start == '\n' || *start == '\0' ) {
        while ( **end != '\n' && **end != '\0' )
            ( *end )++;
        return 0;
    }
    size_t ret = 1;
    *end = start;
    while ( ( start = strchr( start, deliminer ) ) != NULL ) {
        ret++;
        start++;
        *end = start;
    }
    while ( **end != '\n' && **end != '\0' )
        ( *end )++;
    return ret;
}

void copyGroupMembers( char *dest, char **data, char *start, char *end,
                       char deliminer ) {
    *end = '\0';
    memcpy( dest, start, ( end - start ) + 1 );
    size_t pos = 0;
    while ( 1 ) {
        data[pos] = dest;
        while ( *dest != deliminer && *dest != '\0' )
            dest++;
        pos++;
        if ( *dest == '\0' ) {
            break;
        } else {
            *dest = '\0';
            dest++;
        }
    }
    data[pos] = NULL;
}

enum nss_status __fillGroup( char *line, struct group *result, char *buffer,
                             size_t buflen, int *errnop ) {
    char *linestart = line;
    char *lineend = line;
    size_t name_size = 0;
    size_t passwd_size = 0;
    char *name = NULL;
    char *passwd = NULL;

    lineend = __copyDeliminer( &name, linestart, ':', 0 );
    if ( lineend == NULL ) {
        __debug( "Line is empty" );
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    name_size = ( lineend - linestart ) + 1;
    linestart = lineend + 1;

    lineend = __copyDeliminer( &passwd, linestart, ':', 0 );
    if ( lineend == NULL ) {
        __debug( "Found a line withoug a passwd field" );
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    passwd_size = ( lineend - linestart ) + 1;
    linestart = lineend + 1;

    if ( name_size + passwd_size > buflen ) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
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

    result->gr_gid = __numDeliminer( linestart, ':', 0 );
    if ( result->gr_gid == ( unsigned int )-1 ) {
        __debug( "Found a line withoug a GID field" );
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }

    linestart = strchr( linestart, ':' );
    if ( linestart == NULL ) {
        __debug( "Well, this shouldn't happen" );
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    linestart++;

    // +1 because NULL terminated
    size_t num_of_groups = numberOfElements( linestart, &lineend, ',' ) + 1;
    size_t complete_size = name_size + passwd_size +
                           num_of_groups * sizeof( char * ) +
                           ( lineend - linestart ) + 1;
    char mess[1024];
    sprintf( mess, "struct group requires %zu bytes", complete_size );
    __debug( mess );
    if ( complete_size > buflen ) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    char *user_buffer =
        &buffer[name_size + passwd_size + 2 + sizeof( char * ) * num_of_groups];
    char **group_members = ( void * )&buffer[name_size + passwd_size + 2];
    copyGroupMembers( user_buffer, group_members, linestart, lineend, ',' );
    result->gr_mem = group_members;

    if ( feof( __nfs4_group ) ) {
        __debug( "EOF" );
        *errnop = 0;
        return NSS_STATUS_NOTFOUND;
    }
    return NSS_STATUS_SUCCESS;
}

void __debug_group( struct group *gr ) {
    char mess[2048];
    sprintf( mess, "RETURNED:\nName: %s\nPassword: %s\nGID: %i\n", gr->gr_name,
             gr->gr_passwd, gr->gr_gid );
    __debug( mess );
}

enum nss_status _nss_nfs4_getgrent_r( struct group *result, char *buffer,
                                      size_t buflen, int *errnop ) {
    if ( __nfs4_group == NULL )
        return NSS_STATUS_UNAVAIL;
    __debug( "\nREQUEST FOR GROUP ENTRY" );
    long tell = ftell( __nfs4_group );
    char *line = NULL;
    size_t line_length = 0;
    enum nss_status ret = NSS_STATUS_SUCCESS;
    if ( getline( &line, &line_length, __nfs4_group ) > 0 ) {
        ret = __fillGroup( line, result, buffer, buflen, errnop );
        free( line );
    } else {
        ret = NSS_STATUS_NOTFOUND;
    }
    __debug_group( result );
    if ( ret == NSS_STATUS_TRYAGAIN && *errnop == ERANGE ) {
        fseek( __nfs4_group, tell, SEEK_SET );
    }
    return ret;
}

enum nss_status __findGroup( gid_t gid, const char *name, struct group *result,
                             char *buffer, size_t buflen, int *errnop ) {
    char *line = NULL;
    size_t line_length = 0;
    enum nss_status ret = NSS_STATUS_SUCCESS;
    long tell = ftell( __nfs4_group );
    fseek( __nfs4_group, 0, SEEK_SET );
    unsigned int my_gid = gid + 1;
    char *my_name = NULL;

    if ( name != NULL ) {
        do {
            free( my_name );
            my_name = NULL;
            getline( &line, &line_length, __nfs4_group );
            __copyDeliminer( &my_name, line, ':', 0 );
        } while ( my_name != NULL && strcmp( my_name, name ) &&
                  !feof( __nfs4_group ) );
        if ( my_name == NULL || strcmp( my_name, name ) ) {
            __debug( "DIDN'T FIND SPECIFIED USER\n" );
            goto fail;
        }
    } else {
        do {
            getline( &line, &line_length, __nfs4_group );
            my_gid = __numDeliminer( line, ':', 2 );
        } while ( my_gid != ( unsigned int )-1 && my_gid != gid &&
                  !feof( __nfs4_group ) );
        if ( my_gid == ( unsigned int )-1 || my_gid != gid ) {
            __debug( "DIDN'T FIND SPECIFIED USER\n" );
            goto fail;
        }
    }

    ret = __fillGroup( line, result, buffer, buflen, errnop );

    free( line );
    free( my_name );
    fseek( __nfs4_group, tell, SEEK_SET );

    if ( ret == NSS_STATUS_TRYAGAIN )
        return NSS_STATUS_TRYAGAIN;

    return NSS_STATUS_SUCCESS;

fail:
    free( line );
    free( my_name );
    fseek( __nfs4_group, tell, SEEK_SET );
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_nfs4_getgrgid_r( gid_t gid, struct group *result,
                                      char *buffer, size_t buflen,
                                      int *errnop ) {
    int retcode = NSS_STATUS_SUCCESS;
    if ( __nfs4_passwd == NULL &&
         ( retcode = _nss_nfs4_setgrent() ) != NSS_STATUS_SUCCESS ) {
        _nss_nfs4_endgrent();
        return retcode;
    }
    char mess[1024];
    sprintf( mess, "\nREQUEST FOR GROUP BASED ON GID: %i", gid );
    __debug( mess );
    enum nss_status ret =
        __findGroup( gid, NULL, result, buffer, buflen, errnop );
    if ( ret == NSS_STATUS_SUCCESS )
        __debug_group( result );
    _nss_nfs4_endgrent();
    return ret;
}

enum nss_status _nss_nfs4_getgrnam_r( const char *name, struct group *result,
                                      char *buffer, size_t buflen,
                                      int *errnop ) {
    int retcode = NSS_STATUS_SUCCESS;
    if ( __nfs4_passwd == NULL &&
         ( retcode = _nss_nfs4_setgrent() ) != NSS_STATUS_SUCCESS ) {
        _nss_nfs4_endgrent();
        return retcode;
    }
    char mess[1024];
    sprintf( mess, "\nREQUEST FOR GROUP BASED ON NAME: %s", name );
    __debug( mess );
    enum nss_status ret =
        __findGroup( 0, name, result, buffer, buflen, errnop );
    if ( ret == NSS_STATUS_SUCCESS )
        __debug_group( result );
    _nss_nfs4_endgrent();
    return ret;
}
