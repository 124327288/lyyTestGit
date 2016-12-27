#ifndef JW_PLATFORM_H
#define JW_PLATFORM_H

#undef IN
#undef OUT
#define IN
#define OUT

#undef __attribute__
#define __attribute__(x)

#undef inline
#define inline

#define TSS_VER_MAJOR   (1)
#define TSS_VER_MINOR   (2)
#define TSS_SPEC_MAJOR  (1)
#define TSS_SPEC_MINOR  (2)
//#define TSS_SPEC_MAJOR

#pragma pack(push)
#pragma pack(1)

#include "../include/trousers/tss/platform.h"

#define TSM_TCSD_PORT           ((UINT16)10000)
#define MAX_TSM_BUFFER_SIZE     ((UINT32)4096)
#define MAX_TSM_DATA_LENGTH     (MAX_TSM_BUFFER_SIZE - 256)

#define INT32_BYTE0(n)		((BYTE)(((unsigned long)(n) >> 24) & 0x000000FF))
#define INT32_BYTE1(n)		((BYTE)(((unsigned long)(n) >> 16) & 0x000000FF))
#define INT32_BYTE2(n)		((BYTE)(((unsigned long)(n) >> 8) & 0x000000FF))
#define INT32_BYTE3(n)		((BYTE)((unsigned long)(n) & 0x000000FF))

#define INT16_TO_BUF(buf, n)    \
{                               \
    (buf)[0] = INT32_BYTE2(n);  \
	(buf)[1] = INT32_BYTE3(n);  \
}

#define INT32_TO_BUF(buf, n)    \
{                               \
    (buf)[0] = INT32_BYTE0(n);  \
	(buf)[1] = INT32_BYTE1(n);  \
    (buf)[2] = INT32_BYTE2(n);  \
	(buf)[3] = INT32_BYTE3(n);  \
}

#define BUF_TO_INT32(buf, n)                    \
{                                               \
    n = ((long)((buf)[0]) << 24) & 0xFF000000;  \
	n |= ((long)((buf)[1]) << 16) & 0x00FF0000; \
	n |= ((long)((buf)[2]) << 8) & 0x0000FF00;  \
	n |= ((long)((buf)[3]))  & 0x000000FF;      \
}

#ifdef WIN32
//////////////////////////////////////////////////////////////////////////
// WIN32 平台
//////////////////////////////////////////////////////////////////////////

#include <winsock2.h>

// windwos 有 __stdcsll
#define STDCALL __stdcall
/*
#define __STD_TYPE		typedef
#define __SLONGWORD_TYPE	long int

#define __TIME_T_TYPE		__SLONGWORD_TYPE
#define __SUSECONDS_T_TYPE	__SLONGWORD_TYPE

__STD_TYPE __TIME_T_TYPE __time_t;
__STD_TYPE __SUSECONDS_T_TYPE __suseconds_t;

typedef __time_t time_t;

struct timeval
{
    __time_t tv_sec;		// Seconds.
    __suseconds_t tv_usec;	// Microseconds.
};
*/

typedef unsigned int        __mode_t;
typedef __mode_t            mode_t;
typedef unsigned int        __gid_t;
typedef __gid_t             gid_t;

#define __S_IREAD           S_IREAD
#define S_IRUSR             __S_IREAD           // Read by owner.
#define __S_IWRITE          S_IWRITE
#define	S_IWUSR             __S_IWRITE          // Write by owner.
#define __S_IEXEC           S_IEXEC
#define	S_IXUSR             __S_IEXEC           // Execute by owner.

#define	S_IRWXU	            (__S_IREAD|__S_IWRITE|__S_IEXEC)


#define sigfillset(what)    (*(what) = ~(0))

#define rindex              strrchr

/* The group structure.	 */
struct group
  {
    char *gr_name;		/* Group name.	*/
    char *gr_passwd;		/* Password.	*/
    __gid_t gr_gid;		/* Group ID.	*/
    char **gr_mem;		/* Member list.	*/
  };

#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)

#define nanosleep(t, r)      Sleep((t)->tv_sec + (t)->tv_nsec / 1000)

#define strncasecmp		    strncmp
#define strcasecmp          strcmp

#define snprintf                                _snprintf

typedef UINT32 __gid_t;
typedef UINT32 __uid_t;
typedef __uid_t uid_t;

/* The passwd structure.  */
struct passwd
{
  char *pw_name;		/* Username.  */
  char *pw_passwd;		/* Password.  */
  __uid_t pw_uid;		/* User ID.  */
  __gid_t pw_gid;		/* Group ID.  */
  char *pw_gecos;		/* Real name.  */
  char *pw_dir;			/* Home directory.  */
  char *pw_shell;		/* Shell program.  */
};

#define fsync(fd)

#define geteuid()           (0)

#define getpwent_r(a, b, c, d)                  (1)
#else
//////////////////////////////////////////////////////////////////////////
// LINUX 平台
//////////////////////////////////////////////////////////////////////////

// linux 没有 __stdcsll
#define STDCALL

#endif //WIN32


/*

//#include <windows.h>

#ifdef WIN32

typedef unsigned short  UINT16;
typedef unsigned long   UINT32;  
typedef signed char     TSM_BOOL;
typedef unsigned short  TSM_UNICODE;
typedef unsigned char   BYTE;
typedef void*           PVOID;


#else

#endif

#undef TRUE
#undef FALSE

#define TRUE        (0x01)
#define FALSE       (0x00)

*/

#pragma pack(pop)

#endif