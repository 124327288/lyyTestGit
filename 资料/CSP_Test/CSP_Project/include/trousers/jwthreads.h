
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2006
 *
 */

#ifndef __THREADS_H__
#define __THREADS_H__

#include <pthread.h>

#ifndef WIN32 // linux

#ifdef HAVE_PTHREAD_H


/* mutex abstractions */
#define MUTEX_INIT(m)                           pthread_mutex_init(&m, NULL)
#define MUTEX_LOCK(m)                           pthread_mutex_lock(&m)
#define MUTEX_UNLOCK(m)                         pthread_mutex_unlock(&m)
#define MUTEX_DECLARE(m)                        pthread_mutex_t m
#define MUTEX_DECLARE_INIT(m)                   pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER
#define MUTEX_DECLARE_EXTERN(m)                 extern pthread_mutex_t m

/* condition variable abstractions */
#define COND_DECLARE(c)                         pthread_cond_t c
#define COND_INIT(c)                            pthread_cond_init(&c, NULL)
#define COND_VAR                                pthread_cond_t
#define COND_WAIT(c,m)                          pthread_cond_wait(c,m)
#define COND_SIGNAL(c)                          pthread_cond_signal(c)

/* thread abstractions */
#define THREAD_ID                               ((size_t)pthread_self())
#define THREAD_TYPE                             pthread_t
#define THREAD_JOIN                             pthread_join
#define THREAD_DETACH                           pthread_detach
#define THREAD_ATTR_DECLARE(a)                  pthread_attr_t a
#define THREAD_ATTR_INIT(a)                     pthread_attr_init(&a)
#define THREAD_ATTR_SETJOINABLE(a)              pthread_attr_setdetachstate(&a, PTHREAD_CREATE_JOINABLE)
#define THREAD_EXIT                             pthread_exit
#define THREAD_CREATE(a,b,c,d)                  pthread_create(a,b,c,d)
#define THREAD_SET_SIGNAL_MASK                  pthread_sigmask
#define THREAD_NULL                             (THREAD_TYPE)0

#else

#error No threading library defined! (Cannot find pthread.h)

#endif

#else // WIN32

//#include <Windows.h>
//#include <process.h>

// mutex abstractions
#define MUTEX_INIT(m)                           InitializeCriticalSection(&m);
//#define MUTEX_DELETE(m)                         DeleteCriticalSection(&m);
#define MUTEX_LOCK(m)                           EnterCriticalSection(&m);
#define MUTEX_UNLOCK(m)                         LeaveCriticalSection(&m);
#define MUTEX_DECLARE(m)                        CRITICAL_SECTION m
#define MUTEX_DECLARE_INIT(m)                   CRITICAL_SECTION m = {0};
#define MUTEX_DECLARE_EXTERN(m)                 extern CRITICAL_SECTION m;

/* condition variable abstractions */

#define COND_DECLARE(c)                         pthread_cond_t c
#define COND_INIT(c)                            memset(&c, 0, sizeof(c));
#define COND_VAR                                pthread_cond_t
#define COND_WAIT(c,m)                          WaitForSingleObject(c, INFINITE)
#define COND_SIGNAL(c)                          SetEvent(c);

/* thread abstractions */


//#define THREAD_ID                               ((size_t)pthread_self())
typedef unsigned long                           THREAD_TYPE;
#define THREAD_JOIN                             pthread_join
#define THREAD_DETACH                           pthread_detach
#define THREAD_ATTR_DECLARE(a)                  pthread_attr_t a
#define THREAD_ATTR_INIT(a)                     pthread_attr_init(&a)
#define THREAD_ATTR_SETJOINABLE(a)              pthread_attr_setdetachstate(&a, PTHREAD_CREATE_JOINABLE)
#define THREAD_EXIT                             pthread_exit
#define THREAD_CREATE(a,b,c,d)                  pthread_create(a,b,c,d)
#define THREAD_SET_SIGNAL_MASK                  pthread_sigmask
#define THREAD_NULL                             (THREAD_TYPE)0

#endif // WIN#2

#endif
