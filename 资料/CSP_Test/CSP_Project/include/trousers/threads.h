
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

#ifndef WIN32

//#ifdef HAVE_PTHREAD_H
#include <pthreads/pthread.h>

/* mutex abstractions */
#define MUTEX_INIT(m)		pthread_mutex_init(&m, NULL)
#define MUTEX_LOCK(m)		pthread_mutex_lock(&m)
#define MUTEX_UNLOCK(m)		pthread_mutex_unlock(&m)
#define MUTEX_DECLARE(m)	pthread_mutex_t m
#define MUTEX_DECLARE_INIT(m)	pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER
#define MUTEX_DECLARE_EXTERN(m)	extern pthread_mutex_t m

/* condition variable abstractions */
#define COND_DECLARE(c)		pthread_cond_t c
#define COND_INIT(c)		pthread_cond_init(&c, NULL)
#define COND_VAR		    pthread_cond_t
#define COND_WAIT(c,m)		pthread_cond_wait(c,m)
#define COND_SIGNAL(c)		pthread_cond_signal(c)

/* thread abstractions */
#define THREAD_ID					((size_t)pthread_self())
#define THREAD_TYPE					pthread_t
#define THREAD_JOIN					pthread_join
#define THREAD_DETACH				pthread_detach
#define THREAD_ATTR_DECLARE(a)		pthread_attr_t a
#define THREAD_ATTR_INIT(a)			pthread_attr_init(&a)
#define THREAD_ATTR_SETJOINABLE(a)	pthread_attr_setdetachstate(&a, PTHREAD_CREATE_JOINABLE)
#define THREAD_EXIT					pthread_exit
#define THREAD_CREATE(a,b,c,d)		pthread_create(a,b,c,d)
#define THREAD_SET_SIGNAL_MASK		pthread_sigmask
#define THREAD_NULL					(THREAD_TYPE)0

//#else
//#error No threading library defined! (Cannot find pthread.h)
//#endif

#else	// win32

/* mutex abstractions */
#define MUTEX_INIT(m)			m = CreateMutex( NULL, FALSE, NULL )
#define MUTEX_LOCK(m)			WaitForSingleObject( m, INFINITE )
#define MUTEX_UNLOCK(m)			ReleaseMutex(m)
#define MUTEX_DECLARE(m)		HANDLE m
#define MUTEX_DECLARE_INIT(m)	HANDLE m = NULL
#define MUTEX_DECLARE_EXTERN(m)	extern HANDLE m

/* condition variable abstractions */
#define COND_DECLARE(c)		HANDLE c
#define COND_INIT(c)		c = CreateEvent( NULL, FALSE, FALSE, NULL )
#define COND_VAR		    HANDLE
#define COND_WAIT(c,m)		MUTEX_UNLOCK(m);\
							WaitForSingleObject(c, INFINITE );\
							MUTEX_LOCK( m );

#define COND_SIGNAL(c)		SetEvent( *c )

/* thread abstractions */
#define THREAD_ID					GetCurrentThreadId()
#define THREAD_TYPE					HANDLE
#define THREAD_JOIN					WaitForSingleObject
#define THREAD_DETACH				CloseHandle

#define THREAD_ATTR_DECLARE(a)		DWORD a
#define THREAD_ATTR_INIT(a)			a = 0
#define THREAD_ATTR_SETJOINABLE(a)	a |= 0

#define THREAD_EXIT					_endthreadex
#define THREAD_CREATE(a,b,c,d)		(HANDLE)_beginthreadex( NULL,0,c,d,0,NULL)

//#define THREAD_SET_SIGNAL_MASK	pthread_sigmask
#define THREAD_NULL					(THREAD_TYPE)0

#endif

#endif
