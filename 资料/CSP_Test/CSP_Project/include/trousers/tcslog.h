
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */


#ifndef _TCSLOG_H_
#define _TCSLOG_H_

#include <stdio.h>

#ifndef WIN32
#include <syslog.h>
#else
#define LOG_ERR         (3)
#define LOG_WARNING     (4)
#define LOG_INFO        (6)
#endif

extern int foreground;

/* log to syslog -- change your syslog destination here */
#define TSS_SYSLOG_LVL	LOG_LOCAL5

#ifdef WIN32

int LogMessage(FILE* fp, const char * fmt, ...);
int LogError(const char * fmt, ...);
int LogWarn(const char * fmt, ...);
int LogInfo(const char * fmt, ...);
int LogDebug(const char * fmt, ...);
int LogDebugFn(const char * fmt, ...);


#else // ifdef WIN32

#define LogMessage(dest, priority, layer, fmt, ...) \
        do { \
		if (foreground) { \
			fprintf(dest, "%s " fmt "\n", layer, ## __VA_ARGS__); \
		} else { \
			openlog(layer, LOG_NDELAY|LOG_PID, TSS_SYSLOG_LVL); \
			syslog(priority, "TrouSerS " fmt "\n", ## __VA_ARGS__); \
		} \
        } while (0)

/* Debug logging */
#ifdef TSS_DEBUG
#define LogDebug(fmt, ...)	LogMessage(stdout, LOG_DEBUG, APPID, "%s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define LogDebugFn(fmt, ...)	LogMessage(stdout, LOG_DEBUG, APPID, "%s:%d %s: " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define LogBlob(sz,blb)		LogBlobData(APPID, sz, blb)
#define LogDebugKey(k) \
	do { \
		if (k.hdr.key12.tag == TPM_TAG_KEY12) \
			LogDebugFn("Tag: %hu", k.hdr.key12.tag); \
		else \
			LogDebugFn("Version: %hhu.%hhu.%hhu.%hhu", \
			   k.hdr.key11.ver.major, k.hdr.key11.ver.minor, \
			   k.hdr.key11.ver.revMajor, k.hdr.key11.ver.revMinor); \
		LogDebugFn("keyUsage: 0x%hx", k.keyUsage); \
		LogDebugFn("keyFlags: 0x%x", k.keyFlags); \
		LogDebugFn("authDatausage: %hhu", k.authDataUsage); \
		LogDebugFn("pcrInfosize: %u", k.PCRInfoSize); \
		LogDebugFn("encDataSize: %u", k.encSize); \
	} while (0)
#define LogDebugUnrollKey(b) \
	do { \
			TSS_KEY tmpkey; \
			UINT64 offset = 0; \
			if (!UnloadBlob_TSS_KEY(&offset, b, &tmpkey)) { \
				LogDebugKey(tmpkey); \
				destroy_key_refs(&tmpkey); \
			} else { \
				LogDebugFn("*** ERROR UNLOADING DEBUGGING KEY BLOB ***"); \
			} \
	} while (0)

#define LogError(fmt, ...)	LogMessage(stderr, LOG_ERR, APPID, "ERROR: %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define LogWarn(fmt, ...)	LogMessage(stdout, LOG_WARNING, APPID, "%s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define LogInfo(fmt, ...)	LogMessage(stdout, LOG_INFO, APPID, "%s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#else // #ifdef TSS_DEBUG

#define LogDebug(fmt, ...)
#define LogDebugFn(fmt, ...)
#define LogBlob(sz,blb)
#define LogDebugKey(s)
#define LogDebugUnrollKey(b)

/* Error logging */
#define LogError(fmt, ...)	LogMessage(stderr, LOG_ERR, APPID, "ERROR: " fmt, ##__VA_ARGS__)

/* Warn logging */
#define LogWarn(fmt, ...)	LogMessage(stdout, LOG_WARNING, APPID, fmt, ##__VA_ARGS__)

/* Info Logging */
#define LogInfo(fmt, ...)	LogMessage(stdout, LOG_INFO, APPID, fmt, ##__VA_ARGS__)
#endif // #ifdef TSS_DEBUG

#endif // ifdef WIN32

void LogBlobData(char *appid, unsigned long sizeOfBlob, unsigned char *blob);

#endif
