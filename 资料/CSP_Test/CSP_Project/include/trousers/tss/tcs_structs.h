/*++

TSS Core Service structures

*/

#ifndef __TCS_STRUCT_H__
#define __TCS_STRUCT_H__

#include "tpm.h"
#include "tss_structs.h"
#include "tcs_typedef.h"

#pragma pack(push)
#pragma pack(1)

typedef struct tdTCS_AUTH
{
    TCS_AUTHHANDLE  AuthHandle;
    TPM_NONCE       NonceOdd;   // system  
    TPM_NONCE       NonceEven;   // TPM   
    TSS_BOOL        fContinueAuthSession;
    TPM_AUTHDATA    HMAC;
#ifndef USES_TCG_STD
	// 与TSS不同, 以下成员用于TCM的APCreate
	UINT16 entityType;
	UINT32 entityValue;
	UINT32 AntiReplaySeq;
	BYTE   ShareSecret[32];
	UINT32 ordinal;
	TSS_RESULT result;
#endif
} TCS_AUTH;

// This is kept for legacy compatibility
typedef TCS_AUTH    TPM_AUTH;

#ifdef USES_TCG_STD
typedef struct tdTCS_LOADKEY_INFO
{
    TSS_UUID   keyUUID;
    TSS_UUID   parentKeyUUID;
    TPM_DIGEST  paramDigest; // SHA1 digest of the TPM_LoadKey
                             // Command input parameters
                             // As defined in TPM Main Specification
    TPM_AUTH   authData;     // Data regarding a valid auth
                             // Session including the
                             // HMAC digest
} TCS_LOADKEY_INFO;

#endif

#pragma pack(pop)

#endif // __TCS_STRUCT_H__

