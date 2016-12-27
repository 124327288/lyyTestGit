#ifndef JW_TCM_H
#define JW_TCM_H


#ifdef __midl
#define SIZEIS(x)  [size_is(x)]
#else
#define SIZEIS(x)
#endif


#pragma pack(push)
#pragma pack(1)

//#include "trousers/tss/tpm.h"
#include "jwtcm_ordinal.h"
#include "tcm_const.h"

typedef UINT32 TCM_RESULT;
typedef UINT32 TCM_LOCALITY_MOD;
typedef UINT32 TCPA_LOCALITY_MOD;
typedef UINT32 TCM_COMMAND_CODE;
typedef UINT32 TCM_PCRINDEX;
typedef UINT32 TCM_MODIFIER_INDICATOR;


#define TCM_SCH_256_HASH_LEN                    ((BYTE)0x20)
#define TCM_SCHBASED_NONCE_LEN                  TCM_SCH_256_HASH_LEN

#define MAX_PCR_COUNTER                         (32)
//////////////////////////////////////////////////////////////////////////
// 基本结构
//////////////////////////////////////////////////////////////////////////

typedef struct tdTCM_STRUCT_VER
{
    BYTE                major;
    BYTE                minor;
    BYTE                revMajor;
    BYTE                revMinor;
}TCM_STRUCT_VER;

typedef struct tdTCM_VERSION
{
    BYTE                major;
    BYTE                minor;
    BYTE                revMajor;
    BYTE                revMinor;
}TCM_VERSION;

typedef struct tdTCM_DIGEST
{
    BYTE                digest[TCM_SCH_256_HASH_LEN];
}TCM_DIGEST;

typedef struct tdTCM_VERSION_BYTE
{
    int                 leastSigVer : 4;
    int                 mostSigVer  : 4;
}TCM_VERSION_BYTE;

typedef struct tdTCM_NONCE{
    BYTE                nonce[TCM_SCHBASED_NONCE_LEN];
} TCM_NONCE;


typedef TCM_DIGEST          TCM_CHOSENID_HASH;
typedef TCM_DIGEST          TCM_COMPOSITE_HASH;
typedef TCM_DIGEST          TCM_HMAC;
typedef TCM_DIGEST          TCM_PCRVALUE;
typedef TCM_DIGEST          TCM_AUDITDIGEST;

typedef UINT32              TCM_SEQ;

typedef struct tdTCM_AUTHDATA
{
    BYTE                authdata[TCM_SCH_256_HASH_LEN];
} TCM_AUTHDATA;

typedef TCM_AUTHDATA        TCM_SECRET;
typedef TCM_AUTHDATA        TCM_ENCAUTH;

typedef struct tdTCM_KEY_HANDLE_LIST
{
    UINT16              loaded;
    SIZEIS(loaded)
    TCM_KEY_HANDLE*     handle;
} TCM_KEY_HANDLE_LIST;


typedef BYTE TCM_AUTH_DATA_USAGE;
#define TCM_AUTH_NEVER                          ((BYTE)0x00)
#define TCM_AUTH_ALWAYS                         ((BYTE)0x01)
#define TCM_AUTH_PRIV_USE_ONLY                  ((BYTE)0x11)

typedef UINT32 TCM_ACTUAL_COUNT;
typedef struct tdTCM_COUNTER_VALUE
{
    TCM_STRUCTURE_TAG   tag;
    BYTE                label[4];
    TCM_ACTUAL_COUNT    counter;
}TCM_COUNTER_VALUE;

typedef UINT32     TCM_CAPABILITY_AREA;

typedef struct tdTCM_CURRENT_TICKS
{
    TCM_STRUCTURE_TAG   tag;
    UINT64              currentTicks;
    UINT16              tickRate;
    TCM_NONCE           tickNonce;
}TCM_CURRENT_TICKS;

typedef struct tdTCM_CHANGEAUTH_VALIDATE
{
    TCM_SECRET          newAuthSecret;
    TCM_NONCE           n1;
}TCM_CHANGEAUTH_VALIDATE;

typedef struct tdTCM_KEY_PARMS
{
    TCM_ALGORITHM_ID    algorithmID;
    TCM_ENC_SCHEME      encScheme;
    TCM_SIG_SCHEME      sigScheme;
    UINT32              parmSize;
    SIZEIS(parmSize)
    BYTE*               parms;
}TCM_KEY_PARMS;

typedef struct tdTCM_STORE_PUBKEY
{
    UINT32              keyLength;
    BYTE*               key;
}TCM_STORE_PUBKEY;

typedef struct tdTCM_PUBKEY
{
    TCM_KEY_PARMS       algorithmParms;
    TCM_STORE_PUBKEY    pubKey;
}TCM_PUBKEY;

typedef struct tdTCM_MIGRATIONKEYAUTH
{
    TCM_PUBKEY          migrationKey;
    TCM_MIGRATE_SCHEME  migrationScheme;
    TCM_DIGEST          digest;
}TCM_MIGRATIONKEYAUTH;

typedef struct tdTCM_SIGN_INFO
{
    TCM_STRUCTURE_TAG   tag;
    BYTE                fixed[4];
    TCM_NONCE           replay;
    UINT32              dataLen;
    SIZEIS(dataLen)
    BYTE*               data;
}TCM_SIGN_INFO;

typedef struct tdTCM_SELECT_SIZE
{
    BYTE                major;
    BYTE                minor;
    UINT16              reqSize;
}TCM_SELECT_SIZE;

typedef struct tdTCM_PERMANENT_FLAGS{
    TCM_STRUCTURE_TAG   tag;
    TSM_BOOL            disable;
    TSM_BOOL            ownership;
    TSM_BOOL            deactivated;
    TSM_BOOL            readPubek;
    TSM_BOOL            disableOwnerClear;
    TSM_BOOL            physicalPresenceLifetimeLock;
    TSM_BOOL            physicalPresenceHWEnable;
    TSM_BOOL            physicalPresenceCMDEnable;
    TSM_BOOL            CEKPUsed;
    TSM_BOOL            TCMpost;
    TSM_BOOL            TCMpostLock;
//operator 是c++ 关键字
//    TSM_BOOL            operator;
    TSM_BOOL            opt;
    TSM_BOOL            enableRevokeEK;
    TSM_BOOL            nvLocked;
    TSM_BOOL            TCMEstablished;
}TCM_PERMANENT_FLAGS;

typedef struct tdTCM_STCLEAR_FLAGS{
    TCM_STRUCTURE_TAG   tag;
    TSM_BOOL            deactivated;
    TSM_BOOL            disableForceClear;
    TSM_BOOL            physicalPresence;
    TSM_BOOL            physicalPresenceLock;
    TSM_BOOL            bGlobalLock;
}TCM_STCLEAR_FLAGS;

typedef struct tdTCM_STANY_FLAGS{
    TCM_STRUCTURE_TAG       tag;
    TSM_BOOL                postInitialise;
    TCM_MODIFIER_INDICATOR  localityModifier;
    TSM_BOOL                transportExclusive;
    TSM_BOOL                TOSPresent;
}TCM_STANY_FLAGS;

#define TCM_MIN_COUNTERS                        (4)
#define TCM_NUM_PCR                             (16)
#define TCM_MAX_NV_WRITE_NOOWNER                (64)

typedef struct tdTCM_KEY{
    TCM_STRUCTURE_TAG       tag;
    UINT16                  fill;
    TCM_KEY_USAGE           keyUsage;
    TCM_KEY_FLAGS           keyFlags;
    TCM_AUTH_DATA_USAGE     authDataUsage;
    TCM_KEY_PARMS           algorithmParms;
    UINT32                  PCRInfoSize;
    BYTE*                   PCRInfo;
    TCM_STORE_PUBKEY        pubKey;
    UINT32                  encDataSize;
    BYTE*                   encData;
}TCM_KEY;

typedef BYTE                TCM_LOCALITY_SELECTION;

typedef struct tdTCM_PCR_ATTRIBUTES{
    TSM_BOOL                pcrReset;
    TCM_LOCALITY_SELECTION  pcrExtendLocal;
    TCM_LOCALITY_SELECTION  pcrResetLocal;
}TCM_PCR_ATTRIBUTES;

typedef struct tdTCM_SM2_ASYMKEY_PARAMETERS {
	UINT32 keyLength; 
}TCM_SM2_ASYMKEY_PARAMETERS; 

typedef struct tdTCM_SYMMETRIC_KEY_PARMS {
	UINT32 keyLength;
	UINT32 blockSize;
	UINT32 ivSize;
	BYTE IV[256];
} TCM_SYMMETRIC_KEY_PARMS;

typedef struct tdTCM_SYMMETRIC_KEY {
	TCM_ALGORITHM_ID algId;
	TCM_ENC_SCHEME encScheme;
	UINT16 size;
        BYTE data[256];
} TCM_SYMMETRIC_KEY;

typedef struct tdTCM_STORE_SYMKEY {
	TCM_PAYLOAD_TYPE payload;
    TCM_SECRET usageAuth;
    TCM_SECRET migrationAuth;
    UINT16 size;
    BYTE data[256];
	//BYTE* data; //16byte // zhangdp
} TCM_STORE_SYMKEY;

//////////////////////////////////////////////////////////////////////////
// PCR结构
//////////////////////////////////////////////////////////////////////////
typedef struct tdTCM_PCR_SELECTION 
{ 
    UINT16 sizeOfSelect;
    //每个bit位表示对应的PCR(从右到左,从0开始)被选择或未被选择
    //目前定义最多32个PCR
    BYTE pcrSelect[MAX_PCR_COUNTER / 8];
}TCM_PCR_SELECTION;

typedef struct tdTCM_PCR_COMPOSITE
{
    TCM_PCR_SELECTION       select;
    UINT32                  valueSize;
    TCM_PCRVALUE*           pcrValue;
}TCM_PCR_COMPOSITE;

typedef struct tdTCM_PCR_INFO{
    TCM_STRUCTURE_TAG       tag;
    TCM_LOCALITY_SELECTION  localityAtCreation;
    TCM_LOCALITY_SELECTION  localityAtRelease;
    TCM_PCR_SELECTION       creationPCRSelection;
    TCM_PCR_SELECTION       releasePCRSelection;
    TCM_COMPOSITE_HASH      digestAtCreation;
    TCM_COMPOSITE_HASH      digestAtRelease;
}TCM_PCR_INFO;

//////////////////////////////////////////////////////////////////////////
// 身份结构
//////////////////////////////////////////////////////////////////////////

typedef struct tdTCM_IDENTITY_CONTENTS
{
    TCM_STRUCT_VER          ver;
    UINT32                  ordinal;
    TCM_CHOSENID_HASH       labelPrivCADigest;
    TCM_PUBKEY              identityPubKey;
}TCM_IDENTITY_CONTENTS;

typedef struct tdTCM_IDENTITY_PROOF
{
    TCM_STRUCT_VER          Ver;                    // 等于1
    UINT32                  LabelSize;              // 平台身份标识长度
    UINT32                  IdentityBindingSize;    // 身份绑定信息长度
    UINT32                  EndorsementSize;        // EK证书长度
    TCM_PUBKEY              IdentityKey;            // 身份公钥
    BYTE*                   LabelArea;              // 平台身份标识
    BYTE*                   IdentityBinding;        // TCM_IDENTITY_CONTENTS的摘要
    BYTE*                   EndorsementCredential;  // EK证书
}TCM_IDENTITY_PROOF;

typedef struct tdTCM_IDENTITY_REQ
{
    UINT32                  AsymSize;       // AsymBlob的长度
    UINT32                  SymSize;        // SymBlob的长度
    TCM_KEY_PARMS           asymAlgorithm;  // 非对称算法参数
    TCM_KEY_PARMS           symAlgorithm;   // 对称算法参数
    BYTE*                   AsymBlob;       // 非对称加密数据区，可信方公钥对对称密钥进行加密的结果
    BYTE*                   SymBlob;        // 对称加密数据区 (TCM_IDENTITY_PROOF 结构加密数据)
}TCM_IDENTITY_REQ;

typedef struct tdTCM_ASYM_CA_CONTENTS
{
    TCM_SYMMETRIC_KEY       sessionKey;
    TCM_DIGEST              idDigest;
}TCM_ASYM_CA_CONTENTS;

typedef struct tdTCM_ASYM_CA_PEK_CONTENTS
{
    TCM_SYMMETRIC_KEY sessionKey;
}TCM_ASYM_CA_PEK_CONTENTS;

typedef struct tdTCM_PEK_PROOF
{
    TCM_STRUCT_VER          ver;                    // 等于1
    UINT32                  LabelSize;              // 平台身份标识长度
    UINT32                  EndorsementSize;        // EK证书长度
    TCM_KEY_PARMS           IdentityKey;            // PEK公钥参数
    BYTE*                   LabelArea;              // 平台身份标识
    BYTE*                   EndorsementCredential;  // EK证书
}TCM_PEK_PROOF;

typedef struct tdTCM_PEK_REQ
{
    UINT32                   asymSize;      // AsymBlob的长度
    UINT32                   symSize;       // SymBlob的长度
    TCM_KEY_PARMS            asymAlgorithm; // 非对称算法参数
    TCM_KEY_PARMS            symAlgorithm;  // 对称算法参数
    BYTE*                    asymBlob;      // 非对称加密数据区，可信方公钥对对称密钥进行加密的结果
    BYTE*                    symBlob;       // 对称加密数据区 (TCM_PEK_PROOF 结构加密数据)
}TCM_PEK_REQ;

typedef struct tdTCM_SYM_CA_ATTESTATION
{
    UINT32                  credSize;           // 证书参数长度
    TCM_KEY_PARMS           algorithm;          // 算法参数
    BYTE*                   credential;         // 身份证书
}TCM_SYM_CA_ATTESTATION;

//////////////////////////////////////////////////////////////////////////
//add by wangqi 20081204
//tdTCM_PERMANENT_DATA 结构体对应tcm 中的tdTCM_PERMANENT_DATA，但简化过
//全局变量gctx 用到此结构
//////////////////////////////////////////////////////////////////////////
typedef struct tdTCM_PERMANENT_DATA {
	TCM_COUNTER_VALUE auditMonotonicCounter;
	BYTE ordinalAuditStatus[32];
} TCM_PERMANENT_DATA;

typedef struct tdTCM_STANY_DATA{
	TCM_STRUCTURE_TAG 	tag;
	TCM_DIGEST		auditDigest;
	TCM_CURRENT_TICKS	currentTicks;
	UINT32			contextCount;
} TCM_STANY_DATA;

typedef struct tdContent
{
	TCM_PERMANENT_DATA	  PmtDataIns;
	TCM_STANY_DATA		  StyData;
} TSM_CONTENT;

typedef struct tdTCM_AUDIT_EVENT_IN { 
	TCM_STRUCTURE_TAG tag; 
	TCM_DIGEST inputParms; 
	TCM_COUNTER_VALUE auditCount; 
} TCM_AUDIT_EVENT_IN; 

typedef struct tdTCM_AUDIT_EVENT_OUT { 
	TCM_STRUCTURE_TAG tag; 
	TCM_DIGEST outputParms; 
	TCM_COUNTER_VALUE auditCount; 
} TCM_AUDIT_EVENT_OUT; 
//end add by wangqi 


#pragma pack(pop)

#endif
