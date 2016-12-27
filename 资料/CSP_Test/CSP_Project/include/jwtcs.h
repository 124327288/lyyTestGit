//////////////////////////////////////////////////////////////////////////
//
// 文件名: jwtcs.h
// 内容: TCS接口声明
//
//////////////////////////////////////////////////////////////////////////

#if !defined(JW_TCM_CORE_SERVICE_H)
#define JW_TCM_CORE_SERVICE_H

#define _WINSOCKAPI_
#include <winsock2.h>

#include "jwtsm.h"
//#include "jwtcm.h"
//#include "tss_tcs.h"

//#include "../include/trousers/threads.h"

#if !defined( TCSICALL )
#if !defined(WIN32) || defined (TCS_STATIC)
// Linux, or a Win32 static library
#define TCSICALL extern TSM_RESULT STDCALL
#elif defined (TCSDLL_EXPORTS)
// Win32 DLL build
#define TCSICALL extern __declspec(dllexport) TSM_RESULT STDCALL
#else
// Win32 DLL import
#define TCSICALL extern __declspec(dllimport) TSM_RESULT STDCALL
#endif
#endif // TSPICALL

#ifdef __cplusplus
extern "C" {
#endif

//////////////////////////////////////////////////////////////////////////
//
// TCS Context Manager
//
//////////////////////////////////////////////////////////////////////////


// Tcsi_OpenContext is used to obtain a handle to a new context.
// The context handle is used in various functions to assign resources to it. An
// application (i.e., TSP or application directly utilizing the TCS) may require more than
// one context open.
TCSICALL
Tcs_OpenContext(
    TCS_CONTEXT_HANDLE*     hContext            // in
    );

// Tcsi_CloseContext releases all resources assigned to the given context and the
// context itself.
TCSICALL
Tcs_CloseContext(
    TCS_CONTEXT_HANDLE      hContext            // in
    );

// Tcsi_FreeMemory frees memory allocated by TSS CS on a context base. If pMemory
// equals NULL all allocated memory blocks will be freed.
TCSICALL
Tcs_FreeMemory(
    TCS_CONTEXT_HANDLE      hContext,           // in
    BYTE*                   pMemory             // in
    );

// Tcsi_GetCapability provides the capabilities of the TCS.
TCSICALL
Tcs_GetCapability(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCM_CAPABILITY_AREA     capArea,            // in
    UINT32                  subCapSize,         // in
    BYTE*                   subCap,             // in
    UINT32*                 respSize,           // out
    BYTE**                  resp                // out
    );

//////////////////////////////////////////////////////////////////////////
//
// TCS Key and Credential Manager
//
//////////////////////////////////////////////////////////////////////////

// Tcsi_RegisterKey allows registering a key  in the TCS Persistent Storage (PS). Only
// system specific keys (keys definitely bound to a certain system) should be registered
// in TCS PS.
// A key can be registered in TCS PS by providing:
// * A UUID for that key,
// * A UUID for its wrapping parent key and
// * The key blob itself.
// If the same UUID is used to register a key on different systems this key can be
// addressed on different systems by the same UUID. This may be done for a basic
// roaming key, which will wrap all user storage keys in the appropriate key hierarchy.

// 备注:
// 时间: 2008/3/25
// 添加: 吴庆
// TSS函数名: Tcsi_RegisterKey
// TSM函数名: Tcs_RegisterKey
// 差别: 函数名不同
// 处理方式: TCS同时提供两个接口分别符合TSS和TSM规范
// 参数补充说明: 开源trousers中WrappingKeyUUID和KeyUUID参数为指针，标准文档为非指针形式
TCSICALL
Tcs_RegisterKey(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_UUID                WrappingKeyUUID,    // in
    TSM_UUID                KeyUUID,            // in
    UINT32                  cKeySize,           // in
    BYTE*                   rgbKey,             // in
    UINT32                  cVendorDataSize,    // in
    BYTE*                   rgbVendorData       // in
    );

TCSICALL
Tcs_UnregisterKey(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_UUID                KeyUUID             // in
    );

TCSICALL
Tcs_EnumRegisteredKeys(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_UUID*               pKeyUUID,           // in
    UINT32*                 pcKeyHierarchySize, // out
    TSM_KM_KEYINFO**        ppKeyHierarchy      // out
    );

TCSICALL
Tcs_GetRegisteredKey(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_UUID                KeyUUID,            // in
    TSM_KM_KEYINFO**        ppKeyInfo           // out
    );

TCSICALL
Tcs_GetRegisteredKeyBlob(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_UUID                KeyUUID,            // in
    UINT32*                 pcKeySize,          // out
    BYTE**                  prgbKey             // out
    );

TCSICALL
Tcs_GetRegisteredKeyByPublicInfo(
    TCS_CONTEXT_HANDLE      hContext,              // in
    TSM_ALGORITHM_ID        algID,                 // in
    UINT32                  ulPublicInfoLength,    // in
    BYTE*                   rgbPublicInfo,         // in
    UINT32*                 keySize,               // out
    BYTE**                  keyBlob                // out
    );

TCSICALL
Tcs_CollatePekRequest(
    TCS_CONTEXT_HANDLE      hContext,                       // in
    TCM_CHOSENID_HASH       IDLabel_PrivCAHash,             // in
    UINT32*                 pcEndorsementCredentialSize,    // out
    BYTE**                  prgbEndorsementCredential       // out
    ); 

////事件管理
TCSICALL
Tcs_LogPcrEvent(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_PCR_EVENT           Event,              // in
    UINT32*                 pNumber             // out
    );

TCSICALL
Tcs_GetPcrEvent(
    TCS_CONTEXT_HANDLE      hContext,           // in
    UINT32                  PcrIndex,           // in
    UINT32*                 pNumber,            // in, out
    TSM_PCR_EVENT**         ppEvent             // out
    );

TCSICALL
Tcs_GetPcrEventsByPcr(
    TCS_CONTEXT_HANDLE      hContext,           // in
    UINT32                  PcrIndex,           // in
    UINT32                  FirstEvent,         // in
    UINT32*                 pEventCount,        // in,out
    TSM_PCR_EVENT**         ppEvents            // out
    );

TCSICALL
Tcs_GetPcrEventLog(
    TCS_CONTEXT_HANDLE      hContext,           // in
    UINT32*                 pEventCount,        // out
    TSM_PCR_EVENT**         ppEvents            // out
    );


/*可信密码模块管理*/
////TCM测试
TCSICALL
Tcsip_SelfTestFull(
    TCS_CONTEXT_HANDLE      hContext            // in
    );

TCSICALL
Tcsip_ContinueSelfTest(
     TCS_CONTEXT_HANDLE     hContext            // in
    );

TCSICALL
Tcsip_GetTestResult(
     TCS_CONTEXT_HANDLE     hContext,           // in
     UINT32*                outDataSize,        // out
     BYTE**                 outData             // out
    );


////工作模式设置
TCSICALL
Tcsip_SetOwnerInstall(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_BOOL                state               // in
    );

TCSICALL
Tcsip_OwnerSetDisable(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_BOOL                disableState,       // in 
    TCM_AUTH*               ownerAuth           // in, out
    );

TCSICALL
Tcsip_PhysicalEnable(
    TCS_CONTEXT_HANDLE      hContext            // in
    );

TCSICALL
Tcsip_PhysicalDisable(
    TCS_CONTEXT_HANDLE      hContext            // in
    );

TCSICALL
Tcsip_SetTempDeactived(
    TCS_CONTEXT_HANDLE      hContext,           // in
	TCM_AUTH*               operatorAuth        // in, out
    ); 

TCSICALL
Tcsip_PhysicalSetDeactivated(
    TCS_CONTEXT_HANDLE      hContext,           // in 
    TSM_BOOL                state               // in
    );

TCSICALL
Tcsip_SetOperatorAuth(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_SECRET              operatorAuth        // in
    );

// This method sets the physical presence flags.
TCSICALL
Tcsip_PhysicalPresence(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_PHYSICAL_PRESENCE   fPhysicalPresence   // in
    );

////所有者管理
TCSICALL
Tcsip_TakeOwnership(
    TCS_CONTEXT_HANDLE      hContext,           // in
    UINT16                  protocolID,         // in
    UINT32                  encOwnerAuthSize,   // in
    BYTE*                   encOwnerAuth,       // in
    UINT32                  encSmkAuthSize,     // in
    BYTE*                   encSmkAuth,         // in
    UINT32                  smkKeyInfoSize,     // in
    BYTE*                   smkKeyInfo,         // in
    TCM_AUTH*               ownerAuth,          // in, out
    UINT32*                 smkKeyDataSize,     // out
    BYTE**                  smkKeyData          // out
    );

TCSICALL
Tcsip_OwnerClear(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCM_AUTH*               ownerAuth           // in, out
    );

TCSICALL
Tcsip_DisableOwnerClear(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCM_AUTH*               ownerAuth           // in, out
    );

TCSICALL
Tcsip_ForceClear( 
    TCS_CONTEXT_HANDLE      hContext            // in
    );

TCSICALL
Tcsip_DisableForceClear( 
    TCS_CONTEXT_HANDLE      hContext           // in
    );

////属性管理
TCSICALL
Tcsip_GetCapability(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_CAPABILITY_AREA     capArea,            // in
    UINT32                  subCapSize,         // in
    BYTE*                   subCap,             // in
    UINT32*                 respSize,           // out
    BYTE**                  resp                // out
    );

TCSICALL
Tcsip_SetCapability(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCM_CAPABILITY_AREA     capArea,            // in
    UINT32                  subCapSize,         // in
    BYTE*                   subCap,             // in
    UINT32                  valueSize,          // in
    BYTE*                   value,              // in
    TCM_AUTH*               ownerAuth           // in out
    );


////升级维护
TCSICALL
Tcsip_FieldUpgrade(
    TCS_CONTEXT_HANDLE      hContext,           // in
    UINT32                  dataInSize,         // in
    BYTE*                   dataIn,             // in
    TCM_AUTH*               ownerAuth,          // in, out
    UINT32*                 dataOutSize,        // out
    BYTE**                  dataOut             // out
    );

TCSICALL
Tcsip_ResetLockValue(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCM_AUTH*               ownerAuth           // in, out
    );


////授权值管理
TCSICALL
Tcsip_ChangeAuth(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCS_KEY_HANDLE          parentHandle,       // in
    TCM_PROTOCOL_ID         protocolID,         // in
    TCM_ENCAUTH             newAuth,            // in
    TCM_ENTITY_TYPE         entityType,         // in
    UINT32                  encDataSize,        // in
    BYTE*                   encData,            // in
    TCM_AUTH*               ownerAuth,          // in, out
    TCM_AUTH*               entityAuth,         // in, out
    UINT32*                 outDataSize,        // out
    BYTE**                  outData             // out
    );

TCSICALL
Tcsip_ChangeAuthOwner(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCM_PROTOCOL_ID         protocolID,         // in
    TCM_ENCAUTH             newAuth,            // in
    TCM_ENTITY_TYPE         entityType,         // in
    TCM_AUTH*               ownerAuth           // in, out
    );

////非易失性存储管理
TCSICALL
Tcsip_NV_DefineOrReleaseSpace(
    TCS_CONTEXT_HANDLE      hContext,           // in
    UINT32                  cPubInfoSize,       // in
    BYTE*                   pPubInfo,           // in
    TCM_ENCAUTH             encAuth,            // in
    TCM_AUTH*               pAuth               // in, out
    );

TCSICALL
Tcsip_NV_WriteValue(
     TCS_CONTEXT_HANDLE     hContext,           // in
     TSM_NV_INDEX           hNVStore,           // in
     UINT32                 offset,             // in
     UINT32                 ulDataLength,       // in
     BYTE*                  rgbDataToWrite,     // in
     TCM_AUTH*              privAuth            // in, out
    );

TCSICALL
Tcsip_NV_WriteValueAuth(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_NV_INDEX            hNVStore,           // in
    UINT32                  offset,             // in
    UINT32                  ulDataLength,       // in
    BYTE*                   rgbDataToWrite,     // in
    TCM_AUTH*               NVAuth              // in, out
    );

TCSICALL
Tcsip_NV_ReadValue(
     TCS_CONTEXT_HANDLE     hContext,           // in
     TSM_NV_INDEX           hNVStore,           // in
     UINT32                 offset,             // in
     UINT32*                pulDataLength,      // in, out
     TCM_AUTH*              privAuth,           // in, out
     BYTE**                 rgbDataRead         // out
    );

TCSICALL
Tcsip_NV_ReadValueAuth(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_NV_INDEX            hNVStore,           // in
    UINT32                  offset,             // in
    UINT32*                 pulDataLength,      // in, out
    TCM_AUTH*               NVAuth,             // in, out
    BYTE**                  rgbDataRead         // out
    );

////审计
TCSICALL
Tcsip_GetAuditDigest(
    TCS_CONTEXT_HANDLE    hContext,    // in
    UINT32    startOrdinal,    // in
    TCM_DIGEST*    auditDigest,    // out
    UINT32*    counterValueSize,    // out
    BYTE**    counterValue,    // out
    TSM_BOOL*    more,    // out
    UINT32*    ordSize,    // out
    UINT32**    ordList    // out
    );

TCSICALL
Tcsip_GetAuditDigestSigned(
     TCS_CONTEXT_HANDLE    hContext,    // in
     TCS_KEY_HANDLE    keyHandle,    // in
     TSM_BOOL    closeAudit,    // in
     TCM_NONCE    antiReplay,    // in
     TCM_AUTH*    privAuth,    // in, out
     UINT32*    counterValueSize,    // out
     BYTE**    counterValue,    // out
     TCM_DIGEST*    auditDigest,    // out
     TCM_DIGEST*    ordinalDigest,    // out
     UINT32*    sigSize,    // out
     BYTE**    sig    // out
    );

TCSICALL
Tcsip_SetOrdinalAuditStatus(
     TCS_CONTEXT_HANDLE    hContext,    // in
     TCM_AUTH*    ownerAuth,    // in, out
     UINT32    ordinalToAudit, // in
     TSM_BOOL    auditState    // in
    );

////时钟
TCSICALL
Tcsip_ReadCurrentTicks(TCS_CONTEXT_HANDLE hContext,TPM_CURRENT_TICKS *tick);

TCSICALL
Tcsip_TickStampBlob(TCS_CONTEXT_HANDLE hContext,
        TCS_KEY_HANDLE     hKey,
        TCM_NONCE          antiReplay,
        TCM_DIGEST         digestToStamp,
        TCM_AUTH*          privAuth,
        UINT32*            pulSignatureLength,
        BYTE**             prgbSignature,
       // UINT32*            pulTickCountLength,
       // BYTE**             prgbTickCount
	   TPM_CURRENT_TICKS *tick
		);

////计数器
TCSICALL
Tcsip_CreateCounter(
     TCS_CONTEXT_HANDLE    hContext,    // in
     UINT32    LabelSize,    // in 
     BYTE *    pLabel,    // in
     TCM_ENCAUTH    CounterAuth,    // in
     TCM_AUTH *    pOwnerAuth,    // in, out
     TSM_COUNTER_ID *    idCounter,    // out
     TCM_COUNTER_VALUE *    counterValue    // out
    );

TCSICALL
Tcsip_IncrementCounter(
     TCS_CONTEXT_HANDLE    hContext,    // in
     TSM_COUNTER_ID    idCounter,    // in
     TCM_AUTH *    pCounterAuth,    // in, out
     TCM_COUNTER_VALUE *    counterValue    // out
    );

TCSICALL
Tcsip_ReadCounter(
    TCS_CONTEXT_HANDLE    hContext,    // in
    TSM_COUNTER_ID    idCounter,    // in
    TCM_COUNTER_VALUE*    counterValue    // out
    );

TCSICALL
Tcsip_ReleaseCounter(
    TCS_CONTEXT_HANDLE    hContext,    // in
    TSM_COUNTER_ID    idCounter,    // in
    TCM_AUTH *    pCounterAuth    // in, out
    );

TCSICALL
Tcsip_ReleaseCounterOwner( 
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_COUNTER_ID          idCounter,          // in
    TCM_AUTH*               pOwnerAuth          // in, out
    );


/*平台身份标识与认证*/
////密码模块密钥管理

////创建密码模块密钥
TCSICALL
Tcsip_CreateEndorsementKeyPair(
     TCS_CONTEXT_HANDLE    hContext,    // in
     TCM_NONCE    antiReplay,    // in
     UINT32    endorsementKeyInfoSize,    // in
     BYTE*    endorsementKeyInfo,    // in
     UINT32*    endorsementKeySize,    // out
     BYTE**    endorsementKey,    // out
     TCM_DIGEST*    checksum    // out
    );

TCSICALL
Tcsip_CreateRevocableEndorsementKeyPair(
     TCS_CONTEXT_HANDLE    hContext,    // in
     TCM_NONCE    antiReplay,    // in
     UINT32    endorsementKeyInfoSize, // in
     BYTE*    endorsementKeyInfo,    // in
     TSM_BOOL    GenResetAuth,    // in
     TCM_DIGEST*    EKResetAuth,    // in, out
     UINT32*    endorsementKeySize,    // out
     BYTE**    endorsementKey,    // out
     TCM_DIGEST*    checksum    // out
    );

TCSICALL
Tcsip_RevokeEndorsementKeyPair(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCM_DIGEST              EKResetAuth         // in
    );

TCSICALL
Tcsip_ReadPubEK(
    TCS_CONTEXT_HANDLE      hContext,                       // in
    TCM_NONCE              antiReplay,                      // in
    UINT32*                 pubEndorsementKeySize,          // out
    BYTE**                  pubEndorsementKey,              // out
    TCM_DIGEST*            checksum                        // out
    );

TCSICALL
Tcsip_OwnerReadInternalPub(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCS_KEY_HANDLE          hKey,               // in
    TCM_AUTH*               pOwnerAuth,         // in, out
    UINT32*                 punPubKeySize,      // out
    BYTE**                  ppbPubKeyData       // out
    );

////平台身份密钥管理
TCSICALL
Tcsip_MakeIdentity(
     TCS_CONTEXT_HANDLE    hContext,    // in
     TCM_ENCAUTH    identityAuth,    // in
     TCM_CHOSENID_HASH    IDLabel_PrivCAHash,    // in
     UINT32    idIdentityKeyInfoSize,    // in
     BYTE*    idIdentityKeyInfo,    // in
     TCM_AUTH*    pSmkAuth,    // in, out
     TCM_AUTH*    pOwnerAuth,    // in, out
     UINT32*    idIdentityKeySize,    // out
     BYTE**    idIdentityKey,     // out
     UINT32*    pcIdentityBindingSize,    // out
     BYTE**    prgbIdentityBinding,    // out
     UINT32*    pcEndorsementCredentialSize,    // out
     BYTE**    prgbEndorsementCredential    // out
    ); 

TCSICALL
Tcsip_ActivateIdentity(
     TCS_CONTEXT_HANDLE    hContext,    // in
     TCS_KEY_HANDLE    idKey,    // in
     UINT32    blobSize,    // in
     BYTE*    blob,    // in
     TCM_AUTH*    idKeyAuth,    // in, out
     TCM_AUTH*    ownerAuth,    // in, out
     UINT32*    SymmetricKeySize, // out
     BYTE**    SymmetricKey     // out
    );

TCSICALL
Tcsip_ActivatePEKCert(
    TCS_CONTEXT_HANDLE    hContext,    // in
    UINT32    blobSize,    // in
    BYTE*    blob,    // in
    TCM_AUTH*    ownerAuth,    // in, out
    UINT32*    SymmetricKeySize,    // out
    BYTE**    SymmetricKey    // out
    );

TCSICALL
Tcsip_ActivatePEK(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCM_ENCAUTH             KeyUsageAuth,       // in
    TCM_ENCAUTH             KeyMigrationAuth,   // in
    UINT32                  PEKKeyInfoSize,     // in
    BYTE*                   PEKKeyInfo,         // in
    UINT32                  PEKDataSize,        // in
    BYTE*                   PEKData,            // in
    UINT32                  EncSymKeySize,      // in
    BYTE*                   EncSymKey,          // in
    TCM_AUTH*               pSmkAuth,           // in, out
    TCM_AUTH*               pOwnerAuth,         // in, out
    UINT32*                 PekKeySize,         // out
    BYTE**                  PekKey              // out
    ); 



/*平台数据保护*/
////数据保护操作
TCSICALL
Tcsip_Seal(
     TCS_CONTEXT_HANDLE hContext,    // in
     TCS_KEY_HANDLE keyHandle,    // in
     TCM_ENCAUTH encAuth,    // in
     UINT32 pcrInfoSize,    // in
     BYTE* PcrInfo,    // in
     UINT32 inDataSize,    // in
     BYTE* inData,    // in
     TCM_AUTH* pAuth,    // in, out
     UINT32* SealedDataSize,    // out
     BYTE** SealedData    // out
    );

TCSICALL
Tcsip_Unseal(
    TCS_CONTEXT_HANDLE    hContext,    // in
    TCS_KEY_HANDLE    keyHandle,    // in
    UINT32    SealedDataSize, // in
    BYTE*    SealedData,    // in
    TCM_AUTH*    keyAuth,    // in, out
    TCM_AUTH*    dataAuth,    // in, out
    UINT32*    DataSize,    // out
    BYTE**    Data    // out
    );


////密钥管理
TCSICALL
Tcsip_CreateWrapKey(
     TCS_CONTEXT_HANDLE     hContext,           // in
     TCS_KEY_HANDLE         hWrappingKey,       // in
     TCM_ENCAUTH            KeyUsageAuth,       // in
     TCM_ENCAUTH            KeyMigrationAuth,   // in
     UINT32                 keyInfoSize,        // in
     BYTE*                  keyInfo,            // in
     TCM_AUTH*              pAuth,              // in, out
     UINT32*                keyDataSize,        // out
     BYTE**                 keyData             // out
    );

TCSICALL
Tcsip_LoadKeyByBlob(
     TCS_CONTEXT_HANDLE     hContext,    // in
     TCS_KEY_HANDLE         hUnwrappingKey,    // in
     UINT32                 cWrappedKeyBlobSize,    // in
     BYTE*                  rgbWrappedKeyBlob,    // in
     TCM_AUTH*              pAuth,    // in, out
     TCS_KEY_HANDLE*        phKeyTCSI    // out
    );

TCSICALL
Tcsip_LoadKeyByUUID(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_UUID                KeyUUID,            // in
    TCS_LOADKEY_INFO*       pLoadKeyInfo,       // in, out
    TCS_KEY_HANDLE*         phKeyTCSI           // out
    );

TCSICALL
Tcsip_GetPubKey(
    TCS_CONTEXT_HANDLE    hContext,    // in
    TCS_KEY_HANDLE    hKey,    // in
    TCM_AUTH*    pAuth,    // in, out
    UINT32*    pcPubKeySize,    // out
    BYTE**    prgbPubKey    // out
    );

TCSICALL
Tcsip_WrapKey(
     TCS_CONTEXT_HANDLE    hContext,    // in
     TCS_KEY_HANDLE    hWrappingKey,    // in
     TCM_ENCAUTH    KeyUsageAuth,    // in
     TCM_ENCAUTH    KeyMigrationAuth,    // in
     UINT32    keyInfoSize,    // in
     BYTE*    keyInfo,    // in
     TCM_AUTH*    pAuth,    // in, out
     UINT32*    keyDataSize,    // out
     BYTE**    keyData    // out
    );

TCSICALL
Tcsip_CertifyKey(
    TCS_CONTEXT_HANDLE    hContext,    // in
    TCS_KEY_HANDLE    certHandle,    // in
    TCS_KEY_HANDLE    keyHandle,    // in
    TCM_NONCE    antiReplay,    // in
    TCM_AUTH*    certAuth,    // in, out
    TCM_AUTH*    keyAuth,    // in, out
    UINT32*    CertifyInfoSize,    // out
    BYTE**    CertifyInfo,    // out
    UINT32*    outDataSize,    // out
    BYTE**    outData    // out
    );

TCSICALL
Tcsip_FlushSpecific(
	TCS_CONTEXT_HANDLE      hContext,           // in
	TCS_HANDLE              hResHandle,         // in
	TCM_RESOURCE_TYPE       resourceType        // in
    );



////密钥协商
TCSICALL
Tcsip_CreateKeyExchange(
     TCS_CONTEXT_HANDLE    hContext,    //in
     TCM_AUTH*    ownerAuth,    // in, out
     TCM_EXCHANGE_HANLDE *    phExchange,    // out
     UINT32*     pcRxSize,    //out
     BYTE**    prgbRxPoint    //out
    );

TCSICALL
Tcsip_GetKeyExchange(
    TCS_CONTEXT_HANDLE    hContext,    //in
    TCS_KEY_HANDLE    hKey,    // in
    TSM_EXCHANGE_HANLDE    hExchange,    // in
    TSM_EXCHANGE_TAG    cExchangeTag,    // in
    TSM_ENCAUTH    KeyUsageAuth,    // in
    UINT32      cPointSize,    // in
    BYTE*     rgbPoint,    // in
    UINT32      cRaSize,    // in
    BYTE*     rgbRa,    // in
    UINT32      cRbSize,    // in
    BYTE*     rgbRb,    // in
    UINT32      cRxSize,    // in
    BYTE*     rgbRx,    // in
    TSM_HKEY *     phKey,    // in ,out
    TCM_AUTH*    keyAuth,    // in, out
    UINT32*     pcSxSize,    //out
    BYTE**     prgbSxData,    // out
    UINT32*     pcSySize,    // out
    BYTE**     prgbSyData    // out 
    );

TCSICALL
Tcsip_ReleaseExchangeSession(
    TCS_CONTEXT_HANDLE    hContext,    //in
    TCM_EXCHANGE_HANLDE    hExchange    // in
    );





////密钥迁移
TCSICALL
Tcsip_AuthorizeMigrationKey(
    TCS_CONTEXT_HANDLE      hContext,               // in
    TSM_MIGRATE_SCHEME      migrateScheme,          // in
    UINT32                  MigrationKeySize,       // in
    BYTE*                   MigrationKey,           // in
    TCM_AUTH*               ownerAuth,              // in, out
    UINT32*                 MigrationKeyAuthSize,   // out
    BYTE**                  MigrationKeyAuth        // out
    );

TCSICALL
Tcsip_CreateMigrationBlob(
    TCS_CONTEXT_HANDLE      hContext,               // in
    TCS_KEY_HANDLE          parentHandle,           // in
    TSM_MIGRATE_SCHEME      migrationType,          // in
    UINT32                  MigrationKeyAuthSize,   // in
    BYTE*                   MigrationKeyAuth,       // in
    UINT32                  encDataSize,            // in
    BYTE*                   encData,                // in
    TCM_AUTH*               parentAuth,             // in, out
    TCM_AUTH*               entityAuth,             // in, out
    UINT32*                 SymEncDataSize,         // out
    BYTE**                  SymEncData,             // out
    UINT32*                 outDataSize,            // out
    BYTE**                  outData                 // out
    );

TCSICALL
Tcsip_ConvertMigrationBlob(
    TCS_CONTEXT_HANDLE      hContext,               // in
    TCS_KEY_HANDLE          parentHandle,           // in
    TCS_KEY_HANDLE          MEKHandle,              // in
    UINT32                  rgbMigratedDataSize,    // in
    BYTE*                   rgbMigratedData,        // in
    UINT32                  ulEncSymKeySize,        // in
    BYTE*                   rgbEncSymKey,           // in
    TCM_AUTH*               MEKAuth,                // in, out
    TCM_AUTH*               parentAuth,             // in, out
    UINT32*                 outDataSize,            // out
    BYTE**                  outData                 // out
    );

////密码学服务
//
TCSICALL
Tcsip_Sign(
     TCS_CONTEXT_HANDLE    hContext,    // in
     TCS_KEY_HANDLE    keyHandle,    // in
     UINT32    areaToSignSize,    // in
     BYTE*    areaToSign,    // in
     TCM_AUTH*    privAuth,    // in, out
     UINT32*    sigSize,    // out
     BYTE**    sig    // out
    ); 
//
TCSICALL
Tcsip_SMS4Encrypt(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCS_KEY_HANDLE          enckeyHandle,       // in
    BYTE*                   IV,                 // in
    UINT32                  inDataSize,         // in
    BYTE*                   inData,             // in
    TCM_AUTH*               pEncAuth,           // in, out
    UINT32*                 outDataSize,        // out
    BYTE**                  outData             // out
    );
//
TCSICALL
Tcsip_SMS4Decrypt(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCS_KEY_HANDLE          DnckeyHandle,       // in
    BYTE*                   IV,                 // in
    UINT32                  inDataSize,         // in
    BYTE*                   inData,             // in
    TCM_AUTH*               pEncAuth,           // in, out
    UINT32*                 outDataSize,        // out
    BYTE**                  outData             // out
    );
//
TCSICALL
Tcsip_SM2Decrypt(
    TCS_CONTEXT_HANDLE    hContext,    // in
    TCS_KEY_HANDLE    keyHandle,    // in
    UINT32    inDataSize,    // in
    BYTE*    inData,    // in
    TCM_AUTH*    privAuth,    // in, out
    UINT32*    outDataSize,    // out
    BYTE**    outData    // out
    );

TCSICALL
Tcsip_GetRandom(
                TCS_CONTEXT_HANDLE         hContext,         // in
                UINT32*                     dataSize,         // in , out
                BYTE**                     outData            // out
    );



////传输会话
//
TCSICALL
Tcsip_EstablishTransport(
    TCS_CONTEXT_HANDLE    hContext,    // in
    UINT32    ulTransControlFlags,    // in
    TCS_KEY_HANDLE    hEncKey,    // in
    UINT32    ulTransSessionInfoSize,    // in
    BYTE*    rgbTransSessionInfo,    // in
    UINT32    ulSecretSize,    // in
    BYTE*    rgbSecret,    // in
    TCM_AUTH*    pEncKeyAuth,    // in, out
    TCM_LOCALITY_MOD*    pbLocality,    // out
    TCS_HANDLE*    hTransSession,    // out
    UINT32*    ulCurrentTicks,    // out
    BYTE**    prgbCurrentTicks,    // out
    UINT32*    ulTransSeq    // out
    ); 
//
TCSICALL
Tcsip_ExecuteTransport(
     TCS_CONTEXT_HANDLE    hContext,     //in
     TCM_COMMAND_CODE    unWrappedCommandOrdinal,    // in
     UINT32      ulWrappedCmdDataInSize,    // in
     BYTE*     rgbWrappedCmdDataIn,    // in
     UINT32*     pulHandleListSize,    // in, out
     TCS_HANDLE**    rghHandles,     // in, out
     TCM_AUTH*    pWrappedCmdAuth1,    // in, out
     TCM_AUTH*    pWrappedCmdAuth2,    // in, out
     TCM_AUTH*    pTransAuth,     // in, out
     UINT64*     punCurrentTicks,    // out
     TCPA_LOCALITY_MOD*    pbLocality,     // out
     TSM_RESULT*    pulWrappedCmdReturnCode,    // out
     UINT32*     ulWrappedCmdDataOutSize,    // out
     BYTE**     rgbWrappedCmdDataOut    // out
    
    );

//
TCSICALL
Tcsip_ReleaseTransport(
     TCS_CONTEXT_HANDLE    hContext,    // in
     TCM_AUTH*    pTransAuth,    // in, out
     TCM_LOCALITY_MOD*    pbLocality,    // out
     UINT32*    pulCurrentTicks,    // out
     BYTE**    prgbCurrentTicks    // out
    ); 


////授权协议
//
TCSICALL
Tcsip_APCreate(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCM_ENTITY_TYPE         entityType,         // in
    UINT32                  entityValue,        // in
    TCM_NONCE               callerNonce,        // in
    TCM_AUTHDATA*           pAuth,              // in, out
    TCS_AUTHHANDLE*         authHandle,         // out
    TCM_NONCE*              TcmNonce,           // out
    UINT32*                 AntiReplaySeq       // out
    );
//
TCSICALL
Tcsip_APTerminate(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCS_AUTHHANDLE          authHandle,         // in
    TCM_AUTH*               pAuth               // in
    ); 


/*完整性度量与报告*/
//平台配置寄存器管理
TCSICALL
Tcsip_Extend (
     TCS_CONTEXT_HANDLE    hContext,    // in
     TCM_PCRINDEX    pcrNum,    // in
     TCM_DIGEST    inDigest,    // in
     TCM_PCRVALUE*    outDigest    // in, out
    );
//
TCSICALL
Tcsip_PcrRead(
     TCS_CONTEXT_HANDLE    hContext,    // in
     TCM_PCRINDEX    pcrNum,    // in
     TCM_PCRVALUE*    outDigest    // out
    );
//
TCSICALL
Tcsip_Quote(
    TCS_CONTEXT_HANDLE    hContext,    // in
    TCS_KEY_HANDLE    keyHandle,    // in
    TCM_NONCE    antiReplay,    // in
    UINT32    pcrTargetSize,    // in
    BYTE*    pcrTarget,    // in
    TCM_AUTH*    privAuth,    // in, out
    UINT32*    pcrDataSize,    // out
    BYTE**    pcrData,    // out
    UINT32*    sigSize,    // out
    BYTE**    sig    // out
    ); 
//
TCSICALL
Tcsip_PcrReset(
     TCS_CONTEXT_HANDLE    hContext,    // in
     UINT32    pcrTargetSize,    // in
     BYTE*    pcrTarget    // in
    ); 

TCSICALL
Tcsip_SM3Start(
     TCS_CONTEXT_HANDLE    hContext,    // in
     UINT32    *BlockSize
    ); 

TCSICALL
Tcsip_SM3Update(
     TCS_CONTEXT_HANDLE    hContext,    // in
     UINT32    BlockSize,
	 BYTE*    BlockData
    ); 

TCSICALL
Tcsip_SM3Complete(
     TCS_CONTEXT_HANDLE    hContext,    // in
     UINT32    BlockSize,
	 BYTE*     BlockData,    // in
	 BYTE*     Digest
    ); 

TCSICALL
Tcsip_SM3CompleteExtend(
     TCS_CONTEXT_HANDLE    hContext,    // in
	 UINT32    PCRSelect,
     UINT32    BlockSize,
	 BYTE*     BlockData,    // in
	 BYTE*     Digest,
	 BYTE*     PCRInfo
    ); 


TCSICALL 
Tcs_sava_Context(TCS_CONTEXT_HANDLE hContext,
				 TCS_KEY_HANDLE ResourceHandle, /*in*/
				 TPM_RESOURCE_TYPE ResouceType, /*in*/
				 BYTE* ResouceLable,			/*in*/
				 //TPM_CONTEXT_BLOB* contextBlob	/*out*/
				 UINT32*		ctxBlobSize,
				 BYTE*			ctxBlob
				 );

TCSICALL 
Tcs_load_Context(TCS_KEY_HANDLE EntityHandle, /*in*/
				 TPM_BOOL		OldHandle,	  /*in*/
				 //TPM_CONTEXT_BLOB contextBlob,/*in*/
				 UINT32		ctxBlobSize,
				 BYTE*			ctxBlob,
				 TCS_KEY_HANDLE* ResourceHandle /*out*/
				 );
TCSICALL
getTCMHandle(TCS_CONTEXT_HANDLE hContext,
			 TCS_KEY_HANDLE TCSKeyHandle,
			 TCM_KEY_HANDLE* TCMKeyHandle);
#ifdef __cplusplus
}
#endif

#endif
