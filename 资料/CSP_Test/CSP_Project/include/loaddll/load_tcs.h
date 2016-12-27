#ifndef LOAD_TCSK_H
#define LOAD_TCSK_H

#ifdef WIN32

#pragma comment (lib, "Kernel32.lib")

#else
#error linux load_tcs_dll
#endif

#include "../jwtsm.h"

#pragma pack(push)
#pragma pack(1)

typedef struct _tcs_dll_module_{
	void * hModule;

    long (* load)(struct _tcs_dll_module_* m, const char* name);
	long (* free)(struct _tcs_dll_module_* m);
    
	char name[256];

	//////////////////////////////////////////////////////////////////////////
	// Debug
	void (STDCALL* DebugCallback)(unsigned long flag, void * p);

    // TCS Context Manager

    TSM_RESULT (STDCALL* Tcs_OpenContext)(
        TCS_CONTEXT_HANDLE*     hContext            // in
        );

    TSM_RESULT (STDCALL* Tcs_CloseContext)(
        TCS_CONTEXT_HANDLE      hContext            // in
        );

    TSM_RESULT (STDCALL* Tcs_FreeMemory)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        BYTE*                   pMemory             // in
        );

    TSM_RESULT (STDCALL* Tcs_GetCapability)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TCM_CAPABILITY_AREA     capArea,            // in
        UINT32                  subCapSize,         // in
        BYTE*                   subCap,             // in
        UINT32*                 respSize,           // out
        BYTE**                  resp                // out
        );

    // TCS Key and Credential Manager

    TSM_RESULT (STDCALL* Tcs_RegisterKey)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_UUID                WrappingKeyUUID,    // in
        TSM_UUID                KeyUUID,            // in
        UINT32                  cKeySize,           // in
        BYTE*                   rgbKey,             // in
        UINT32                  cVendorDataSize,    // in
        BYTE*                   rgbVendorData       // in
        );

    TSM_RESULT (STDCALL* Tcs_UnregisterKey)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_UUID                KeyUUID             // in
        );

    TSM_RESULT (STDCALL* Tcs_EnumRegisteredKeys)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_UUID*               pKeyUUID,           // in
        UINT32*                 pcKeyHierarchySize, // out
        TSM_KM_KEYINFO**        ppKeyHierarchy      // out
        );

    TSM_RESULT (STDCALL* Tcs_GetRegisteredKey)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_UUID                KeyUUID,            // in
        TSM_KM_KEYINFO**        ppKeyInfo           // out
        );

    TSM_RESULT (STDCALL* Tcs_GetRegisteredKeyBlob)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_UUID                KeyUUID,            // in
        UINT32*                 pcKeySize,          // out
        BYTE**                  prgbKey             // out
        );

    TSM_RESULT (STDCALL* Tcs_GetRegisteredKeyByPublicInfo)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_ALGORITHM_ID        algID,              // in
        UINT32                  ulPublicInfoLength, // in
        BYTE*                   rgbPublicInfo,      // in
        UINT32*                 keySize,            // out
        BYTE**                  keyBlob             // out
        );

    TSM_RESULT (STDCALL* Tcs_CollatePekRequest)(
        TCS_CONTEXT_HANDLE      hContext,                       // in
        TCM_CHOSENID_HASH       IDLabel_PrivCAHash,             // in
        UINT32*                 pcEndorsementCredentialSize,    // out
        BYTE**                  prgbEndorsementCredential       // out
        ); 

////事件管理
    TSM_RESULT (STDCALL* Tcs_LogPcrEvent)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_PCR_EVENT           Event,              // in
        UINT32*                 pNumber             // out
        );

    TSM_RESULT (STDCALL* Tcs_GetPcrEvent)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        UINT32                  PcrIndex,           // in
        UINT32*                 pNumber,            // in, out
        TSM_PCR_EVENT**         ppEvent             // out
        );

    TSM_RESULT (STDCALL* Tcs_GetPcrEventsByPcr)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        UINT32                  PcrIndex,           // in
        UINT32                  FirstEvent,         // in
        UINT32*                 pEventCount,        // in, out
        TSM_PCR_EVENT**         ppEvents            // out
        );

    TSM_RESULT (STDCALL* Tcs_GetPcrEventLog)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        UINT32*                 pEventCount,        // out
        TSM_PCR_EVENT**         ppEvents            // out
        );

    // 可信密码模块管理
    // TCM测试
    TSM_RESULT (STDCALL* Tcsip_SelfTestFull)(
        TCS_CONTEXT_HANDLE      hContext            // in
        );

    TSM_RESULT (STDCALL* Tcsip_ContinueSelfTest)(
         TCS_CONTEXT_HANDLE     hContext            // in
        );

    TSM_RESULT (STDCALL* Tcsip_GetTestResult)(
         TCS_CONTEXT_HANDLE     hContext,           // in
         UINT32*                outDataSize,        // out
         BYTE**                 outData             // out
        );

    // 工作模式设置
    TSM_RESULT (STDCALL* Tcsip_SetOwnerInstall)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_BOOL                state               // in
        );

    TSM_RESULT (STDCALL* Tcsip_OwnerSetDisable)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_BOOL                disableState,       // in 
        TCM_AUTH*               ownerAuth           // in, out
        );

    TSM_RESULT (STDCALL* Tcsip_PhysicalEnable)(
        TCS_CONTEXT_HANDLE      hContext            // in
        );

    TSM_RESULT (STDCALL* Tcsip_PhysicalDisable)(
        TCS_CONTEXT_HANDLE      hContext            // in
        );

    TSM_RESULT (STDCALL* Tcsip_SetTempDeactived)(
         TCS_CONTEXT_HANDLE     hContext            // in
        ); 

    TSM_RESULT (STDCALL* Tcsip_PhysicalSetDeactivated)(
        TCS_CONTEXT_HANDLE      hContext,           // in 
        TSM_BOOL                state               // in
        );

    TSM_RESULT (STDCALL* Tcsip_SetOperatorAuth)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_SECRET              operatorAuth        // in
        );

    TSM_RESULT (STDCALL* Tcsip_PhysicalPresence)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_PHYSICAL_PRESENCE   fPhysicalPresence   // in
        );

    //所有者管理
    TSM_RESULT (STDCALL* Tcsip_TakeOwnership)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        UINT16                  protocolID,         // in
        UINT32                  encOwnerAuthSize,   // in
        BYTE*                   encOwnerAuth,       // in
        UINT32                  encSmkAuthSize,     // in
        BYTE*                   encSmkAuth,         // in
        UINT32                  smkKeyInfoSize,     // in
        BYTE*                   smkKeyInfo,         // in
        TSM_AUTH*               ownerAuth,          // in, out
        UINT32*                 smkKeyDataSize,     // out
        BYTE**                  smkKeyData          // out
        );

    TSM_RESULT (STDCALL* Tcsip_OwnerClear)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_AUTH*               ownerAuth           // in, out
        );

    TSM_RESULT (STDCALL* Tcsip_DisableOwnerClear)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_AUTH*               ownerAuth           // in, out
        );

    TSM_RESULT (STDCALL* Tcsip_ForceClear)( 
        TCS_CONTEXT_HANDLE      hContext            // in
        );

    TSM_RESULT (STDCALL* Tcsip_DisableForceClear)( 
        TCS_CONTEXT_HANDLE      hContext            // in
        );

    //属性管理
    TSM_RESULT (STDCALL* Tcsip_GetCapability)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_CAPABILITY_AREA     capArea,            // in
        UINT32                  subCapSize,         // in
        BYTE*                   subCap,             // in
        UINT32*                 respSize,           // out
        BYTE**                  resp                // out
        );

    TSM_RESULT (STDCALL* Tcsip_SetCapability)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TCM_CAPABILITY_AREA     capArea,            // in
        UINT32                  subCapSize,         // in
        BYTE*                   subCap,             // in
        UINT32                  valueSize,          // in
        BYTE*                   value,              // in
        TCM_AUTH*               ownerAuth           // in out
        );


    //升级维护
    TSM_RESULT (STDCALL* Tcsip_FieldUpgrade)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        UINT32                  dataInSize,         // in
        BYTE*                   dataIn,             // in
        TCM_AUTH*               ownerAuth,          // in, out
        UINT32*                 dataOutSize,        // out
        BYTE**                  dataOut             // out
        );

    TSM_RESULT (STDCALL* Tcsip_ResetLockValue)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TCM_AUTH*               ownerAuth           // in, out
        );


    //授权值管理
    TSM_RESULT (STDCALL* Tcsip_ChangeAuth)(
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

    TSM_RESULT (STDCALL* Tcsip_ChangeAuthOwner)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TCM_PROTOCOL_ID         protocolID,         // in
        TCM_ENCAUTH             newAuth,            // in
        TCM_ENTITY_TYPE         entityType,         // in
        TCM_AUTH*               ownerAuth           // in, out
        );

    //非易失性存储管理
    TSM_RESULT (STDCALL* Tcsip_NV_DefineOrReleaseSpace)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        UINT32                  cPubInfoSize,       // in
        BYTE*                   pPubInfo,           // in
        TCM_ENCAUTH             encAuth,            // in
        TCM_AUTH*               pAuth               // in, out
        );

    TSM_RESULT (STDCALL* Tcsip_NV_WriteValue)(
         TCS_CONTEXT_HANDLE     hContext,           // in
         TSM_NV_INDEX           hNVStore,           // in
         UINT32                 offset,             // in
         UINT32                 ulDataLength,       // in
         BYTE*                  rgbDataToWrite,     // in
         TCM_AUTH*              privAuth            // in, out
        );

    TSM_RESULT (STDCALL* Tcsip_NV_WriteValueAuth)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_NV_INDEX            hNVStore,           // in
        UINT32                  offset,             // in
        UINT32                  ulDataLength,       // in
        BYTE*                   rgbDataToWrite,     // in
        TCM_AUTH*               NVAuth              // in, out
        );

    TSM_RESULT (STDCALL* Tcsip_NV_ReadValue)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_NV_INDEX            hNVStore,           // in
        UINT32                  offset,             // in
        UINT32*                 pulDataLength,      // in, out
        TCM_AUTH*               privAuth,           // in, out
        BYTE**                  rgbDataRead         // out
        );

    TSM_RESULT (STDCALL* Tcsip_NV_ReadValueAuth)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_NV_INDEX            hNVStore,           // in
        UINT32                  offset,             // in
        UINT32*                 pulDataLength,      // in, out
        TCM_AUTH*               NVAuth,             // in, out
        BYTE**                  rgbDataRead         // out
        );

    //审计
    TSM_RESULT (STDCALL* Tcsip_GetAuditDigest)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        UINT32                  startOrdinal,       // in
        TCM_DIGEST*             auditDigest,        // out
        UINT32*                 counterValueSize,   // out
        BYTE**                  counterValue,       // out
        TSM_BOOL*               more,               // out
        UINT32*                 ordSize,            // out
        UINT32**                ordList             // out
        );

    TSM_RESULT (STDCALL* Tcsip_GetAuditDigestSigned)(
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

    TSM_RESULT (STDCALL* Tcsip_SetOrdinalAuditStatus)(
         TCS_CONTEXT_HANDLE    hContext,    // in
         TCM_AUTH*    ownerAuth,    // in, out
         UINT32    ordinalToAudit, // in
         TSM_BOOL    auditState    // in
        );

    //时钟
    TSM_RESULT (STDCALL* Tcsip_ReadCurrentTicks)(
		TCS_CONTEXT_HANDLE hContext,
		TPM_CURRENT_TICKS *tick
		);

    TSM_RESULT (STDCALL* Tcsip_TickStampBlob)(TCS_CONTEXT_HANDLE hContext,
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


    //计数器
    TSM_RESULT (STDCALL* Tcsip_CreateCounter)(
         TCS_CONTEXT_HANDLE    hContext,    // in
         UINT32    LabelSize,    // in 
         BYTE *    pLabel,    // in
         TCM_ENCAUTH    CounterAuth,    // in
         TCM_AUTH *    pOwnerAuth,    // in, out
         TSM_COUNTER_ID *    idCounter,    // out
         TCM_COUNTER_VALUE *    counterValue    // out
        );

    TSM_RESULT (STDCALL* Tcsip_IncrementCounter)(
         TCS_CONTEXT_HANDLE    hContext,    // in
         TSM_COUNTER_ID    idCounter,    // in
         TCM_AUTH *    pCounterAuth,    // in, out
         TCM_COUNTER_VALUE *    counterValue    // out
        );

    TSM_RESULT (STDCALL* Tcsip_ReadCounter)(
        TCS_CONTEXT_HANDLE    hContext,    // in
        TSM_COUNTER_ID    idCounter,    // in
        TCM_COUNTER_VALUE*    counterValue    // out
        );

    TSM_RESULT (STDCALL* Tcsip_ReleaseCounter)(
        TCS_CONTEXT_HANDLE    hContext,    // in
        TSM_COUNTER_ID    idCounter,    // in
        TCM_AUTH *    pCounterAuth    // in, out
        );

    TSM_RESULT (STDCALL* Tcsip_ReleaseCounterOwner)( 
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_COUNTER_ID          idCounter,          // in
        TCM_AUTH*               pOwnerAuth          // in, out
        );

    // 平台身份标识与认证
    //创建密码模块密钥
    TSM_RESULT (STDCALL* Tcsip_CreateEndorsementKeyPair)(
         TCS_CONTEXT_HANDLE    hContext,    // in
         TCM_NONCE    antiReplay,    // in
         UINT32    endorsementKeyInfoSize,    // in
         BYTE*    endorsementKeyInfo,    // in
         UINT32*    endorsementKeySize,    // out
         BYTE**    endorsementKey,    // out
         TCM_DIGEST*    checksum    // out
        );

    TSM_RESULT (STDCALL* Tcsip_CreateRevocableEndorsementKeyPair)(
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

    TSM_RESULT (STDCALL* Tcsip_RevokeEndorsementKeyPair)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TCM_DIGEST              EKResetAuth         // in
        );

    TSM_RESULT (STDCALL* Tcsip_ReadPubEK)(
        TCS_CONTEXT_HANDLE      hContext,                       // in
        TCM_NONCE              antiReplay,                      // in
        UINT32*                 pubEndorsementKeySize,          // out
        BYTE**                  pubEndorsementKey,              // out
        TCM_DIGEST*            checksum                        // out
        );

    TSM_RESULT (STDCALL* Tcsip_OwnerReadInternalPub)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TCS_KEY_HANDLE          hKey,               // in
        TCM_AUTH*               pOwnerAuth,         // in, out
        UINT32*                 punPubKeySize,      // out
        BYTE**                  ppbPubKeyData       // out
        );

    //平台身份密钥管理
    TSM_RESULT (STDCALL* Tcsip_MakeIdentity)(
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

    TSM_RESULT (STDCALL* Tcsip_ActivateIdentity)(
         TCS_CONTEXT_HANDLE    hContext,    // in
         TCS_KEY_HANDLE    idKey,    // in
         UINT32    blobSize,    // in
         BYTE*    blob,    // in
         TCM_AUTH*    idKeyAuth,    // in, out
         TCM_AUTH*    ownerAuth,    // in, out
         UINT32*    SymmetricKeySize, // out
         BYTE**    SymmetricKey     // out
        );

    TSM_RESULT (STDCALL* Tcsip_ActivatePEKCert)(
        TCS_CONTEXT_HANDLE    hContext,    // in
        UINT32    blobSize,    // in
        BYTE*    blob,    // in
        TCM_AUTH*    ownerAuth,    // in, out
        UINT32*    SymmetricKeySize,    // out
        BYTE**    SymmetricKey    // out
        );

    TSM_RESULT (STDCALL* Tcsip_ActivatePEK)(
      TCS_CONTEXT_HANDLE         hContext,             // in
      TCM_ENCAUTH     KeyUsageAuth,         // in
      TCM_ENCAUTH     KeyMigrationAuth,     // in
      UINT32         PEKKeyInfoSize,     // in
      BYTE*         PEKKeyInfo,         // in
      UINT32         PEKDataSize,         // in
      BYTE*         PEKData,             // in
      UINT32*         EncSymKeySize,         // in
      BYTE**         EncSymKey,             // in
      TCM_AUTH*     pSmkAuth,             // in, out
      TCM_AUTH*     pOwnerAuth,         // in, out
      UINT32*         PekKeySize,         // out
      BYTE**         PekKey    // out
      ); 

    // 平台数据保护
    // 数据保护操作
    TSM_RESULT (STDCALL* Tcsip_Seal)(
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

    TSM_RESULT (STDCALL* Tcsip_Unseal)(
        TCS_CONTEXT_HANDLE    hContext,    // in
        TCS_KEY_HANDLE    keyHandle,    // in
        UINT32    SealedDataSize, // in
        BYTE*    SealedData,    // in
        TCM_AUTH*    keyAuth,    // in, out
        TCM_AUTH*    dataAuth,    // in, out
        UINT32*    DataSize,    // out
        BYTE**    Data    // out
        );

    //密钥管理
    TSM_RESULT (STDCALL* Tcsip_CreateWrapKey)(
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

    TSM_RESULT (STDCALL* Tcsip_LoadKeyByBlob)(
         TCS_CONTEXT_HANDLE     hContext,    // in
         TCS_KEY_HANDLE         hUnwrappingKey,    // in
         UINT32                 cWrappedKeyBlobSize,    // in
         BYTE*                  rgbWrappedKeyBlob,    // in
         TCM_AUTH*              pAuth,    // in, out
         TCS_KEY_HANDLE*        phKeyTCSI    // out
        );

    TSM_RESULT (STDCALL* Tcsip_LoadKeyByUUID)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TSM_UUID                KeyUUID,            // in
        TCS_LOADKEY_INFO*       pLoadKeyInfo,       // in, out
        TCS_KEY_HANDLE*         phKeyTCSI           // out
        );

    TSM_RESULT (STDCALL* Tcsip_GetPubKey)(
        TCS_CONTEXT_HANDLE    hContext,    // in
        TCS_KEY_HANDLE    hKey,    // in
        TCM_AUTH*    pAuth,    // in, out
        UINT32*    pcPubKeySize,    // out
        BYTE**    prgbPubKey    // out
        );

    TSM_RESULT (STDCALL* Tcsip_WrapKey)(
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

    TSM_RESULT (STDCALL* Tcsip_CertifyKey)(
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

    TSM_RESULT (STDCALL* Tcsip_FlushSpecific)(
         TCS_CONTEXT_HANDLE hContext,    // in
         TCS_KEY_HANDLE    hKey    // in
        );

    //密钥协商
    TSM_RESULT (STDCALL* Tcsip_CreateKeyExchange)(
         TCS_CONTEXT_HANDLE    hContext,    //in
         TSM_AUTH*    ownerAuth,    // in, out
         TCM_EXCHANGE_HANLDE *    phExchange,    // out
         UINT32*     pcRxSize,    //out
         BYTE**    prgbRxPoint    //out
        );

    TSM_RESULT (STDCALL* Tcsip_GetKeyExchange)(
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
        TSM_AUTH*    keyAuth,    // in, out
        UINT32*     pcSxSize,    //out
        BYTE**     prgbSxData,    // out
        UINT32*     pcSySize,    // out
        BYTE**     prgbSyData    // out 
        );

    TSM_RESULT (STDCALL* Tcsip_ReleaseExchangeSession)(
        TCS_CONTEXT_HANDLE    hContext,    //in
        TCM_EXCHANGE_HANLDE    hExchange    // in
        );

    //密钥迁移
    TSM_RESULT (STDCALL* Tcsip_AuthorizeMigrationKey)(
         TCS_CONTEXT_HANDLE hContext,    // in
         TSM_MIGRATE_SCHEME migrateScheme,    // in
         UINT32 MigrationKeySize,    // in
         BYTE* MigrationKey,    // in
         TCM_AUTH* ownerAuth,    // in, out
         UINT32* MigrationKeyAuthSize,    // out
         BYTE** MigrationKeyAuth    // out
        );

    TSM_RESULT (STDCALL* Tcsip_CreateMigrationBlob)(
        TCS_CONTEXT_HANDLE hContext,    // in
        TCS_KEY_HANDLE parentHandle,    // in
        TSM_MIGRATE_SCHEME migrationType,    // in
        UINT32 MigrationKeyAuthSize,    // in
        BYTE* MigrationKeyAuth,    // in
        UINT32 encDataSize,    // in
        BYTE* encData,     // in
        TCM_AUTH* parentAuth,    // in, out
        TCM_AUTH* entityAuth,     // in, out
        UINT32* SymEncDataSize,    // out
        BYTE** SymEncData,    // out
        UINT32* outDataSize,    // out
        BYTE** outData    // out
        );

    TSM_RESULT (STDCALL* Tcsip_ConvertMigrationBlob)(
         TCS_CONTEXT_HANDLE hContext,    // in
         TCS_KEY_HANDLE parentHandle,    // in
         TCS_KEY_HANDLE MEKHandle,    // in
         UINT32* prgbMigratedDataSize,    // in
         BYTE** prgbMigratedData,    // in
         UINT32* pulEncSymKeySize,    // in
         BYTE** prgbEncSymKey,    // in
         TCM_AUTH*MEKAuth,    // in, out
         TCM_AUTH* parentAuth,    // in, out
         UINT32* outDataSize,    // out
         BYTE** outData    // out
        );

    //密码学服务

    TSM_RESULT (STDCALL* Tcsip_Sign)(
         TCS_CONTEXT_HANDLE    hContext,    // in
         TCS_KEY_HANDLE    keyHandle,    // in
         UINT32    areaToSignSize,    // in
         BYTE*    areaToSign,    // in
         TCM_AUTH*    privAuth,    // in, out
         UINT32*    sigSize,    // out
         BYTE**    sig    // out
        ); 

    TSM_RESULT (STDCALL* Tcsip_SMS4Encrypt)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TCS_KEY_HANDLE          enckeyHandle,       // in
        BYTE*                   IV,                 // in
        UINT32                  inDataSize,         // in
        BYTE*                   inData,             // in
        TCM_AUTH*               pEncAuth,           // in, out
        UINT32*                 outDataSize,        // out
        BYTE**                  outData             // out
        );

    TSM_RESULT (STDCALL* Tcsip_SMS4Decrypt)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        TCS_KEY_HANDLE          DnckeyHandle,       // in
        BYTE*                   IV,                 // in
        UINT32                  inDataSize,         // in
        BYTE*                   inData,             // in
        TCM_AUTH*               pEncAuth,           // in, out
        UINT32*                 outDataSize,        // out
        BYTE**                  outData             // out
        );

    TSM_RESULT (STDCALL* Tcsip_SM2Decrypt)(
        TCS_CONTEXT_HANDLE    hContext,    // in
        TCS_KEY_HANDLE    keyHandle,    // in
        UINT32    inDataSize,    // in
        BYTE*    inData,    // in
        TCM_AUTH*    privAuth,    // in, out
        UINT32*    outDataSize,    // out
        BYTE**    outData    // out
        ); 

    TSM_RESULT (STDCALL* Tcsip_GetRandom)(
        TCS_CONTEXT_HANDLE      hContext,           // in
        UINT32*                 dataSize,           // in , out
        BYTE**                  outData             // out
        );

    //传输会话
    TSM_RESULT (STDCALL* Tcsip_EstablishTransport)(
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

    TSM_RESULT (STDCALL* Tcsip_ExecuteTransport)(
         TCS_CONTEXT_HANDLE    hContext,     //in
         TCM_COMMAND_CODE    unWrappedCommandOrdinal,    // in
         UINT32      ulWrappedCmdDataInSize,    // in
         BYTE*     rgbWrappedCmdDataIn,    // in
         UINT32*     pulHandleListSize,    // in, out
         TCS_HANDLE**    rghHandles,     // in, out
         TSM_AUTH*    pWrappedCmdAuth1,    // in, out
         TSM_AUTH*    pWrappedCmdAuth2,    // in, out
         TSM_AUTH*    pTransAuth,     // in, out
         UINT64*     punCurrentTicks,    // out
     TCPA_LOCALITY_MOD*    pbLocality,     // out
     TSM_RESULT*    pulWrappedCmdReturnCode,    // out
         UINT32*     ulWrappedCmdDataOutSize,    // out
         BYTE**     rgbWrappedCmdDataOut    // out
        );

    TSM_RESULT (STDCALL* Tcsip_ReleaseTransport)(
         TCS_CONTEXT_HANDLE    hContext,    // in
         TCM_AUTH*    pTransAuth,    // in, out
         TCM_LOCALITY_MOD*    pbLocality,    // out
         UINT32*    pulCurrentTicks,    // out
         BYTE**    prgbCurrentTicks    // out
        ); 

    //授权协议

    TSM_RESULT (STDCALL* Tcsip_APCreate)(
         TCS_CONTEXT_HANDLE    hContext,    // in
         TCM_ENTITY_TYPE    entityType,    // in
         UINT32    entityValue,    // in
         TCM_NONCE    callerNonce,    // in
         TCM_AUTHDATA*    pAuth,    // in, out
         TCS_AUTHHANDLE*    authHandle,    // out
         TCM_NONCE*    TcmNonce,    // out
         UINT32 *    AntiReplaySeq    // out
        );

    TSM_RESULT (STDCALL* Tcsip_APTerminate)(
        TCS_CONTEXT_HANDLE    hContext,    // in
        TCS_AUTHHANDLE    authHandle,    // in
        TCM_AUTH*    pAuth    // in
        ); 

    // 完整性度量与报告
    // 平台配置寄存器管理
    TSM_RESULT (STDCALL* Tcsip_Extend)(
         TCS_CONTEXT_HANDLE    hContext,    // in
         TCM_PCRINDEX    pcrNum,    // in
         TCM_DIGEST    inDigest,    // in
         TCM_PCRVALUE*    outDigest    // in, out
        );

    TSM_RESULT (STDCALL* Tcsip_PcrRead)(
         TCS_CONTEXT_HANDLE    hContext,    // in
         TCM_PCRINDEX    pcrNum,    // in
         TCM_PCRVALUE*    outDigest    // out
        );

    TSM_RESULT (STDCALL* Tcsip_Quote)(
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

    TSM_RESULT (STDCALL* Tcsip_PcrReset)(
         TCS_CONTEXT_HANDLE    hContext,    // in
         UINT32    pcrTargetSize,    // in
         BYTE*    pcrTarget    // in
        ); 


	TSM_RESULT (STDCALL* Tcsip_SM3Start)(
     TCS_CONTEXT_HANDLE    hContext,    // in
     UINT32    *BlockSize
    ); 

	TSM_RESULT (STDCALL* Tcsip_SM3Update)(
     TCS_CONTEXT_HANDLE    hContext,    // in
     UINT32    BlockSize,
	 BYTE*    BlockData
);

TSM_RESULT (STDCALL* Tcsip_SM3Complete)(
     TCS_CONTEXT_HANDLE    hContext,    // in
     UINT32    BlockSize,
	 BYTE*     BlockData,    // in
	 BYTE*     Digest
    ); 

	TSM_RESULT (STDCALL* Tcsip_SM3CompleteExtend)(
     TCS_CONTEXT_HANDLE    hContext,    // in
	 UINT32    PCRSelect,
     UINT32    BlockSize,
	 BYTE*     BlockData,    // in
	 BYTE*     Digest,
	 BYTE*     PCRInfo
    ); 

	TSM_RESULT
		(STDCALL* Tcs_sava_Context)(TCS_CONTEXT_HANDLE hContext,
						TCS_KEY_HANDLE ResourceHandle, /*in*/
						TPM_RESOURCE_TYPE ResouceType, /*in*/
						BYTE* ResouceLable,			/*in*/
						//TPM_CONTEXT_BLOB* contextBlob	/*out*/
						UINT32*		ctxBlobSize,
						BYTE*			ctxBlob
						);
	
	TSM_RESULT
		(STDCALL*  Tcs_load_Context)(TCS_KEY_HANDLE EntityHandle, /*in*/
						TPM_BOOL		OldHandle,	  /*in*/
						//TPM_CONTEXT_BLOB contextBlob,/*in*/
						UINT32		ctxBlobSize,
						BYTE*			ctxBlob,
						TCS_KEY_HANDLE* ResourceHandle /*out*/
						);

	TSM_RESULT
		(STDCALL*  getTCMHandle)(TCS_CONTEXT_HANDLE hContext,
						TCS_KEY_HANDLE TCSKeyHandle,
						TCM_KEY_HANDLE* TCMKeyHandle);

}TCS_DLL_MODULE;

#pragma pack(pop)

extern TCS_DLL_MODULE gTcsModule;

#endif