#ifndef LOAD_TSP_DLL_H
#define LOAD_TSP_DLL_H

#ifdef WIN32

#pragma comment (lib, "Kernel32.lib")

#else
#error linux load_tsp
#endif

#include "../jwtsm.h"

#pragma pack(push)
#pragma pack(1)

typedef struct _tsp_module_
{
	void * hModule;

    long (* load)(struct _tsp_module_* m, const char* name);
	long (* free)(struct _tsp_module_* m);
	
	char name[256];

//////////////////////////////////////////////////////////////////////////
// 通用接口
//////////////////////////////////////////////////////////////////////////

TSM_RESULT (STDCALL*
Tspi_SetAttribUint32)(
    TSM_HOBJECT             hObject,            // in
    TSM_FLAG                attribFlag,         // in
    TSM_FLAG                subFlag,            // in
    UINT32                  ulAttrib            // in
    );

TSM_RESULT (STDCALL*
Tspi_GetAttribUint32)(
    TSM_HOBJECT             hObject,            // in
    TSM_FLAG                attribFlag,         // in
    TSM_FLAG                subFlag,            // in
    UINT32*                 pulAttrib           // out
    );

TSM_RESULT (STDCALL*
Tspi_SetAttribData)( 
    TSM_HOBJECT             hObject,            // in
    TSM_FLAG                attribFlag,         // in
    TSM_FLAG                subFlag,            // in
    UINT32                  ulAttribDataSize,   // in
    BYTE*                   rgbAttribData       // in
    );

TSM_RESULT (STDCALL*
Tspi_GetAttribData)( 
    TSM_HOBJECT             hObject,            // in
    TSM_FLAG                attribFlag,         // in
    TSM_FLAG                subFlag,            // in
    UINT32*                 pulAttribDataSize,  // out
    BYTE**                  prgbAttribData      // out
    );

TSM_RESULT (STDCALL*
Tspi_ChangeAuth)( 
    TSM_HOBJECT             hObjectToChange,    // in
    TSM_HOBJECT             hParentObject,      // in
    TSM_HPOLICY             hNewPolicy          // in
    );

TSM_RESULT (STDCALL*
Tspi_GetPolicyObject)( 
    TSM_HOBJECT             hObject,            // in
    TSM_FLAG                policyType,         // in
    TSM_HPOLICY*            phPolicy            // out
    );

//////////////////////////////////////////////////////////////////////////
// 上下文类
//////////////////////////////////////////////////////////////////////////

TSM_RESULT (STDCALL*
Tspi_Context_Create)( 
    TSM_HCONTEXT*           phContext           // out
    );

TSM_RESULT (STDCALL*
Tspi_Context_Close)(
    TSM_HCONTEXT            hContext            // in
    );

TSM_RESULT (STDCALL*
Tspi_Context_Connect)(
    TSM_HCONTEXT            hContext,         // in
    TSM_UNICODE*            wszDestination     // in
    );

TSM_RESULT (STDCALL*
Tspi_Context_FreeMemory)(
    TSM_HCONTEXT            hContext,     // in
    BYTE*                   rgbMemory // in
    );

TSM_RESULT (STDCALL*
Tspi_Context_GetDefaultPolicy)(
    TSM_HCONTEXT            hContext,     // in
    TSM_HPOLICY*            phPolicy      // out
    );

TSM_RESULT (STDCALL*
Tspi_Context_CreateObject)(
    TSM_HCONTEXT            hContext,     // in
    TSM_FLAG                objectType,         // in
    TSM_FLAG                initFlags,        // in
    TSM_HOBJECT*            phObject     // out
    );

TSM_RESULT (STDCALL*
Tspi_Context_CloseObject)(
    TSM_HCONTEXT            hContext,    // in
    TSM_HOBJECT             hObject     // in
    );

TSM_RESULT (STDCALL*
Tspi_Context_GetCapability)( 
    TSM_HCONTEXT            hContext,                 // in
    TSM_FLAG                capArea,                 // in
    UINT32                  ulSubCapLength,         // in
    BYTE*                   rgbSubCap,                 // in
    UINT32*                 pulRespDataLength,         // out
    BYTE**                  prgbRespData             // out
    );

TSM_RESULT (STDCALL*
Tspi_Context_GetTCMObject)( 
    TSM_HCONTEXT            hContext,                 // in
    TSM_HTCM*               phTCM                     // out
    );

TSM_RESULT (STDCALL*
Tspi_Context_LoadKeyByBlob)(
    TSM_HCONTEXT            hContext,        // in
    TSM_HKEY                hUnwrappingKey, // in
    UINT32                  ulBlobLength,     // in
    BYTE*                   rgbBlobData,     // in
    TSM_HKEY*               phKey             // out
    );

TSM_RESULT (STDCALL*
Tspi_Context_LoadKeyByUUID)( 
    TSM_HCONTEXT            hContext,              // in
    TSM_FLAG                persistentStorageType, // in
    TSM_UUID                uuidData,              // in
    TSM_HKEY*               phKey                  // out
    );

TSM_RESULT (STDCALL*
Tspi_Context_RegisterKey)(
    TSM_HCONTEXT            hContext,                     // in
    TSM_HKEY                hKey,                             // in
    TSM_FLAG                persistentStorageType,         // in
    TSM_UUID                uuidKey,                         // in
    TSM_FLAG                persistentStorageTypeParent,     // in
    TSM_UUID                uuidParentKey                 // in
    );

TSM_RESULT (STDCALL*
Tspi_Context_UnregisterKey)(
    TSM_HCONTEXT            hContext,               // in
    TSM_FLAG                persistentStorageType,// in
    TSM_UUID                uuidKey,               // in
    TSM_HKEY*               phkey                  //out
    );

TSM_RESULT (STDCALL*
Tspi_Context_GetKeyByUUID)(
    TSM_HCONTEXT            hContext,              // in
    TSM_FLAG                persistentStorageType, // in
    TSM_UUID                uuidData,              // in
    TSM_HKEY*               phKey                  // out
    );

TSM_RESULT (STDCALL*
Tspi_Context_GetKeyByPublicInfo)(
    TSM_HCONTEXT            hContext,                 // in
    TSM_FLAG                persistentStorageType, // in
    TSM_ALGORITHM_ID        algID,                 // in
    UINT32                  ulPublicInfoLength,     // in
    BYTE*                   rgbPublicInfo,         // in
    TSM_HKEY*               phKey                     // out
    );

TSM_RESULT (STDCALL*
Tspi_Context_GetRegisteredKeysByUUID)(
    TSM_HCONTEXT            hContext,              // in
    TSM_FLAG                persistentStorageType,// in
    TSM_UUID*               pUuidData,              // in
    UINT32*                 pulKeyHierarchySize,  // out
    TSM_KM_KEYINFO**        ppKeyHierarchy          // out
    );

TSM_RESULT (STDCALL*
Tspi_Context_SetTransEncryptionKey)( 
    TSM_HCONTEXT            hContext,               // in
    TSM_HKEY                hKey                   // in
    );


TSM_RESULT (STDCALL*
Tspi_Context_CloseTransport)( 
    TSM_HCONTEXT            hContext                 // in
    );

//////////////////////////////////////////////////////////////////////////
// 策略类
//////////////////////////////////////////////////////////////////////////

TSM_RESULT (STDCALL*
Tspi_Policy_SetSecret)(
    TSM_HPOLICY             hPolicy,             // in
    TSM_FLAG                secretMode,         // in
    UINT32                  ulSecretLength,     // in
    BYTE*                   rgbSecret         // in
    );

TSM_RESULT (STDCALL*
Tspi_Policy_FlushSecret)( 
    TSM_HPOLICY             hPolicy                     // in 
    );

TSM_RESULT (STDCALL*
Tspi_Policy_AssignToObject)( 
    TSM_HPOLICY             hPolicy,                     // in
    TSM_HOBJECT             hObject                     // in
    );

//////////////////////////////////////////////////////////////////////////
// TCM类
//////////////////////////////////////////////////////////////////////////

TSM_RESULT (STDCALL*
Tspi_TCM_CollateIdentityRequest)(
    TSM_HTCM                hTCM,                    // in
    TSM_HKEY                hKeySMK,                 // in
    TSM_HKEY                hCAPubKey,               // in
    UINT32                  ulIdentityLabelLength,   // in
    BYTE*                   rgbIdentityLabelData,       // in
    TSM_HKEY                hIdentityKey,               // in
    TSM_ALGORITHM_ID        algID,                   // in
    UINT32*                 pulTCMIdentityReqLength, // out
    BYTE**                  prgbTCMIdentityReq       // out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_ActivateIdentity)(
    TSM_HTCM                hTCM,                             // in
    TSM_HKEY                hIdentKey,                         // in
    UINT32                  ulAsymCAContentsBlobLength,         // in
    BYTE*                   rgbAsymCAContentsBlob,             // in
    UINT32                  ulSymCAAttestationBlobLength,     // in
    BYTE*                   rgbSymCAAttestationBlob,         // in
    UINT32*                 pulCredentialLength,             // out
    BYTE**                  prgbCredential                     // out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_CollatePekRequest)(
    TSM_HTCM                hTCM,                     // in
    TSM_HKEY                hCAPubKey,                 // in
    UINT32                  ulPekLabelLength,         // in 
    BYTE*                   rgbPekLabelData,         // in
    TSM_ALGORITHM_ID        algID,                 // in
    UINT32                  ulPekParamsLength,        // in 
    BYTE*                   rgbPekParams,             // in
    UINT32*                 pulTCMPekReqLength,     // out
    BYTE**                  prgbTCMPekReq             // out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_ActivatePEKCert)(
    TSM_HTCM                hTCM,                             // in
    UINT32                  ulAsymCAContentsBlobLength,     // in
    BYTE*                   rgbAsymCAContentsBlob,             // in
    UINT32                  ulSymCAAttestationBlobLength,     // in
    BYTE*                   rgbSymCAAttestationBlob,         // in
    UINT32*                 pulCredentialLength,             // out
    BYTE**                  prgbCredential                     // out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_ActivatePEK)(
    TSM_HTCM                hTCM,                                 // in
    TSM_HKEY                hKeySMK,                             // in
    TSM_HKEY                hPEKKey,                             // in，out
    TSM_HPCRS               hPEKPcr,                            // in
    UINT32                  ulAsymCAContentsBlobLength,         // in
    BYTE*                   rgbAsymCAContentsBlob,                 // in
    UINT32                  ulSymCAAttestationBlobLength,         // in
    BYTE*                   rgbSymCAAttestationBlob             // in
    );

TSM_RESULT (STDCALL*
Tspi_TCM_CreateEndorsementKey)(
    TSM_HTCM                hTCM,           // in
    TSM_HKEY                hKey,           // in
    TSM_VALIDATION*         pValidationData // in, out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_GetPubEndorsementKey)(
    TSM_HTCM                hTCM,             // in
    TSM_BOOL                fOwnerAuthorized, // in
    TSM_VALIDATION*         pValidationData,     // in, out
    TSM_HKEY*               phEndorsementPubKey// out
    );


TSM_RESULT (STDCALL*
Tspi_TCM_CreateRevocableEndorsementKey)(
    TSM_HTCM                hTCM,                  // in
    TSM_HKEY                hKey,                  // in
    TSM_VALIDATION*         pValidationData,      // in, out
    UINT32*                 pulEkResetDataLength, // in, out
    BYTE**                  prgbEkResetData          // in, out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_RevokeEndorsementKey)(
    TSM_HTCM                hTCM,                 // in
    UINT32                  ulEkResetDataLength, // in
    BYTE*                   rgbEkResetData         // in
    );

TSM_RESULT (STDCALL*
Tspi_TCM_TakeOwnership)(
    TSM_HTCM                hTCM,                 // in
    TSM_HKEY                hKeySMK,             // in
    TSM_HKEY                hEndorsementPubKey     // in
    );

TSM_RESULT (STDCALL*
Tspi_TCM_ClearOwner)(
    TSM_HTCM                hTCM,             // in
    TSM_BOOL                fForcedClear     // in
    );

TSM_RESULT (STDCALL*
Tspi_TCM_SetOperatorAuth)(
    TSM_HTCM                hTCM,                 // in
    TSM_HPOLICY             hOperatorPolicy     // in
    );

TSM_RESULT (STDCALL*
Tspi_TCM_SetStatus)(
    TSM_HTCM                hTCM,             // in
    TSM_FLAG                statusFlag,     // in
    TSM_BOOL                fTcmState         // in
    );


TSM_RESULT (STDCALL*
Tspi_TCM_GetStatus)(
    TSM_HTCM                hTCM,             // in
    TSM_FLAG                statusFlag,     // in
    TSM_BOOL* pfTcmState     // out
    );


TSM_RESULT (STDCALL*
Tspi_TCM_GetCapability)(
    TSM_HTCM                hTCM,                 // in
    TSM_FLAG                capArea,             // in
    UINT32                  ulSubCapLength,     // in
    BYTE*                   rgbSubCap,             // in
    UINT32*                 pulRespDataLength,     // out
    BYTE**                  prgbRespData         // out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_SelfTestFull)(
    TSM_HTCM                hTCM     // in
    );


TSM_RESULT (STDCALL*
Tspi_TCM_GetTestResult)(
    TSM_HTCM                hTCM,                     // in
    UINT32*                 pulTestResultLength,     // out
    BYTE**                  prgbTestResult             // out
    );


TSM_RESULT (STDCALL*
Tspi_TCM_GetRandom)( 
    TSM_HTCM                hTCM,                 // in
    UINT32                  ulRandomDataLength,    // in
    BYTE**                  prgbRandomData         // out
    );


TSM_RESULT (STDCALL*
Tspi_TCM_GetEvent)(
    TSM_HTCM                hTCM,                 // in
    UINT32                  ulPcrIndex,         // in
    UINT32                  ulEventNumber,         // in
    TSM_PCR_EVENT*          pPcrEvent             // out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_GetEvents)(
    TSM_HTCM                hTCM,                 // in
    UINT32                  ulPcrIndex,         // in
    UINT32                  ulStartNumber,     // in
    UINT32*                 pulEventNumber,     // in, out
    TSM_PCR_EVENT**         prgPcrEvents       // out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_GetEventLog)(
    TSM_HTCM                hTCM,             // in
    UINT32*                 pulEventNumber, // out
    TSM_PCR_EVENT**         prgPcrEvents    // out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_PcrExtend)( 
    TSM_HTCM                hTCM,                 // in
    UINT32                  ulPcrIndex,             //in
    UINT32                  ulPcrDataLength,         // in
    BYTE*                   pbPcrData,             // in
    TSM_PCR_EVENT*          pPcrEvent,             // in
    UINT32*                 pulPcrValueLength,     // out
    BYTE**                  prgbPcrValue             // out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_PcrRead)(
    TSM_HTCM                hTCM,                // in
    UINT32                  ulPcrIndex,             // in
    UINT32*                 pulPcrValueLength,    // out
    BYTE**                  prgbPcrValue         // out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_PcrReset)(
    TSM_HTCM                hTCM,             // in
    TSM_HPCRS               hPcrComposite     // in
    );

TSM_RESULT (STDCALL*
Tspi_TCM_Quote)(
    TSM_HTCM                hTCM,                 // in
    TSM_HKEY                hIdentKey,            // in
    TSM_BOOL                fAddVersion,          // in
    TSM_HPCRS*              hPcrComposite,        // in
    TSM_VALIDATION*         pValidationData,      // in, out
    UINT32*                 versionInfoSize,      //out
    BYTE**                  versionInfo           // out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_CreateCounter)(
    TSM_HTCM                hTPM,                 // in
    UINT32                  LabelSize,            // in (=4)
    BYTE*                   pLabel,               // in
    TSM_COUNTER_ID*         idCounter,            // out
    TCM_COUNTER_VALUE*      counterValue
    );

TSM_RESULT (STDCALL*
Tspi_TCM_ReadCounter)(
    TSM_HTCM                hTCM,         // in
    UINT32*                 counterValue     // out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_ReadCurrentTicks)( 
    TSM_HTCM                hTCM,                 //in
    TCM_CURRENT_TICKS*      tickCount             // out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_GetAuditDigest)(
    TSM_HTCM                hTCM,             // in
    TSM_HKEY                hKey,             // in
    TSM_BOOL                closeAudit,         // in
    TCM_DIGEST*             pAuditDigest,    // out
    TCM_COUNTER_VALUE*      pCounterValue,   // out
    TSM_VALIDATION*         pValidationData,    // out
    UINT32*                 ordSize,         // out
    UINT32** ordList             // out
    );

TSM_RESULT (STDCALL*
Tspi_TCM_SetOrdinalAuditStatus)(
    TSM_HTCM                hTCM,                 // in
    TCM_COMMAND_CODE        ordinalToAudit,     // in
    TSM_BOOL                auditState             // in
    );

//////////////////////////////////////////////////////////////////////////
// 密钥类
//////////////////////////////////////////////////////////////////////////

TSM_RESULT (STDCALL* 
Tspi_Key_LoadKey)( 
    TSM_HKEY                hKey,          // in
    TSM_HKEY                hUnwrappingKey // in
    );

TSM_RESULT (STDCALL*
Tspi_Key_UnloadKey)( 
    TSM_HKEY                hKey // in
    );

TSM_RESULT (STDCALL*
Tspi_Key_GetPubKey)( 
    TSM_HKEY                hKey,              // in
    UINT32*                 pulPubKeyLength, // out
    BYTE**                  prgbPubKey          // out
    );

TSM_RESULT (STDCALL*
Tspi_Key_CertifyKey)( 
    TSM_HKEY                hKey,           // in
    TSM_HKEY                hCertifyingKey, // in
    TSM_VALIDATION*         pValidationData // in, out
    );

TSM_RESULT (STDCALL*
Tspi_Key_CreateKey)( 
    TSM_HKEY                hKey,          // in
    TSM_HKEY                hWrappingKey,  // in
    TSM_HPCRS               hPcrComposite  // in, 
    );

TSM_RESULT (STDCALL*
Tspi_Key_WrapKey)( 
    TSM_HKEY                hKey,         // in
    TSM_HKEY                hWrappingKey, // in
    TSM_HPCRS               hPcrComposite // in, 
    );

TSM_RESULT (STDCALL*
Tspi_Key_AuthorizeMigrationKey)( 
    TSM_HTCM                hTCM,                    // in 
    TSM_HKEY                hMigrationKey,            // in
    TSM_MIGRATE_SCHEME      migrationScheme,            // in
    UINT32*                 pulMigrationKeyAuthSize, // out
    BYTE**                  ppulMigrationKeyAuth       // out 
    );

TSM_RESULT (STDCALL*
Tspi_Key_CreateMigrationBlob)(
    TSM_HKEY                hKeyToMigrate,                     // in
    TSM_HKEY                hParentKey,                         // in
    UINT32                  ulmigrationKeyAuthSize,             // in
    BYTE*                   rgbmigrationKeyAuth,                 // in
    UINT32*                 pulMigratedDataSize,                 // out
    BYTE**                  prgbMigratedData,                 // out
    UINT32*                 pulEncSymKeySize,                 // out
    BYTE**                  prgbEncSymKey                     // out
    );

TSM_RESULT (STDCALL*
Tspi_Key_ConvertMigrationBlob)(
    TSM_HKEY                hMEK,                    // in
    TSM_HKEY                hParentKey,                 // in
    TSM_HKEY                hKeyToMigrate,             // in 
    UINT32                  ulMigratedDataSize,         // in
    BYTE*                   rgbMigratedData,         // in
    UINT32                  ulEncSymKeySize,         // in
    BYTE*                   rgbEncSymKey             // in
    );

//////////////////////////////////////////////////////////////////////////
// 数据加解密类
//////////////////////////////////////////////////////////////////////////

TSM_RESULT (STDCALL*
Tspi_Data_Seal)(
    TSM_HENCDATA            hEncData,      // in
    TSM_HKEY                hEncKey,      // in
    UINT32                  ulDataLength,// in
    BYTE*                   rgbDataToSeal,// in
    TSM_HPCRS               hPcrComposite // in
    );

TSM_RESULT (STDCALL*
Tspi_Data_Unseal)(
    TSM_HENCDATA            hEncData,             // in
    TSM_HKEY                hKey,                 // in
    UINT32*                 pulUnsealedDataLength, // out
    BYTE**                  prgbUnsealedData          // out
    );

TSM_RESULT (STDCALL*
Tspi_Data_Encrypt)(
    TSM_HENCDATA            hEncData,         // in
    TSM_HKEY                hEncKey,          // in
    TSM_BOOL                bFinal,             // in
    BYTE*                   rgbDataIV,          // in
    BYTE*                   rgbDataToEncrypt, // in
    UINT32                  ulDataLength      // in
    );

TSM_RESULT (STDCALL*
Tspi_Data_Decrypt)(
    TSM_HENCDATA            hEncData,         // in
    TSM_HKEY                hEncKey,         // in
    TSM_BOOL                bFinal,            // in
    BYTE*                   rgbDataIV,         // in
    UINT32*                 ulDataLength,     // out
    BYTE**                  rgbDataDecrypted    //out
    );

TSM_RESULT (STDCALL*
Tspi_Data_Envelop)(
    TSM_HENCDATA            hEncData,          // in
    TSM_HKEY                hEncKey,          // in
    BYTE*                   rgbDataToEncrypt, // in
    UINT32                  ulDataLength      // in
    );

TSM_RESULT (STDCALL*
Tspi_Data_Unenvelop)(
    TSM_HENCDATA            hEncData,         // in
    TSM_HKEY                hEncKey,         // in
    UINT32*                 ulDataLength,     // out
    BYTE**                  rgbDataDecrypted//out
    );

//////////////////////////////////////////////////////////////////////////
// PCR操作类
//////////////////////////////////////////////////////////////////////////

TSM_RESULT (STDCALL*
Tspi_PcrComposite_SetPcrLocality)(
    TSM_HPCRS               hPcrComposite,     //in
    UINT32                  LocalityValue     //in
    );

TSM_RESULT (STDCALL*
Tspi_PcrComposite_GetPcrLocality)(
    TSM_HPCRS               hPcrComposite,     //in
    UINT32*                 pLocalityValue     //out
    );

TSM_RESULT (STDCALL*
Tspi_PcrComposite_GetCompositeHash)( 
    TSM_HPCRS               hPcrComposite,    //in
    UINT32*                 pLen,             //out
    BYTE**                  ppbHashData     //out
    );

TSM_RESULT (STDCALL*
Tspi_PcrComposite_SetPcrValue)( 
    TSM_HPCRS               hPcrComposite,             // in
    UINT32                  ulPcrIndex,             // in
    UINT32                  ulPcrValueLength,         // in
    BYTE*                   rgbPcrValue             // in
    );

TSM_RESULT (STDCALL*
Tspi_PcrComposite_GetPcrValue)( 
    TSM_HPCRS               hPcrComposite,         // in
    UINT32                  ulPcrIndex,         // in
    UINT32*                 pulPcrValueLength,     // out
    BYTE**                  prgbPcrValue         // out
    );

TSM_RESULT (STDCALL*
Tspi_PcrComposite_SelectPcrIndex)( 
    TSM_HPCRS               hPcrComposite,       //in
    UINT32                  ulPcrIndex,             //in
    UINT32                  Direction             //in
    );

//////////////////////////////////////////////////////////////////////////
// 非易失性存储类
//////////////////////////////////////////////////////////////////////////

TSM_RESULT (STDCALL*
Tspi_NV_DefineSpace)(
    TSM_HNVSTORE            hNVStore,            // in
    TSM_HPCRS               hReadPcrComposite,    // in, 可以为NULL
    TSM_HPCRS               hWritePcrComposite    // in, 可以为NULL
    );

TSM_RESULT (STDCALL*
Tspi_NV_ReleaseSpace)(
    TSM_HNVSTORE            hNVStore                // in
    );

TSM_RESULT (STDCALL*
Tspi_NV_WriteValue)(
    TSM_HNVSTORE            hNVStore,             // in
    UINT32                  offset,                // in
    UINT32                  ulDataLength,         // in
    BYTE*                   rgbDataToWrite         // in
    );

TSM_RESULT (STDCALL*
Tspi_NV_ReadValue)(
    TSM_HNVSTORE            hNVStore,        // in
    UINT32                  offset,            // in
    UINT32*                 pulDataLength,    // in, out
    BYTE**                  prgbDataRead    // out
    );

//////////////////////////////////////////////////////////////////////////
// 杂凑类
//////////////////////////////////////////////////////////////////////////

TSM_RESULT (STDCALL*
Tspi_Hash_SetUserMessageData)( 
    TSM_HHASH               hHash,                     // in
    TSM_HKEY                hKey,                     // in
    UINT32                  ulUserIDSize,             // in 
    BYTE*                   rgbUserID,                // in
    UINT32                  ulMessageSize,             // in 
    BYTE*                   rgbMessage                // in
    );

TSM_RESULT (STDCALL*
Tspi_Hash_SetHashValue)(
    TSM_HHASH               hHash,                 // in
    UINT32                  ulHashValueLength,     // in
    BYTE*                   rgbHashValue             // in
    );


TSM_RESULT (STDCALL*
Tspi_Hash_GetHashValue)(
    TSM_HHASH               hHash,             // in
    UINT32*                 pulHashValueLength,// out
    BYTE**                  prgbHashValue         // out
    );

TSM_RESULT (STDCALL*
Tspi_Hash_UpdateHashValue)(
    TSM_HHASH               hHash,          // in
    UINT32                  ulDataLength,// in
    BYTE*                   rgbData      // in
    );
   
TSM_RESULT (STDCALL*
Tspi_Hash_Sign)( 
    TSM_HHASH               hHash,                     // in
    TSM_HKEY                hKey,                     // in
    UINT32*                 pulSignatureLength,        // out
    BYTE**                  prgbSignature             // out
    );

TSM_RESULT (STDCALL*
Tspi_Hash_VerifySignature)(
    TSM_HHASH               hHash,              // in
    TSM_HKEY                hKey,              // in
    UINT32                  ulSignatureLength,// in
    BYTE*                   rgbSignature       // in
    );

TSM_RESULT (STDCALL*
Tspi_Hash_TickStampBlob)(
    TSM_HHASH               hHash,                     // in
    TSM_HKEY                hIdentKey,                 // in
    TSM_VALIDATION*         pValidationData         //in
    );

//////////////////////////////////////////////////////////////////////////
// 密钥协商
//////////////////////////////////////////////////////////////////////////

TSM_RESULT (STDCALL*
Tspi_Exchange_CreateKeyExchange)( 
    TSM_HEXCHANGE           hKeyExchange,         // in
    UINT32*                 pcRxSize,            //out
    BYTE**                  prgbRxPoint            //out
    );

TSM_RESULT (STDCALL*
Tspi_Exchange_GetKeyExchange)(
    TSM_HEXCHANGE           hKeyExchange,         // in
    TSM_HKEY                hPermanentKey,         // in
    TSM_EXCHANGE_TAG        cExchangeTag,        // in
    UINT32                  cPointSize,            // in
    BYTE*                   rgbPoint,            // in
    UINT32                  cRaSize,                // in
    BYTE*                   rgbRa,                // in
    UINT32                  cRbSize,                // in
    BYTE*                   rgbRb,                // in
    UINT32                  cRxSize,                // in
    BYTE*                   rgbRx,                // in
    TSM_HKEY*               phKey,                // in,out
    UINT32*                 pcSxSize,            //out
    BYTE**                  prgbSxData,            // out
    UINT32*                 pcSySize,            // out
    BYTE**                  prgbSyData            // out
    );

TSM_RESULT (STDCALL*
Tspi_Exchange_ReleaseExchangeSession)( 
    TSM_HEXCHANGE           hKeyExchange         // in
    );

//////////////////////////////////////////////////////////////////////////
// 回调函数
//////////////////////////////////////////////////////////////////////////

TSM_RESULT (STDCALL*
Tspicb_CallbackTakeOwnership)(
    PVOID                   lpAppData,     // in
    TSM_HOBJECT             hObject,         // in
    TSM_HKEY                hObjectPubKey,// in
    UINT32                  ulSizeEncAuth, // in
    BYTE*                   rgbEncAuth     // out
    );

TSM_RESULT (STDCALL*
Tspicb_CollateIdentity)(
    PVOID                   lpAppData,                         // in
    UINT32                  ulTCMPlainIdentityProofLength,     // in
    BYTE*                   rgbTCMPlainIdentityProof,         // in
    TSM_ALGORITHM_ID        algID,                             // in
    UINT32                  ulSessionKeyLength,             // out
    BYTE*                   rgbSessionKey,                     // out
    UINT32*                 pulTCMIdentityProofLength,         // out
    BYTE*                   rgbTCMIdentityProof             // out
    );

TSM_RESULT (STDCALL*
Tspicb_ActivateIdentity)(
    PVOID                   lpAppData,                    // in
    UINT32                  ulSessionKeyLength,          // in
    BYTE*                   rgbSessionKey,               // in
    UINT32                  ulSymCAAttestationBlobLength, // in
    BYTE*                   rgbSymCAAttestationBlob,     // in
    UINT32*                 pulCredentialLength,         // out
    BYTE*                   rgbCredential                // out
    );

TSM_RESULT (STDCALL*
Tspicb_CallbackHMACAuth)(
    PVOID                   lpAppData,                         // in
    TSM_HOBJECT             hAuthorizedObject,                 // in
    TSM_BOOL                ReturnOrVerify,                 // in
    UINT32                  ulPendingFunction,             // in
    TSM_BOOL                ContinueUse,                     // in
    UINT32                  ulSizeNonces,                     // in
    BYTE*                   rgbNonceEven,                     // in
    BYTE*                   rgbNonceOdd,                     // in
    BYTE*                   rgbNonceEvenOSAP,                 // in
    BYTE*                   rgbNonceOddOSAP,                 // in
    UINT32                  ulSizeDigestHmac,                 // in
    BYTE*                   rgbParamDigest,                 // in
    BYTE*                   rgbHmacData                     // in, out
    );

}TSP_MODULE;

#pragma pack(pop)

extern TSP_MODULE gTspModule;

#endif
