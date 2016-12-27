#if !defined(_TSPI_H_)
#define _TSPI_H_

#include "tss_defines.h"
#include "tss_typedef.h"
#include "tss_structs.h"
#include "tss_error.h"
#include "tss_error_basics.h"

// Class-independent ASN.1 conversion functions
Tspi_EncodeDER_TssBlob_internal
(
    UINT32              rawBlobSize,                   // in
    BYTE*               rawBlob,                       // in
    UINT32              blobType,                      // in
    UINT32*             derBlobSize,                   // in, out
    BYTE*               derBlob                        // out
);

Tspi_DecodeBER_TssBlob_internal
(
    UINT32              berBlobSize,                   // in
    BYTE*               berBlob,                       // in
    UINT32*             blobType,                      // out
    UINT32*             rawBlobSize,                   // in, out
    BYTE*               rawBlob                        // out
);

// Common Methods
Tspi_SetAttribUint32_internal
(
    TSS_HOBJECT         hObject,                       // in
    TSS_FLAG            attribFlag,                    // in
    TSS_FLAG            subFlag,                       // in
    UINT32              ulAttrib                       // in
);

Tspi_GetAttribUint32_internal
(
    TSS_HOBJECT         hObject,                       // in
    TSS_FLAG            attribFlag,                    // in
    TSS_FLAG            subFlag,                       // in
    UINT32*             pulAttrib                      // out
);

Tspi_SetAttribData_internal
(
    TSS_HOBJECT         hObject,                       // in
    TSS_FLAG            attribFlag,                    // in
    TSS_FLAG            subFlag,                       // in
    UINT32              ulAttribDataSize,              // in
    BYTE*               rgbAttribData                  // in
);

Tspi_GetAttribData_internal
(
    TSS_HOBJECT         hObject,                       // in
    TSS_FLAG            attribFlag,                    // in
    TSS_FLAG            subFlag,                       // in
    UINT32*             pulAttribDataSize,             // out
    BYTE**              prgbAttribData                 // out
);

Tspi_ChangeAuth_internal
(
    TSS_HOBJECT         hObjectToChange,               // in
    TSS_HOBJECT         hParentObject,                 // in
    TSS_HPOLICY         hNewPolicy                     // in
);

Tspi_ChangeAuthAsym_internal
(
    TSS_HOBJECT         hObjectToChange,               // in
    TSS_HOBJECT         hParentObject,                 // in
    TSS_HKEY            hIdentKey,                     // in
    TSS_HPOLICY         hNewPolicy                     // in
);

Tspi_GetPolicyObject_internal
(
    TSS_HOBJECT         hObject,                       // in
    TSS_FLAG            policyType,                    // in
    TSS_HPOLICY*        phPolicy                       // out
);



// Tspi_Context Class Definitions
Tspi_Context_Create_internal
(
    TSS_HCONTEXT*       phContext                      // out
);

Tspi_Context_Close_internal
(
    TSS_HCONTEXT        hContext                       // in
);

Tspi_Context_Connect_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_UNICODE*        wszDestination                 // in
);

Tspi_Context_FreeMemory_internal
(
    TSS_HCONTEXT        hContext,                      // in
    BYTE*               rgbMemory                      // in
);

Tspi_Context_GetDefaultPolicy_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_HPOLICY*        phPolicy                       // out
);

Tspi_Context_CreateObject_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_FLAG            objectType,                    // in
    TSS_FLAG            initFlags,                     // in
    TSS_HOBJECT*        phObject                       // out
);

Tspi_Context_CloseObject_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_HOBJECT         hObject                        // in
);

Tspi_Context_GetCapability_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_FLAG            capArea,                       // in
    UINT32              ulSubCapLength,                // in
    BYTE*               rgbSubCap,                     // in
    UINT32*             pulRespDataLength,             // out
    BYTE**              prgbRespData                   // out
);

Tspi_Context_GetTpmObject_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_HTPM*           phTPM                          // out
);

Tspi_Context_SetTransEncryptionKey_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_HKEY            hKey                           // in
);

Tspi_Context_CloseSignTransport_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_HKEY            hSigningKey,                   // in
    TSS_VALIDATION*     pValidationData                // in, out
);

Tspi_Context_LoadKeyByBlob_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_HKEY            hUnwrappingKey,                // in
    UINT32              ulBlobLength,                  // in
    BYTE*               rgbBlobData,                   // in
    TSS_HKEY*           phKey                          // out
);

Tspi_Context_LoadKeyByUUID_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_FLAG            persistentStorageType,         // in
    TSS_UUID            uuidData,                      // in
    TSS_HKEY*           phKey                          // out
);

Tspi_Context_RegisterKey_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_HKEY            hKey,                          // in
    TSS_FLAG            persistentStorageType,         // in
    TSS_UUID            uuidKey,                       // in
    TSS_FLAG            persistentStorageTypeParent,   // in
    TSS_UUID            uuidParentKey                  // in
);

Tspi_Context_UnregisterKey_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_FLAG            persistentStorageType,         // in
    TSS_UUID            uuidKey,                       // in
    TSS_HKEY*           phkey                          // out
);

Tspi_Context_GetKeyByUUID_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_FLAG            persistentStorageType,         // in
    TSS_UUID            uuidData,                      // in
    TSS_HKEY*           phKey                          // out
);

Tspi_Context_GetKeyByPublicInfo_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_FLAG            persistentStorageType,         // in
    TSS_ALGORITHM_ID    algID,                         // in
    UINT32              ulPublicInfoLength,            // in
    BYTE*               rgbPublicInfo,                 // in
    TSS_HKEY*           phKey                          // out
);

Tspi_Context_GetRegisteredKeysByUUID_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_FLAG            persistentStorageType,         // in
    TSS_UUID*           pUuidData,                     // in
    UINT32*             pulKeyHierarchySize,           // out
    TSS_KM_KEYINFO**    ppKeyHierarchy                 // out
);

Tspi_Context_GetRegisteredKeysByUUID2_internal
(
    TSS_HCONTEXT        hContext,                      // in
    TSS_FLAG            persistentStorageType,         // in
    TSS_UUID*           pUuidData,                     // in
    UINT32*             pulKeyHierarchySize,           // out
    TSS_KM_KEYINFO2**   ppKeyHierarchy                 // out
);


// Policy class definitions
Tspi_Policy_SetSecret_internal
(
    TSS_HPOLICY         hPolicy,                       // in
    TSS_FLAG            secretMode,                    // in
    UINT32              ulSecretLength,                // in
    BYTE*               rgbSecret                      // in
);

Tspi_Policy_FlushSecret_internal
(
    TSS_HPOLICY         hPolicy                        // in
);

Tspi_Policy_AssignToObject_internal
(
    TSS_HPOLICY         hPolicy,                       // in
    TSS_HOBJECT         hObject                        // in
);



// TPM Class Definitions
Tspi_TPM_KeyControlOwner_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hKey,                          // in
    UINT32              attribName,                    // in
    TSS_BOOL            attribValue,                   // in
    TSS_UUID*           pUuidData                      // out
);

Tspi_TPM_CreateEndorsementKey_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hKey,                          // in
    TSS_VALIDATION*     pValidationData                // in, out
);

Tspi_TPM_CreateRevocableEndorsementKey_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hKey,                          // in
    TSS_VALIDATION*     pValidationData,               // in, out
    UINT32*             pulEkResetDataLength,          // in, out
    BYTE**              rgbEkResetData                 // in, out
);

Tspi_TPM_RevokeEndorsementKey_internal
(
    TSS_HTPM            hTPM,                          // in
    UINT32              ulEkResetDataLength,           // in
    BYTE*               rgbEkResetData                 // in
);

Tspi_TPM_GetPubEndorsementKey_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_BOOL            fOwnerAuthorized,              // in
    TSS_VALIDATION*     pValidationData,               // in, out
    TSS_HKEY*           phEndorsementPubKey            // out
);

Tspi_TPM_OwnerGetSRKPubKey_internal
(
    TSS_HTPM            hTPM,                          // in
    UINT32*             pulPubKeyLength,               // out
    BYTE**              prgbPubKey                     // out
);

Tspi_TPM_TakeOwnership_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hKeySRK,                       // in
    TSS_HKEY            hEndorsementPubKey             // in
);

Tspi_TPM_ClearOwner_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_BOOL            fForcedClear                   // in
);

Tspi_TPM_CollateIdentityRequest_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hKeySRK,                       // in
    TSS_HKEY            hCAPubKey,                     // in
    UINT32              ulIdentityLabelLength,         // in
    BYTE*               rgbIdentityLabelData,          // in
    TSS_HKEY            hIdentityKey,                  // in
    TSS_ALGORITHM_ID    algID,                         // in
    UINT32*             pulTCPAIdentityReqLength,      // out
    BYTE**              prgbTCPAIdentityReq            // out
);

Tspi_TPM_ActivateIdentity_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hIdentKey,                     // in
    UINT32              ulAsymCAContentsBlobLength,    // in
    BYTE*               rgbAsymCAContentsBlob,         // in
    UINT32              ulSymCAAttestationBlobLength,  // in
    BYTE*               rgbSymCAAttestationBlob,       // in
    UINT32*             pulCredentialLength,           // out
    BYTE**              prgbCredential                 // out
);

Tspi_TPM_CreateMaintenanceArchive_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_BOOL            fGenerateRndNumber,            // in
    UINT32*             pulRndNumberLength,            // out
    BYTE**              prgbRndNumber,                 // out
    UINT32*             pulArchiveDataLength,          // out
    BYTE**              prgbArchiveData                // out
);

Tspi_TPM_KillMaintenanceFeature_internal
(
    TSS_HTPM            hTPM                           // in
);

Tspi_TPM_LoadMaintenancePubKey_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hMaintenanceKey,               // in
    TSS_VALIDATION*     pValidationData                // in, out
);

Tspi_TPM_CheckMaintenancePubKey_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hMaintenanceKey,               // in
    TSS_VALIDATION*     pValidationData                // in, out
);

Tspi_TPM_SetOperatorAuth_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HPOLICY         hOperatorPolicy                // in
);

Tspi_TPM_SetStatus_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_FLAG            statusFlag,                    // in
    TSS_BOOL            fTpmState                      // in
);

Tspi_TPM_GetStatus_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_FLAG            statusFlag,                    // in
    TSS_BOOL*           pfTpmState                     // out
);

Tspi_TPM_GetCapability_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_FLAG            capArea,                       // in
    UINT32              ulSubCapLength,                // in
    BYTE*               rgbSubCap,                     // in
    UINT32*             pulRespDataLength,             // out
    BYTE**              prgbRespData                   // out
);

Tspi_TPM_GetCapabilitySigned_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hKey,                          // in
    TSS_FLAG            capArea,                       // in
    UINT32              ulSubCapLength,                // in
    BYTE*               rgbSubCap,                     // in
    TSS_VALIDATION*     pValidationData,               // in, out
    UINT32*             pulRespDataLength,             // out
    BYTE**              prgbRespData                   // out
);

Tspi_TPM_SelfTestFull_internal
(
    TSS_HTPM            hTPM                           // in
);

Tspi_TPM_CertifySelfTest_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hKey,                          // in
    TSS_VALIDATION*     pValidationData                // in, out
);

Tspi_TPM_GetTestResult_internal
(
    TSS_HTPM            hTPM,                          // in
    UINT32*             pulTestResultLength,           // out
    BYTE**              prgbTestResult                 // out
);

Tspi_TPM_GetRandom_internal
(
    TSS_HTPM            hTPM,                          // in
    UINT32              ulRandomDataLength,            // in
    BYTE**              prgbRandomData                 // out
);

Tspi_TPM_StirRandom_internal
(
    TSS_HTPM            hTPM,                          // in
    UINT32              ulEntropyDataLength,           // in
    BYTE*               rgbEntropyData                 // in
);

Tspi_TPM_GetEvent_internal
(
    TSS_HTPM            hTPM,                          // in
    UINT32              ulPcrIndex,                    // in
    UINT32              ulEventNumber,                 // in
    TSS_PCR_EVENT*      pPcrEvent                      // out
);

Tspi_TPM_GetEvents_internal
(
    TSS_HTPM            hTPM,                          // in
    UINT32              ulPcrIndex,                    // in
    UINT32              ulStartNumber,                 // in
    UINT32*             pulEventNumber,                // in, out
    TSS_PCR_EVENT**     prgPcrEvents                   // out
);

Tspi_TPM_GetEventLog_internal
(
    TSS_HTPM            hTPM,                          // in
    UINT32*             pulEventNumber,                // out
    TSS_PCR_EVENT**     prgPcrEvents                   // out
);

Tspi_TPM_Quote_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hIdentKey,                     // in
    TSS_HPCRS           hPcrComposite,                 // in
    TSS_VALIDATION*     pValidationData                // in, out
);

Tspi_TPM_Quote2_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hIdentKey,                     // in
    TSS_BOOL            fAddVersion,                   // in
    TSS_HPCRS           hPcrComposite,                 // in
    TSS_VALIDATION*     pValidationData,               // in, out
    UINT32*             versionInfoSize,               // out
    BYTE**              versionInfo                    // out
);

Tspi_TPM_PcrExtend_internal
(
    TSS_HTPM            hTPM,                          // in
    UINT32              ulPcrIndex,                    // in
    UINT32              ulPcrDataLength,               // in
    BYTE*               pbPcrData,                     // in
    TSS_PCR_EVENT*      pPcrEvent,                     // in
    UINT32*             pulPcrValueLength,             // out
    BYTE**              prgbPcrValue                   // out
);

Tspi_TPM_PcrRead_internal
(
    TSS_HTPM            hTPM,                          // in
    UINT32              ulPcrIndex,                    // in
    UINT32*             pulPcrValueLength,             // out
    BYTE**              prgbPcrValue                   // out
);

Tspi_TPM_PcrReset_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HPCRS           hPcrComposite                  // in
);

Tspi_TPM_AuthorizeMigrationTicket_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hMigrationKey,                 // in
    TSS_MIGRATE_SCHEME  migrationScheme,               // in
    UINT32*             pulMigTicketLength,            // out
    BYTE**              prgbMigTicket                  // out
);

Tspi_TPM_CMKSetRestrictions_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_CMK_DELEGATE    CmkDelegate                    // in
);

Tspi_TPM_CMKApproveMA_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HMIGDATA        hMaAuthData                    // in
);

Tspi_TPM_CMKCreateTicket_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hVerifyKey,                    // in
    TSS_HMIGDATA        hSigData                       // in
);

Tspi_TPM_ReadCounter_internal
(
    TSS_HTPM            hTPM,                          // in
    UINT32*             counterValue                   // out
);

Tspi_TPM_ReadCurrentTicks_internal
(
    TSS_HTPM            hTPM,                          // in
    TPM_CURRENT_TICKS*  tickCount                      // out
);

Tspi_TPM_DirWrite_internal
(
    TSS_HTPM            hTPM,                          // in
    UINT32              ulDirIndex,                    // in
    UINT32              ulDirDataLength,               // in
    BYTE*               rgbDirData                     // in
);

Tspi_TPM_DirRead_internal
(
    TSS_HTPM            hTPM,                          // in
    UINT32              ulDirIndex,                    // in
    UINT32*             pulDirDataLength,              // out
    BYTE**              prgbDirData                    // out
);

Tspi_TPM_Delegate_AddFamily_internal
(
    TSS_HTPM            hTPM,                          // in, must not be NULL
    BYTE                bLabel,                        // in
    TSS_HDELFAMILY*     phFamily                       // out
);

Tspi_TPM_Delegate_GetFamily_internal
(
    TSS_HTPM            hTPM,                          // in, must not NULL
    UINT32              ulFamilyID,                    // in
    TSS_HDELFAMILY*     phFamily                       // out
);

Tspi_TPM_Delegate_InvalidateFamily_internal
(
    TSS_HTPM            hTPM,                          // in, must not be NULL
    TSS_HDELFAMILY      hFamily                        // in
);

Tspi_TPM_Delegate_CreateDelegation_internal
(
    TSS_HOBJECT         hObject,                       // in
    BYTE                bLabel,                        // in
    UINT32              ulFlags,                       // in
    TSS_HPCRS           hPcr,                          // in, may be NULL
    TSS_HDELFAMILY      hFamily,                       // in
    TSS_HPOLICY         hDelegation                    // in, out
);

Tspi_TPM_Delegate_CacheOwnerDelegation_internal
(
    TSS_HTPM            hTPM,                          // in, must not be NULL
    TSS_HPOLICY         hDelegation,                   // in, out
    UINT32              ulIndex,                       // in
    UINT32              ulFlags                        // in
);

Tspi_TPM_Delegate_UpdateVerificationCount_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HPOLICY         hDelegation                    // in, out
);

Tspi_TPM_Delegate_VerifyDelegation_internal
(
    TSS_HPOLICY         hDelegation                    // in, out
);

Tspi_TPM_Delegate_ReadTables_internal
(
    TSS_HCONTEXT                  hContext,                      // in
    UINT32*                       pulFamilyTableSize,            // out
    TSS_FAMILY_TABLE_ENTRY**      ppFamilyTable,                 // out
    UINT32*                       pulDelegateTableSize,          // out
    TSS_DELEGATION_TABLE_ENTRY**  ppDelegateTable                // out
);

Tspi_TPM_DAA_JoinInit_internal
(
    TSS_HTPM                      hTPM,                          // in
    TSS_HDAA_ISSUER_KEY           hIssuerKey,                    // in
    UINT32                        daaCounter,                    // in
    UINT32                        issuerAuthPKsLength,           // in
    TSS_HKEY*                     issuerAuthPKs,                 // in
    UINT32                        issuerAuthPKSignaturesLength,  // in
    UINT32                        issuerAuthPKSignaturesLength2, // in
    BYTE**                        issuerAuthPKSignatures,        // in
    UINT32*                       capitalUprimeLength,           // out
    BYTE**                        capitalUprime,                 // out
    TSS_DAA_IDENTITY_PROOF**      identityProof,                 // out
    UINT32*                       joinSessionLength,             // out
    BYTE**                        joinSession                    // out
);

Tspi_TPM_DAA_JoinCreateDaaPubKey_internal
(
    TSS_HTPM                      hTPM,                          // in
    TSS_HDAA_CREDENTIAL           hDAACredential,                // in
    UINT32                        authenticationChallengeLength, // in
    BYTE*                         authenticationChallenge,       // in
    UINT32                        nonceIssuerLength,             // in
    BYTE*                         nonceIssuer,                   // in
    UINT32                        attributesPlatformLength,      // in
    UINT32                        attributesPlatformLength2,     // in
    BYTE**                        attributesPlatform,            // in
    UINT32                        joinSessionLength,             // in
    BYTE*                         joinSession,                   // in
    TSS_DAA_CREDENTIAL_REQUEST**  credentialRequest              // out
);

Tspi_TPM_DAA_JoinStoreCredential_internal
(
    TSS_HTPM                      hTPM,                          // in
    TSS_HDAA_CREDENTIAL           hDAACredential,                // in
    TSS_DAA_CRED_ISSUER*          credIssuer,                    // in
    UINT32                        joinSessionLength,             // in
    BYTE*                         joinSession                    // in
);

Tspi_TPM_DAA_Sign_internal
(
    TSS_HTPM                      hTPM,                          // in
    TSS_HDAA_CREDENTIAL           hDAACredential,                // in
    TSS_HDAA_ARA_KEY              hARAKey,                       // in
    TSS_DAA_SELECTED_ATTRIB*      revealAttributes,              // in
    UINT32                        verifierNonceLength,           // in
    BYTE*                         verifierNonce,                 // in
    UINT32                        verifierBaseNameLength,        // in
    BYTE*                         verifierBaseName,              // in
    TSS_HOBJECT                   signData,                      // in
    TSS_DAA_SIGNATURE**           daaSignature                   // out
);

Tspi_TPM_GetAuditDigest_internal
(
    TSS_HTPM            hTPM,                          // in
    TSS_HKEY            hKey,                          // in
    TSS_BOOL            closeAudit,                    // in
    UINT32*             pulAuditDigestSize,            // out
    BYTE**              prgbAuditDigest,               // out
    TPM_COUNTER_VALUE*  pCounterValue,                 // out
    TSS_VALIDATION*     pValidationData,               // out
    UINT32*             ordSize,                       // out
    UINT32**            ordList                        // out
);



// PcrComposite Class Definitions
Tspi_PcrComposite_SelectPcrIndex_internal
(
    TSS_HPCRS           hPcrComposite,                 // in
    UINT32              ulPcrIndex                     // in
);

Tspi_PcrComposite_SelectPcrIndexEx_internal
(
    TSS_HPCRS           hPcrComposite,                 // in
    UINT32              ulPcrIndex,                    // in
    UINT32              direction                      // in
);

Tspi_PcrComposite_SetPcrValue_internal
(
    TSS_HPCRS           hPcrComposite,                 // in
    UINT32              ulPcrIndex,                    // in
    UINT32              ulPcrValueLength,              // in
    BYTE*               rgbPcrValue                    // in
);

Tspi_PcrComposite_GetPcrValue_internal
(
    TSS_HPCRS           hPcrComposite,                 // in
    UINT32              ulPcrIndex,                    // in
    UINT32*             pulPcrValueLength,             // out
    BYTE**              prgbPcrValue                   // out
);

Tspi_PcrComposite_SetPcrLocality_internal
(
    TSS_HPCRS           hPcrComposite,                 // in
    UINT32              LocalityValue                  // in
);

Tspi_PcrComposite_GetPcrLocality_internal
(
    TSS_HPCRS           hPcrComposite,                 // in
    UINT32*             pLocalityValue                 // out
);

Tspi_PcrComposite_GetCompositeHash_internal
(
    TSS_HPCRS           hPcrComposite,                 // in
    UINT32*             pLen,                          // in
    BYTE**              ppbHashData                    // out
);



// Key Class Definition
Tspi_Key_LoadKey_internal
(
    TSS_HKEY            hKey,                          // in
    TSS_HKEY            hUnwrappingKey                 // in
);

Tspi_Key_UnloadKey_internal
(
    TSS_HKEY            hKey                           // in
);

Tspi_Key_GetPubKey_internal
(
    TSS_HKEY            hKey,                          // in
    UINT32*             pulPubKeyLength,               // out
    BYTE**              prgbPubKey                     // out
);

Tspi_Key_CertifyKey_internal
(
    TSS_HKEY            hKey,                          // in
    TSS_HKEY            hCertifyingKey,                // in
    TSS_VALIDATION*     pValidationData                // in, out
);

Tspi_Key_CreateKey_internal
(
    TSS_HKEY            hKey,                          // in
    TSS_HKEY            hWrappingKey,                  // in
    TSS_HPCRS           hPcrComposite                  // in, may be NULL
);

Tspi_Key_WrapKey_internal
(
    TSS_HKEY            hKey,                          // in
    TSS_HKEY            hWrappingKey,                  // in
    TSS_HPCRS           hPcrComposite                  // in, may be NULL
);

Tspi_Key_CreateMigrationBlob_internal
(
    TSS_HKEY            hKeyToMigrate,                 // in
    TSS_HKEY            hParentKey,                    // in
    UINT32              ulMigTicketLength,             // in
    BYTE*               rgbMigTicket,                  // in
    UINT32*             pulRandomLength,               // out
    BYTE**              prgbRandom,                    // out
    UINT32*             pulMigrationBlobLength,        // out
    BYTE**              prgbMigrationBlob              // out
);

Tspi_Key_ConvertMigrationBlob_internal
(
    TSS_HKEY            hKeyToMigrate,                 // in
    TSS_HKEY            hParentKey,                    // in
    UINT32              ulRandomLength,                // in
    BYTE*               rgbRandom,                     // in
    UINT32              ulMigrationBlobLength,         // in
    BYTE*               rgbMigrationBlob               // in
);

Tspi_Key_MigrateKey_internal
(
    TSS_HKEY            hMaKey,                        // in
    TSS_HKEY            hPublicKey,                    // in
    TSS_HKEY            hMigData                       // in
);

Tspi_Key_CMKCreateBlob_internal
(
    TSS_HKEY            hKeyToMigrate,                 // in
    TSS_HKEY            hParentKey,                    // in
    TSS_HMIGDATA        hMigrationData,                // in
    UINT32*             pulRandomLength,               // out
    BYTE**              prgbRandom                     // out
);

Tspi_Key_CMKConvertMigration_internal
(
    TSS_HKEY            hKeyToMigrate,                 // in
    TSS_HKEY            hParentKey,                    // in
    TSS_HMIGDATA        hMigrationData,                // in
    UINT32              ulRandomLength,                // in
    BYTE*               rgbRandom                      // in
);



// Hash Class Definition
Tspi_Hash_Sign_internal
(
    TSS_HHASH           hHash,                         // in
    TSS_HKEY            hKey,                          // in
    UINT32*             pulSignatureLength,            // out
    BYTE**              prgbSignature                  // out
);

Tspi_Hash_VerifySignature_internal
(
    TSS_HHASH           hHash,                         // in
    TSS_HKEY            hKey,                          // in
    UINT32              ulSignatureLength,             // in
    BYTE*               rgbSignature                   // in
);

Tspi_Hash_SetHashValue_internal
(
    TSS_HHASH           hHash,                         // in
    UINT32              ulHashValueLength,             // in
    BYTE*               rgbHashValue                   // in
);

Tspi_Hash_GetHashValue_internal
(
    TSS_HHASH           hHash,                         // in
    UINT32*             pulHashValueLength,            // out
    BYTE**              prgbHashValue                  // out
);

Tspi_Hash_UpdateHashValue_internal
(
    TSS_HHASH           hHash,                         // in
    UINT32              ulDataLength,                  // in
    BYTE*               rgbData                        // in
);

Tspi_Hash_TickStampBlob_internal
(
    TSS_HHASH           hHash,                         // in
    TSS_HKEY            hIdentKey,                     // in
    TSS_VALIDATION*     pValidationData                // in
);

// EncData Class Definition
Tspi_Data_Bind
(
    TSS_HENCDATA        hEncData,                      // in
    TSS_HKEY            hEncKey,                       // in
    UINT32              ulDataLength,                  // in
    BYTE*               rgbDataToBind,                 // in
	...
);

Tspi_Data_Unbind
(
    TSS_HENCDATA        hEncData,                      // in
    TSS_HKEY            hKey,                          // in
    UINT32*             pulUnboundDataLength,          // out
    BYTE**              prgbUnboundData,               // out
	...
);

Tspi_Data_Seal_internal
(
    TSS_HENCDATA        hEncData,                      // in
    TSS_HKEY            hEncKey,                       // in
    UINT32              ulDataLength,                  // in
    BYTE*               rgbDataToSeal,                 // in
    TSS_HPCRS           hPcrComposite                  // in
);

Tspi_Data_Unseal_internal
(
    TSS_HENCDATA        hEncData,                      // in
    TSS_HKEY            hKey,                          // in
    UINT32*             pulUnsealedDataLength,         // out
    BYTE**              prgbUnsealedData               // out
);



// NV Class Definition
Tspi_NV_DefineSpace_internal
(
    TSS_HNVSTORE        hNVStore,                      // in
    TSS_HPCRS           hReadPcrComposite,             // in, may be NULL
    TSS_HPCRS           hWritePcrComposite             // in, may be NULL
);

Tspi_NV_ReleaseSpace_internal
(
    TSS_HNVSTORE        hNVStore                       // in
);

Tspi_NV_WriteValue_internal
(
    TSS_HNVSTORE        hNVStore,                      // in
    UINT32              offset,                        // in
    UINT32              ulDataLength,                  // in
    BYTE*               rgbDataToWrite                 // in
);

Tspi_NV_ReadValue_internal
(
    TSS_HNVSTORE        hNVStore,                      // in
    UINT32              offset,                        // in
    UINT32*             ulDataLength,                  // in, out
    BYTE**              rgbDataRead                    // out
);


// DAA Utility functions (optional, do not require a TPM or TCS)
Tspi_DAA_IssuerKeyVerify_internal
(
    TSS_HDAA_CREDENTIAL           hDAACredential,                // in
    TSS_HDAA_ISSUER_KEY           hIssuerKey,                    // in
    TSS_BOOL*                     isCorrect                      // out
);

Tspi_DAA_Issuer_GenerateKey_internal
(
    TSS_HDAA_ISSUER_KEY           hIssuerKey,                    // in
    UINT32                        issuerBaseNameLength,          // in
    BYTE*                         issuerBaseName                 // in
);

Tspi_DAA_Issuer_InitCredential_internal
(
    TSS_HDAA_ISSUER_KEY           hIssuerKey,                    // in
    TSS_HKEY                      issuerAuthPK,                  // in
    TSS_DAA_IDENTITY_PROOF*       identityProof,                 // in
    UINT32                        capitalUprimeLength,           // in
    BYTE*                         capitalUprime,                 // in
    UINT32                        daaCounter,                    // in
    UINT32*                       nonceIssuerLength,             // out
    BYTE**                        nonceIssuer,                   // out
    UINT32*                       authenticationChallengeLength, // out
    BYTE**                        authenticationChallenge,       // out
    UINT32*                       joinSessionLength,             // out
    BYTE**                        joinSession                    // out
);

Tspi_DAA_Issuer_IssueCredential_internal
(
    TSS_HDAA_ISSUER_KEY           hIssuerKey,                    // in
    TSS_DAA_CREDENTIAL_REQUEST*   credentialRequest,             // in
    UINT32                        issuerJoinSessionLength,       // in
    BYTE*                         issuerJoinSession,             // in
    TSS_DAA_CRED_ISSUER**         credIssuer                     // out
);

Tspi_DAA_Verifier_Init_internal
(
    TSS_HDAA_CREDENTIAL           hDAACredential,                // in
    UINT32*                       nonceVerifierLength,           // out
    BYTE**                        nonceVerifier,                 // out
    UINT32*                       baseNameLength,                // out
    BYTE**                        baseName                       // out
);

Tspi_DAA_VerifySignature_internal
(
    TSS_HDAA_CREDENTIAL           hDAACredential,                // in
    TSS_HDAA_ISSUER_KEY           hIssuerKey,                    // in
    TSS_HDAA_ARA_KEY              hARAKey,                       // in
    TSS_HHASH                     hARACondition,                 // in
    UINT32                        attributesLength,              // in
    UINT32                        attributesLength2,             // in
    BYTE**                        attributes,                    // in
    UINT32                        verifierNonceLength,           // in
    BYTE*                         verifierNonce,                 // in
    UINT32                        verifierBaseNameLength,        // in
    BYTE*                         verifierBaseName,              // in
    TSS_HOBJECT                   signData,                      // in
    TSS_DAA_SIGNATURE*            daaSignature,                  // in
    TSS_BOOL*                     isCorrect                      // out
);

Tspi_DAA_ARA_GenerateKey_internal
(
    TSS_HDAA_ISSUER_KEY           hIssuerKey,                    // in
    TSS_HDAA_ARA_KEY              hARAKey                        // in
);

Tspi_DAA_ARA_RevokeAnonymity_internal
(
    TSS_HDAA_ARA_KEY              hARAKey,                       // in
    TSS_HHASH                     hARACondition,                 // in
    TSS_HDAA_ISSUER_KEY           hIssuerKey,                    // in
    TSS_DAA_PSEUDONYM_ENCRYPTED*  encryptedPseudonym,            // in
    TSS_DAA_PSEUDONYM_PLAIN**     pseudonym                      // out
);

#if 0

// Callback typedefs
typedef TSS_RESULT (*Tspicb_CallbackHMACAuth)
(
    PVOID            lpAppData,          // in
    TSS_HOBJECT      hAuthorizedObject,  // in
    TSS_BOOL         ReturnOrVerify,     // in
    UINT32           ulPendingFunction,  // in
    TSS_BOOL         ContinueUse,        // in
    UINT32           ulSizeNonces,       // in
    BYTE*            rgbNonceEven,       // in
    BYTE*            rgbNonceOdd,        // in
    BYTE*            rgbNonceEvenOSAP,   // in
    BYTE*            rgbNonceOddOSAP,    // in
    UINT32           ulSizeDigestHmac,   // in
    BYTE*            rgbParamDigest,     // in
    BYTE*            rgbHmacData         // in, out
);

typedef TSS_RESULT (*Tspicb_CallbackXorEnc)
(
   PVOID            lpAppData,            // in
   TSS_HOBJECT      hOSAPObject,          // in
   TSS_HOBJECT      hObject,              // in
   TSS_FLAG         PurposeSecret,        // in
   UINT32           ulSizeNonces,         // in
   BYTE*            rgbNonceEven,         // in
   BYTE*            rgbNonceOdd,          // in
   BYTE*            rgbNonceEvenOSAP,     // in
   BYTE*            rgbNonceOddOSAP,      // in
   UINT32           ulSizeEncAuth,        // in
   BYTE*            rgbEncAuthUsage,      // out
   BYTE*            rgbEncAuthMigration   // out
);

typedef TSS_RESULT (*Tspicb_CallbackTakeOwnership)
(
   PVOID            lpAppData,         // in
   TSS_HOBJECT      hObject,           // in
   TSS_HKEY         hObjectPubKey,     // in
   UINT32           ulSizeEncAuth,     // in
   BYTE*            rgbEncAuth         // out
);

typedef TSS_RESULT (*Tspicb_CallbackSealxMask)
(
    PVOID            lpAppData,        // in
    TSS_HKEY         hKey,             // in
    TSS_HENCDATA     hEncData,         // in
    TSS_ALGORITHM_ID algID,            // in
    UINT32           ulSizeNonces,     // in
    BYTE*            rgbNonceEven,     // in
    BYTE*            rgbNonceOdd,      // in
    BYTE*            rgbNonceEvenOSAP, // in
    BYTE*            rgbNonceOddOSAP,  // in
    UINT32           ulDataLength,     // in
    BYTE*            rgbDataToMask,    // in
    BYTE*            rgbMaskedData     // out
);

typedef TSS_RESULT (*Tspicb_CallbackChangeAuthAsym)
(
   PVOID            lpAppData,        // in
   TSS_HOBJECT      hObject,          // in
   TSS_HKEY         hObjectPubKey,    // in
   UINT32           ulSizeEncAuth,    // in
   UINT32           ulSizeAuthLink,   // in
   BYTE*            rgbEncAuth,       // out
   BYTE*            rgbAuthLink       // out
);

typedef TSS_RESULT (*Tspicb_CollateIdentity)
(
   PVOID            lpAppData,                      // in
   UINT32           ulTCPAPlainIdentityProofLength, // in
   BYTE*            rgbTCPAPlainIdentityProof,      // in
   TSS_ALGORITHM_ID algID,                          // in
   UINT32           ulSessionKeyLength,             // out
   BYTE*            rgbSessionKey,                  // out
   UINT32*          pulTCPAIdentityProofLength,     // out
   BYTE*            rgbTCPAIdentityProof            // out
);


typedef TSS_RESULT (*Tspicb_ActivateIdentity)
(
   PVOID            lpAppData,                    // in
   UINT32           ulSessionKeyLength,           // in
   BYTE*            rgbSessionKey,                // in
   UINT32           ulSymCAAttestationBlobLength, // in
   BYTE*            rgbSymCAAttestationBlob,      // in
   UINT32*          pulCredentialLength,          // out
   BYTE*            rgbCredential                 // out
);


typedef TSS_RESULT (*Tspicb_DAA_Sign)
(
    PVOID                        lpAppData,                 // in
    TSS_HDAA_ISSUER_KEY          daaPublicKey,              // in
    UINT32                       gammasLength,              // in
    BYTE**                       gammas,                    // in
    UINT32                       attributesLength,          // in
    BYTE**                       attributes,                // in
    UINT32                       randomAttributesLength,    // in
    BYTE**                       randomAttributes,          // in
    UINT32                       attributeCommitmentsLength,// in
    TSS_DAA_ATTRIB_COMMIT*       attributeCommitments,      // in
    TSS_DAA_ATTRIB_COMMIT*       attributeCommitmentsProof, // in
    TSS_DAA_PSEUDONYM_PLAIN*     pseudonym,                 // in
    TSS_DAA_PSEUDONYM_PLAIN*     pseudonymTilde,            // in
    TSS_DAA_PSEUDONYM_ENCRYPTED* pseudonymEncrypted,        // in
    TSS_DAA_PSEUDONYM_ENCRYPTED* pseudonymEncProof,         // in
    TSS_DAA_SIGN_CALLBACK**      additionalProof            // out
);

typedef TSS_RESULT (*Tspicb_DAA_VerifySignature)
(
    PVOID                        lpAppData,                 // in
    UINT32                       challengeLength,           // in
    BYTE*                        challenge,                 // in
    TSS_DAA_SIGN_CALLBACK*       additionalProof,           // in
    TSS_HDAA_ISSUER_KEY          daaPublicKey,              // in
    UINT32                       gammasLength,              // in
    BYTE**                       gammas,                    // in
    UINT32                       sAttributesLength,         // in
    BYTE**                       sAttributes,               // in
    UINT32                       attributeCommitmentsLength,// in
    TSS_DAA_ATTRIB_COMMIT*       attributeCommitments,      // in
    TSS_DAA_ATTRIB_COMMIT*       attributeCommitmentsProof, // in
    UINT32                       zetaLength,                // in
    BYTE*                        zeta,                      // in
    UINT32                       sFLength,                  // in
    BYTE*                        sF,                        // in
    TSS_DAA_PSEUDONYM*           pseudonym,                 // in
    TSS_DAA_PSEUDONYM*           pseudonymProof,            // in
    TSS_BOOL*                    isCorrect                  // out
);

#endif

#endif /* _TSPI_H_ */
