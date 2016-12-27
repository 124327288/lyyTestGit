//#include "stdafx.h"
#include "load_tsp.h"

#undef GETPROCADDRESS
#define GETPROCADDRESS(f)                           \
{                                                   \
    void ** p = (void **)&(m->##f);                 \
    *p = GetProcAddress((HMODULE)m->hModule, #f);   \
    if(NULL == *p)                                  \
    {                                               \
        m->free(m);                                 \
        return TCSERR(TSM_E_FAIL);                  \
    }                                               \
}                                                   \


long free_tsp(TSP_MODULE* m)
{
    if((void *)0 == m)
    {
        return TCSERR(TSM_E_BAD_PARAMETER);
    }
    if((void *)0 != m->hModule)
    {
        FreeLibrary((HMODULE)m->hModule);
    }

    // 通用接口
    m->Tspi_SetAttribUint32;
    m->Tspi_GetAttribUint32;
    m->Tspi_SetAttribData;
    m->Tspi_GetAttribData;
    m->Tspi_ChangeAuth;
    m->Tspi_GetPolicyObject;

    // 上下文类
    m->Tspi_Context_Create;
    m->Tspi_Context_Close;
    m->Tspi_Context_Connect;
    m->Tspi_Context_FreeMemory;
    m->Tspi_Context_GetDefaultPolicy;
    m->Tspi_Context_CreateObject;
    m->Tspi_Context_CloseObject;
    m->Tspi_Context_GetCapability;
    m->Tspi_Context_GetTCMObject;
    m->Tspi_Context_LoadKeyByBlob;
    m->Tspi_Context_LoadKeyByUUID;
    m->Tspi_Context_RegisterKey;
    m->Tspi_Context_UnregisterKey;
    m->Tspi_Context_GetKeyByUUID;
    m->Tspi_Context_GetKeyByPublicInfo;
    m->Tspi_Context_GetRegisteredKeysByUUID;
    m->Tspi_Context_SetTransEncryptionKey;
    m->Tspi_Context_CloseTransport;

    // 策略类
    m->Tspi_Policy_SetSecret;
    m->Tspi_Policy_FlushSecret;
    m->Tspi_Policy_AssignToObject;

    // TCM类
    m->Tspi_TCM_CollateIdentityRequest;
    m->Tspi_TCM_ActivateIdentity;
    m->Tspi_TCM_CollatePekRequest;
    m->Tspi_TCM_ActivatePEKCert;
    m->Tspi_TCM_ActivatePEK;
    m->Tspi_TCM_CreateEndorsementKey;
    m->Tspi_TCM_GetPubEndorsementKey;
    m->Tspi_TCM_CreateRevocableEndorsementKey;
    m->Tspi_TCM_RevokeEndorsementKey;
    m->Tspi_TCM_TakeOwnership;
    m->Tspi_TCM_ClearOwner;
    m->Tspi_TCM_SetOperatorAuth;
    m->Tspi_TCM_SetStatus;
    m->Tspi_TCM_GetStatus;
    m->Tspi_TCM_GetCapability;
    m->Tspi_TCM_SelfTestFull;
    m->Tspi_TCM_GetTestResult;
    m->Tspi_TCM_GetRandom;
    m->Tspi_TCM_GetEvent;
    m->Tspi_TCM_GetEvents;
    m->Tspi_TCM_GetEventLog;
    m->Tspi_TCM_PcrExtend;
    m->Tspi_TCM_PcrRead;
    m->Tspi_TCM_PcrReset;
    m->Tspi_TCM_Quote;
    m->Tspi_TCM_CreateCounter;
    m->Tspi_TCM_ReadCounter;
    m->Tspi_TCM_ReadCurrentTicks;
    m->Tspi_TCM_GetAuditDigest;
    m->Tspi_TCM_SetOrdinalAuditStatus;

    // 密钥类
    m->Tspi_Key_LoadKey;
    m->Tspi_Key_UnloadKey;
    m->Tspi_Key_GetPubKey;
    m->Tspi_Key_CertifyKey;
    m->Tspi_Key_CreateKey;
    m->Tspi_Key_WrapKey;
    m->Tspi_Key_AuthorizeMigrationKey;
    m->Tspi_Key_CreateMigrationBlob;
    m->Tspi_Key_ConvertMigrationBlob;

    // 数据加解密类
    m->Tspi_Data_Seal;
    m->Tspi_Data_Unseal;
    m->Tspi_Data_Encrypt;
    m->Tspi_Data_Decrypt;
    m->Tspi_Data_Envelop;
    m->Tspi_Data_Unenvelop;

    // PCR操作类
    m->Tspi_PcrComposite_SetPcrLocality;
    m->Tspi_PcrComposite_GetPcrLocality;
    m->Tspi_PcrComposite_GetCompositeHash;
    m->Tspi_PcrComposite_SetPcrValue;
    m->Tspi_PcrComposite_GetPcrValue;
    m->Tspi_PcrComposite_SelectPcrIndex;

    // 非易失性存储类
    m->Tspi_NV_DefineSpace;
    m->Tspi_NV_ReleaseSpace;
    m->Tspi_NV_WriteValue;
    m->Tspi_NV_ReadValue;

    // 杂凑类
    m->Tspi_Hash_SetUserMessageData;
    m->Tspi_Hash_SetHashValue;
    m->Tspi_Hash_GetHashValue;
    m->Tspi_Hash_UpdateHashValue;
    m->Tspi_Hash_Sign;
    m->Tspi_Hash_VerifySignature;
    m->Tspi_Hash_TickStampBlob;

    // 密钥协商
    m->Tspi_Exchange_CreateKeyExchange;
    m->Tspi_Exchange_GetKeyExchange;
    m->Tspi_Exchange_ReleaseExchangeSession;

    // 回调函数
    m->Tspicb_CallbackTakeOwnership;
    m->Tspicb_CollateIdentity;
    m->Tspicb_ActivateIdentity;
    m->Tspicb_CallbackHMACAuth;

    return TSM_SUCCESS;
}

long load_tsp(TSP_MODULE* m, const char* name)
{
    int len = 0;
    if((NULL == m) || (0 == name))
    {
        return TCSERR(TSM_E_BAD_PARAMETER);
    }
    len = strlen(name);
    if((0 == len) || (255 < len))
    {
        return TCSERR(TSM_E_BAD_PARAMETER);
    }

    m->load = load_tsp;
    m->free = free_tsp;

    memset(m->name, 0, sizeof(m->name));
    memcpy(m->name, name, len);
//#ifdef WIN32

    m->hModule = LoadLibraryA(name);
    if((void *)0 == m->hModule)
    {
        return TCSERR(TSM_E_FAIL);
    }

    // 通用接口
    GETPROCADDRESS(Tspi_SetAttribUint32);
    GETPROCADDRESS(Tspi_GetAttribUint32);
    GETPROCADDRESS(Tspi_SetAttribData);
    GETPROCADDRESS(Tspi_GetAttribData);
    GETPROCADDRESS(Tspi_ChangeAuth);
    GETPROCADDRESS(Tspi_GetPolicyObject);

    // 上下文类
    GETPROCADDRESS(Tspi_Context_Create);
    GETPROCADDRESS(Tspi_Context_Close);
    GETPROCADDRESS(Tspi_Context_Connect);
    GETPROCADDRESS(Tspi_Context_FreeMemory);
    GETPROCADDRESS(Tspi_Context_GetDefaultPolicy);
    GETPROCADDRESS(Tspi_Context_CreateObject);
    GETPROCADDRESS(Tspi_Context_CloseObject);
    GETPROCADDRESS(Tspi_Context_GetCapability);
    GETPROCADDRESS(Tspi_Context_GetTCMObject);
    GETPROCADDRESS(Tspi_Context_LoadKeyByBlob);
    GETPROCADDRESS(Tspi_Context_LoadKeyByUUID);
    GETPROCADDRESS(Tspi_Context_RegisterKey);
    GETPROCADDRESS(Tspi_Context_UnregisterKey);
    GETPROCADDRESS(Tspi_Context_GetKeyByUUID);
    GETPROCADDRESS(Tspi_Context_GetKeyByPublicInfo);
    GETPROCADDRESS(Tspi_Context_GetRegisteredKeysByUUID);
    GETPROCADDRESS(Tspi_Context_SetTransEncryptionKey);
    GETPROCADDRESS(Tspi_Context_CloseTransport);

    // 策略类
    GETPROCADDRESS(Tspi_Policy_SetSecret);
    GETPROCADDRESS(Tspi_Policy_FlushSecret);
    GETPROCADDRESS(Tspi_Policy_AssignToObject);

    // TCM类
    GETPROCADDRESS(Tspi_TCM_CollateIdentityRequest);
    GETPROCADDRESS(Tspi_TCM_ActivateIdentity);
    GETPROCADDRESS(Tspi_TCM_CollatePekRequest);
    GETPROCADDRESS(Tspi_TCM_ActivatePEKCert);
    GETPROCADDRESS(Tspi_TCM_ActivatePEK);
    GETPROCADDRESS(Tspi_TCM_CreateEndorsementKey);
    GETPROCADDRESS(Tspi_TCM_GetPubEndorsementKey);
    GETPROCADDRESS(Tspi_TCM_CreateRevocableEndorsementKey);
    GETPROCADDRESS(Tspi_TCM_RevokeEndorsementKey);
    GETPROCADDRESS(Tspi_TCM_TakeOwnership);
    GETPROCADDRESS(Tspi_TCM_ClearOwner);
    GETPROCADDRESS(Tspi_TCM_SetOperatorAuth);
    GETPROCADDRESS(Tspi_TCM_SetStatus);
    GETPROCADDRESS(Tspi_TCM_GetStatus);
    GETPROCADDRESS(Tspi_TCM_GetCapability);
    GETPROCADDRESS(Tspi_TCM_SelfTestFull);
    GETPROCADDRESS(Tspi_TCM_GetTestResult);
    GETPROCADDRESS(Tspi_TCM_GetRandom);
    GETPROCADDRESS(Tspi_TCM_GetEvent);
    GETPROCADDRESS(Tspi_TCM_GetEvents);
    GETPROCADDRESS(Tspi_TCM_GetEventLog);
    GETPROCADDRESS(Tspi_TCM_PcrExtend);
    GETPROCADDRESS(Tspi_TCM_PcrRead);
    GETPROCADDRESS(Tspi_TCM_PcrReset);
    GETPROCADDRESS(Tspi_TCM_Quote);
    GETPROCADDRESS(Tspi_TCM_CreateCounter);
    GETPROCADDRESS(Tspi_TCM_ReadCounter);
    GETPROCADDRESS(Tspi_TCM_ReadCurrentTicks);
    GETPROCADDRESS(Tspi_TCM_GetAuditDigest);
    GETPROCADDRESS(Tspi_TCM_SetOrdinalAuditStatus);

    // 密钥类
    GETPROCADDRESS(Tspi_Key_LoadKey);
    GETPROCADDRESS(Tspi_Key_UnloadKey);
    GETPROCADDRESS(Tspi_Key_GetPubKey);
    GETPROCADDRESS(Tspi_Key_CertifyKey);
    GETPROCADDRESS(Tspi_Key_CreateKey);
    GETPROCADDRESS(Tspi_Key_WrapKey);
    GETPROCADDRESS(Tspi_Key_AuthorizeMigrationKey);
    GETPROCADDRESS(Tspi_Key_CreateMigrationBlob);
    GETPROCADDRESS(Tspi_Key_ConvertMigrationBlob);

    // 数据加解密类
    GETPROCADDRESS(Tspi_Data_Seal);
    GETPROCADDRESS(Tspi_Data_Unseal);
    GETPROCADDRESS(Tspi_Data_Encrypt);
    GETPROCADDRESS(Tspi_Data_Decrypt);
    GETPROCADDRESS(Tspi_Data_Envelop);
    GETPROCADDRESS(Tspi_Data_Unenvelop);

    // PCR操作类
    GETPROCADDRESS(Tspi_PcrComposite_SetPcrLocality);
    GETPROCADDRESS(Tspi_PcrComposite_GetPcrLocality);
    GETPROCADDRESS(Tspi_PcrComposite_GetCompositeHash);
    GETPROCADDRESS(Tspi_PcrComposite_SetPcrValue);
    GETPROCADDRESS(Tspi_PcrComposite_GetPcrValue);
    GETPROCADDRESS(Tspi_PcrComposite_SelectPcrIndex);

    // 非易失性存储类
    GETPROCADDRESS(Tspi_NV_DefineSpace);
    GETPROCADDRESS(Tspi_NV_ReleaseSpace);
    GETPROCADDRESS(Tspi_NV_WriteValue);
    GETPROCADDRESS(Tspi_NV_ReadValue);

    // 杂凑类
    GETPROCADDRESS(Tspi_Hash_SetUserMessageData);
    GETPROCADDRESS(Tspi_Hash_SetHashValue);
    GETPROCADDRESS(Tspi_Hash_GetHashValue);
    GETPROCADDRESS(Tspi_Hash_UpdateHashValue);
    GETPROCADDRESS(Tspi_Hash_Sign);
    GETPROCADDRESS(Tspi_Hash_VerifySignature);
    GETPROCADDRESS(Tspi_Hash_TickStampBlob);

    // 密钥协商
    GETPROCADDRESS(Tspi_Exchange_CreateKeyExchange);
    GETPROCADDRESS(Tspi_Exchange_GetKeyExchange);
    GETPROCADDRESS(Tspi_Exchange_ReleaseExchangeSession);

    // 回调函数
    GETPROCADDRESS(Tspicb_CallbackTakeOwnership);
    GETPROCADDRESS(Tspicb_CollateIdentity);
    GETPROCADDRESS(Tspicb_ActivateIdentity);
    GETPROCADDRESS(Tspicb_CallbackHMACAuth);

    return TSM_SUCCESS;
}

#undef GETPROCADDRESS

TSP_MODULE gTspModule = {
    (void *)0, load_tsp, free_tsp,
};
