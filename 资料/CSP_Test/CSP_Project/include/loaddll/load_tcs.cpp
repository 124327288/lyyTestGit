#include "stdafx.h"
#include "load_tcs.h"

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

long free_tcs_dll(TCS_DLL_MODULE* m)
{
    if((void *)0 == m)
    {
        return TCSERR(TSM_E_BAD_PARAMETER);
    }
    if((void *)0 != m->hModule)
    {
        FreeLibrary((HMODULE)m->hModule);
    }

    return TSM_SUCCESS;
}

long load_tcs_dll(TCS_DLL_MODULE* m, const char* name)
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

    m->load = load_tcs_dll;
    m->free = free_tcs_dll;

    memset(m->name, 0, sizeof(m->name));
    memcpy(m->name, name, len);

    m->hModule = LoadLibraryA(name);
    if((void *)0 == m->hModule)
    {
        return TCSERR(TSM_E_FAIL);
    }
	
    GETPROCADDRESS(DebugCallback);

    GETPROCADDRESS(Tcs_OpenContext);

    GETPROCADDRESS(Tcs_CloseContext);

    GETPROCADDRESS(Tcs_FreeMemory);

    GETPROCADDRESS(Tcs_GetCapability);

    // TCS Key and Credential Manager

    GETPROCADDRESS(Tcs_RegisterKey);

    GETPROCADDRESS(Tcs_UnregisterKey);

    GETPROCADDRESS(Tcs_EnumRegisteredKeys);

    GETPROCADDRESS(Tcs_GetRegisteredKey);

    GETPROCADDRESS(Tcs_GetRegisteredKeyBlob);

    GETPROCADDRESS(Tcs_GetRegisteredKeyByPublicInfo);

    GETPROCADDRESS(Tcs_CollatePekRequest);

    //事件管理
    GETPROCADDRESS(Tcs_LogPcrEvent);

    GETPROCADDRESS(Tcs_GetPcrEvent);

    GETPROCADDRESS(Tcs_GetPcrEventsByPcr);

    GETPROCADDRESS(Tcs_GetPcrEventLog);

    // 可信密码模块管理
    // TCM测试
    GETPROCADDRESS(Tcsip_SelfTestFull);

    GETPROCADDRESS(Tcsip_ContinueSelfTest);

    GETPROCADDRESS(Tcsip_GetTestResult);

    // 工作模式设置
    GETPROCADDRESS(Tcsip_SetOwnerInstall);

    GETPROCADDRESS(Tcsip_OwnerSetDisable);

    GETPROCADDRESS(Tcsip_PhysicalEnable);

    GETPROCADDRESS(Tcsip_PhysicalDisable);

    GETPROCADDRESS(Tcsip_SetTempDeactived);

    GETPROCADDRESS(Tcsip_PhysicalSetDeactivated);

    GETPROCADDRESS(Tcsip_SetOperatorAuth);

    GETPROCADDRESS(Tcsip_PhysicalPresence);

    //所有者管理
    GETPROCADDRESS(Tcsip_TakeOwnership);

    GETPROCADDRESS(Tcsip_OwnerClear);

    GETPROCADDRESS(Tcsip_DisableOwnerClear);

    GETPROCADDRESS(Tcsip_ForceClear);

    GETPROCADDRESS(Tcsip_DisableForceClear);

    //属性管理
    GETPROCADDRESS(Tcsip_GetCapability);

    GETPROCADDRESS(Tcsip_SetCapability);


    //升级维护
    GETPROCADDRESS(Tcsip_FieldUpgrade);

    GETPROCADDRESS(Tcsip_ResetLockValue);

    //授权值管理
    GETPROCADDRESS(Tcsip_ChangeAuth);

    GETPROCADDRESS(Tcsip_ChangeAuthOwner);

    //非易失性存储管理
    GETPROCADDRESS(Tcsip_NV_DefineOrReleaseSpace);

    GETPROCADDRESS(Tcsip_NV_WriteValue);

    GETPROCADDRESS(Tcsip_NV_WriteValueAuth);

    GETPROCADDRESS(Tcsip_NV_ReadValue);

    GETPROCADDRESS(Tcsip_NV_ReadValueAuth);

    //审计
    GETPROCADDRESS(Tcsip_GetAuditDigest);

    GETPROCADDRESS(Tcsip_GetAuditDigestSigned);

    GETPROCADDRESS(Tcsip_SetOrdinalAuditStatus);

    //时钟
    GETPROCADDRESS(Tcsip_ReadCurrentTicks);

    GETPROCADDRESS(Tcsip_TickStampBlob);

    //计数器
    GETPROCADDRESS(Tcsip_CreateCounter);

    GETPROCADDRESS(Tcsip_IncrementCounter);

    GETPROCADDRESS(Tcsip_ReadCounter);

    GETPROCADDRESS(Tcsip_ReleaseCounter);

    GETPROCADDRESS(Tcsip_ReleaseCounterOwner);

    // 平台身份标识与认证
    //创建密码模块密钥
    GETPROCADDRESS(Tcsip_CreateEndorsementKeyPair);

    GETPROCADDRESS(Tcsip_CreateRevocableEndorsementKeyPair);

    GETPROCADDRESS(Tcsip_RevokeEndorsementKeyPair);

    GETPROCADDRESS(Tcsip_ReadPubEK);

    GETPROCADDRESS(Tcsip_OwnerReadInternalPub);

    //平台身份密钥管理
    GETPROCADDRESS(Tcsip_MakeIdentity);

    GETPROCADDRESS(Tcsip_ActivateIdentity);

    GETPROCADDRESS(Tcsip_ActivatePEKCert);

    GETPROCADDRESS(Tcsip_ActivatePEK);

    // 平台数据保护
    // 数据保护操作
    GETPROCADDRESS(Tcsip_Seal);

    GETPROCADDRESS(Tcsip_Unseal);

    //密钥管理
    GETPROCADDRESS(Tcsip_CreateWrapKey);

    GETPROCADDRESS(Tcsip_LoadKeyByBlob);

    GETPROCADDRESS(Tcsip_LoadKeyByUUID);

    GETPROCADDRESS(Tcsip_GetPubKey);

    GETPROCADDRESS(Tcsip_WrapKey);

    GETPROCADDRESS(Tcsip_CertifyKey);

    GETPROCADDRESS(Tcsip_FlushSpecific);

    //密钥协商
    GETPROCADDRESS(Tcsip_CreateKeyExchange);

    GETPROCADDRESS(Tcsip_GetKeyExchange);

    GETPROCADDRESS(Tcsip_ReleaseExchangeSession);

    //密钥迁移
    GETPROCADDRESS(Tcsip_AuthorizeMigrationKey);

    GETPROCADDRESS(Tcsip_CreateMigrationBlob);

    GETPROCADDRESS(Tcsip_ConvertMigrationBlob);

    //密码学服务

    GETPROCADDRESS(Tcsip_Sign);

    GETPROCADDRESS(Tcsip_SMS4Encrypt);

    GETPROCADDRESS(Tcsip_SMS4Decrypt);

    GETPROCADDRESS(Tcsip_SM2Decrypt);

    GETPROCADDRESS(Tcsip_GetRandom);

	GETPROCADDRESS(Tcsip_SM3Start);
	
    GETPROCADDRESS(Tcsip_SM3Update);
	
    GETPROCADDRESS(Tcsip_SM3Complete);
	
    GETPROCADDRESS(Tcsip_SM3CompleteExtend);

    //传输会话
    GETPROCADDRESS(Tcsip_EstablishTransport);

    GETPROCADDRESS(Tcsip_ExecuteTransport);

    GETPROCADDRESS(Tcsip_ReleaseTransport);

    //授权协议

    GETPROCADDRESS(Tcsip_APCreate);

    GETPROCADDRESS(Tcsip_APTerminate);

    // 完整性度量与报告
    // 平台配置寄存器管理
    GETPROCADDRESS(Tcsip_Extend);

    GETPROCADDRESS(Tcsip_PcrRead);

    GETPROCADDRESS(Tcsip_Quote);

    GETPROCADDRESS(Tcsip_PcrReset);

	//保存，加载TCM环境
	GETPROCADDRESS(Tcs_sava_Context);

	GETPROCADDRESS(Tcs_load_Context);
	
	GETPROCADDRESS(getTCMHandle);

    return TSM_SUCCESS;
}

TCS_DLL_MODULE gTcsModule = {
    (void *)0, load_tcs_dll, free_tcs_dll
};
