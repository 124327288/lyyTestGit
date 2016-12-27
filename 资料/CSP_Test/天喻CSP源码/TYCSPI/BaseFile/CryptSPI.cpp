#include "stdafx.h"
#include "CryptSPI.h"
#include "KeyContainer.h"
#include "UserFile.h"
#include "Support.h"

//-------------------------------------------------------------------
//	功能：
//		连接Token
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		OUT HCRYPTPROV hProv	返回连接后的容器句柄
//		DWORD dwIndex			TOKEN的索引号(读卡器索引或列表索引)
//
//  说明：
//		如果TOKEN已格式化成了CSP文件系统，则返回VERIFYCONTEXT的容器句柄。
//	否则返回TOKEN的连接句柄。
//		可调用CPIsFormatted来断是否已格式化成了CSP的文件系统。
//-------------------------------------------------------------------
BOOL WINAPI CPConnect(
	OUT HCRYPTPROV *phProv,
	IN DWORD dwIndex
	)
{
	TRACE_FUNCTION("CPConnect");

	BOOL bRetVal = g_theTYCSPManager.Connect(phProv, dwIndex);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		连接卡片
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		CHAR* szReaderName		读卡器的名字
//
//  说明：
//	
//-------------------------------------------------------------------
BOOL WINAPI CPConnect1(
	CHAR* szReaderName
	)
{
	TRACE_FUNCTION("CPConnect");
	
	g_theTYCSPManager.GetCSPCount();
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByReaderName(szReaderName);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->Connect(FALSE);
	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		复位卡片
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		BYTE* pbATR			ATR命令
//		DWORD* pdwATR		ATR的长度
//		ResetMode mode		复位模式
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPResetCard(
	CHAR* szReaderName,
	BYTE* pbATR,
	DWORD* pdwATR,
	ResetMode mode /*=WARM*/
)
{
	TRACE_FUNCTION("CPResetCard");
	
	g_theTYCSPManager.GetCSPCount();
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByReaderName(szReaderName);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->ResetCard(pbATR, pdwATR, mode);
	TRACE_RESULT(bRetVal);

	return bRetVal;
}


//-------------------------------------------------------------------
//	功能：
//		连接Token
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		OUT HCRYPTPROV hProv	返回连接后的容器句柄
//		CHAR* szReaderName		TOKEN的名称
//
//  说明：
//		如果TOKEN已格式化成了CSP文件系统，则返回VERIFYCONTEXT的容器句柄。
//	否则返回TOKEN的连接句柄。
//		可调用CPIsFormatted来断是否已格式化成了CSP的文件系统。
//-------------------------------------------------------------------
BOOL WINAPI CPConnect2(
	OUT HCRYPTPROV *phProv,
	IN CHAR* szReaderName
	)
{
	TRACE_FUNCTION("CPConnect2");

	BOOL bRetVal = g_theTYCSPManager.Connect(phProv, szReaderName);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		判断是否已格式化成了CSP的文件系统
//
//	返回：
//		TRUE：已格式化	FALSE：未格式化
//
//  参数：
//		HCRYPTPROV hProv	容器句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPIsFormatted(
	IN HCRYPTPROV hProv
	)
{
	if(hProv & 0x0000FFFF)
		return TRUE;
	else
		return FALSE;
}

//-------------------------------------------------------------------
//
//	Service Provider Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	功能：
//		打开、新建或删除指定TOKEN中的一个容器
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV* phProv		对于打开或新建返回的容器句柄
//		CHAR* pszContainer		容器名称
//		DWORD dwFlags			支持以下值，意义见MSDN描述
//			0
//			CRYPT_VERIFYCONTEXT
//			CRYPT_NEWKEYSET
//			CRYPT_DELETEKEYSET
//		DWORD dwIndex			TOKEN的索引号(读卡器索引或列表索引)
//
//  说明：
//		缺省为列表索引
//-------------------------------------------------------------------
BOOL WINAPI CPAcquireContext(
	HCRYPTPROV *phProv,
	CHAR *pszContainer,
	DWORD dwFlags,
	DWORD dwIndex
	)
{
	TRACE_FUNCTION("CPAcquireContext");

	BOOL bRetVal = g_theTYCSPManager.AcquireContext(phProv, pszContainer, dwFlags, dwIndex);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		打开、新建或删除指定TOKEN中的一个容器
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV* phProv		对于打开或新建返回的容器句柄
//		CHAR* pszContainer		容器名称
//		DWORD dwFlags			支持以下值，意义见MSDN描述
//			0
//			CRYPT_VERIFYCONTEXT
//			CRYPT_NEWKEYSET
//			CRYPT_DELETEKEYSET
//		CHAR* szReaderName		TOKEN的名称
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPAcquireContext2(
	HCRYPTPROV *phProv,
	CHAR *pszContainer,
	DWORD dwFlags,
	CHAR* szReaderName
	)
{
	TRACE_FUNCTION("CPAcquireContext2");

	BOOL bRetVal = g_theTYCSPManager.AcquireContext(phProv, pszContainer, dwFlags, szReaderName);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		关闭打开的容器
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv	容器句柄
//		DWORD dwFlags		总是为0
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPReleaseContext(
	HCRYPTPROV hProv,
	DWORD dwFlags
	)
{
	TRACE_FUNCTION("CPReleaseContext");

	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->ReleaseContext(hProv, dwFlags);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}


//-------------------------------------------------------------------
//	功能：
//		获取容器参数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv	容器句柄
//		DWORD dwParam		参数类型，支持以下取值,意义见MSDN描述
//			PP_CONTAINER
//			PP_ENUMALGS
//			PP_ENUMALGS_EX
//			PP_ENUMCONTAINERS
//			PP_NAME
//			PP_VERSION
//			PP_IMPTYPE
//			PP_PROVTYPE
//		BYTE* pbData		返回的数据
//		DWORD* pdwDataLen	返回数据的长度
//		DWORD dwFlags		标识，支持以下取值,意义见MSDN描述
//			CRYPT_FIRST
//			CRYPT_NEXT
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetProvParam(
	HCRYPTPROV hProv,  
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD *pdwDataLen, 
	DWORD dwFlags      
	)
{
	TRACE_FUNCTION("CPGetProvParam");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->GetProvParam(hProv, dwParam, pbData, pdwDataLen, dwFlags);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		设置容器参数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv	容器句柄
//		DWORD dwParam		参数类型，支持以下取值,意义见MSDN描述
//		BYTE* pbData		设置的数据
//		DWORD dwFlags		标识，支持以下取值,意义见MSDN描述
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPSetProvParam(
	HCRYPTPROV hProv,  
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD dwFlags      
	)
{
	TRACE_FUNCTION("CPSetProvParam");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->SetProvParam(hProv, dwParam, pbData, dwFlags);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}
 
//-------------------------------------------------------------------
//
//	Key Generation and Exchange Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	功能：
//		产生密钥(对称密钥或非对称密钥)
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		ALG_ID AlgId			密钥标识，支持以下取值,意义见MSDN描述
//			CALG_RC2
//			CALG_RC4
//			CALG_3DES
//			CALG_3DES_112
//			CALG_SSF33
//			CALG_RSA_SIGN,AT_SIGNATURE
//			CALG_RSA_KEYX,AT_KEYEXCHANGE
//		DWORD dwFlags			密钥属性设置，支持以下取值,意义见MSDN描述
//			CRYPT_EXPORTABLE
//			CRYPT_CREATE_SALT
//			CRYPT_NO_SALT
//			CRYPT_USER_PROTECTED
//		HCRYPTKEY* phKey		产生的密钥句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGenKey(
	HCRYPTPROV hProv, 
	ALG_ID Algid,     
	DWORD dwFlags,    
	HCRYPTKEY *phKey  
	)
{
	TRACE_FUNCTION("CPGenKey");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->GenKey(Algid, dwFlags, phKey);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		复制密钥
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			待复制的密钥句柄
//		DWORD* pdwReserved		总为NULL
//		DWORD dwFlags			总为0
//		HCRYPTKEY* phKey		复制的密钥句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPDuplicateKey(
	HCRYPTPROV hProv,    
	HCRYPTKEY hKey,      
	DWORD *pdwReserved,  
	DWORD dwFlags,       
	HCRYPTKEY* phKey     
	)
{
	TRACE_FUNCTION("CPDuplicateKey");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->DuplicateKey(hKey, pdwReserved, dwFlags, phKey);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		派生出对称密钥
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		ALG_ID Algid			算法标识
//		HCRYPTHASH hBaseData	基础数据	
//		DWORD dwFlags			密钥属性设置，支持以下取值,意义见MSDN描述
//			CRYPT_EXPORTABLE
//			CRYPT_CREATE_SALT
//			CRYPT_NO_SALT
//			CRYPT_USER_PROTECTED
//		HCRYPTKEY* phKey		派生出的密钥句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPDeriveKey(
	HCRYPTPROV hProv,      
	ALG_ID Algid,          
	HCRYPTHASH hBaseData,  
	DWORD dwFlags,         
	HCRYPTKEY *phKey       
	)
{
	TRACE_FUNCTION("CPDeriveKey");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->DeriveKey(Algid, hBaseData, dwFlags, phKey);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		销毁对称密钥
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY pKey			密钥句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPDestroyKey(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey     
	)
{
	TRACE_FUNCTION("CPDestroyKey");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->DestroyKey(hKey);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		销毁密钥对
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		DWORD dwKeySpec			密钥对类型
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPDestroyKeyPair(
	HCRYPTPROV hProv,  
	DWORD dwKeySpec     
	)
{
	TRACE_FUNCTION("CPDestroyKeyPair");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->DestroyKeyPair(dwKeySpec);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		获取密钥参数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			密钥句柄
//		DWORD dwParam			参数类型，支持以下取值,意义见MSDN描述
//			KP_ALGID 
//			KP_BLOCKLEN 
//			KP_SALT 
//			KP_PERMISSIONS 
//			KP_IV 
//			KP_PADDING 
//			KP_MODE 
//			KP_MODE_BITS
//			KP_EFFECTIVE_KEYLEN 
//			KP_CERTIFICATE
//		BYTE* pbData			返回的数据
//		DWORD* pdwDataLen		返回数据的长度
//		DWORD dwFlags			总是为0			
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetKeyParam(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey,    
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD *pdwDataLen, 
	DWORD dwFlags      
	)
{
	TRACE_FUNCTION("CPGetKeyParam");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->GetKeyParam(hKey, dwParam, pbData, pdwDataLen, dwFlags);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		设置密钥参数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			密钥句柄
//		DWORD dwParam			参数类型，支持以下取值,意义见MSDN描述
//			KP_ALGID 
//			KP_BLOCKLEN 
//			KP_SALT 
//			KP_PERMISSIONS 
//			KP_IV 
//			KP_PADDING 
//			KP_MODE 
//			KP_MODE_BITS
//			KP_EFFECTIVE_KEYLEN 
//			KP_CERTIFICATE
//		BYTE* pbData			设置的数据
//		DWORD dwFlags			总是为0			
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPSetKeyParam(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey,    
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD dwFlags      
	)
{
	TRACE_FUNCTION("CPSetKeyParam");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->SetKeyParam(hKey, dwParam, pbData, dwFlags);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		导出密钥
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			待导出密钥句柄
//		HCRYPTKEY hExpKey		导出密钥用的加密密钥
//		DWORD dwBlobType		密钥BLOB的类型		
//		DWORD dwFlags			总是为0
//		BYTE* pbData			导出的数据
//		DWORD* pdwDataLen		导出数据的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPExportKey(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey,    
	HCRYPTKEY hExpKey, 
	DWORD dwBlobType,  
	DWORD dwFlags,     
	BYTE *pbData,      
	DWORD *pdwDataLen  
	)
{
	TRACE_FUNCTION("CPExportKey");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->ExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen);
	
	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		导出公钥的DER编码
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKeyPair		密钥对句柄
//		LPBYTE pbDERCode		导出的编码
//		LPDWORD pdwDERCodeLen	导出的编码长度		
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPExportPublicKeyDERCode(
	IN HCRYPTPROV hProv,
	IN HCRYPTKEY hKeyPair,
	OUT LPBYTE lpPubKey,
	IN OUT LPDWORD lpPubKeyLen
	)
{
	TRACE_FUNCTION("CPExportKey");

	return ExportPublicKey(hProv, hKeyPair, lpPubKey, lpPubKeyLen);
}

//-------------------------------------------------------------------
//	功能：
//		导入密钥
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		CONST BYTE *pbData		导入的数据
//		DWORD dwDataLen			导入数据的长度
//		HCRYPTKEY hImpKey		导入时解密用的密钥句柄		
//		DWORD dwFlags			标识，支持以下取值,意义见MSDN描述
//			CRYPT_EXPORTABLE 
//		HCRYPTKEY *phKey		导入产生的密钥句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPImportKey(
	HCRYPTPROV hProv,   
	CONST BYTE *pbData, 
	DWORD dwDataLen,    
	HCRYPTKEY hImpKey,  
	DWORD dwFlags,      
	HCRYPTKEY *phKey    
	)
{
	TRACE_FUNCTION("CPImportKey");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->ImportKey(pbData, dwDataLen, hImpKey, dwFlags, phKey);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		查询密钥对
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		DWORD dwKeySpec			密钥对类型
//		HCRYPTKEY hKeyPair		密钥对句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserKey(
	HCRYPTPROV hProv,     
	DWORD dwKeySpec,      
	HCRYPTKEY *phUserKey  
	)
{
	TRACE_FUNCTION("CPGetUserKey");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->GetUserKey(dwKeySpec, phUserKey);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		产生随机数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		DWORD dwLen				产生随机数的长度
//		BYTE pbBuffer			产生的随机数
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGenRandom(
	HCRYPTPROV hProv,  
	DWORD dwLen,       
	BYTE *pbBuffer     
	)
{
	TRACE_FUNCTION("CPGenRandom");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->GenRandom(dwLen, pbBuffer);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}
 
//-------------------------------------------------------------------
//
//	Data Encryption Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	功能：
//		解密
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			解密密钥的句柄
//		HCRYPTHASH hHash		解密同时计算HASH
//		BOOL Final				最后一块
//		DWORD dwFlags			总是为0
//		BYTE* pbData			[IN]密文/[OUT]明文
//		DWORD* pdwDataLen		[IN]密文长度/[OUT]明文长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPDecrypt(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey,    
	HCRYPTHASH hHash,  
	BOOL Final,        
	DWORD dwFlags,     
	BYTE *pbData,      
	DWORD *pdwDataLen  
	)
{
	TRACE_FUNCTION("CPDecrypt");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->Decrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}
 
//-------------------------------------------------------------------
//	功能：
//		加密
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			加密密钥的句柄
//		HCRYPTHASH hHash		加密同时计算HASH
//		BOOL Final				最后一块
//		DWORD dwFlags			总是为0
//		BYTE* pbData			[IN]明文/[OUT]密文
//		DWORD* pdwDataLen		[IN]明文长度/[OUT]密文长度
//		DWORD dwBufLen			pbData的空间大小
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPEncrypt(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey,    
	HCRYPTHASH hHash,  
	BOOL Final,        
	DWORD dwFlags,     
	BYTE *pbData,      
	DWORD *pdwDataLen, 
	DWORD dwBufLen     
	)
{
	TRACE_FUNCTION("CPEncrypt");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->Encrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		RSA原始解密
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			密钥对句柄
//		LPBYTE pbInData			输入数据
//		DWORD dwInDataLen		输入数据的长度
//		LPBYTE pbOutData		输出数据
//		LPDWORD pdwOutDataLen	输出数据的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPRSARawDecrypt(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey,    
	LPBYTE pbInData,
	DWORD dwInDataLen,
	LPBYTE pbOutData,
	LPDWORD pdwOutDataLen
	)
{
	TRACE_FUNCTION("CPRSARawDecrypt");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->RSARawDecrypt(hKey, pbInData, dwInDataLen, pbOutData, pdwOutDataLen);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		RSA原始加密
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			密钥对句柄
//		LPBYTE pbInData			输入数据
//		DWORD dwInDataLen		输入数据的长度
//		LPBYTE pbOutData		输出数据
//		LPDWORD pdwOutDataLen	输出数据的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPRSARawEncrypt(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey,    
	LPBYTE pbInData,
	DWORD dwInDataLen,
	LPBYTE pbOutData,
	LPDWORD pdwOutDataLen
	)
{
	TRACE_FUNCTION("CPRSARawEncrypt");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->RSARawEncrypt(hKey, pbInData, dwInDataLen, pbOutData, pdwOutDataLen);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}


//-------------------------------------------------------------------
//
//	Hashing and Digital Signature Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	功能：
//		创建HASH
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		ALG_ID AlgId			算法标识，可取以下值
//			CALG_MD5
//			CALG_SHA
//			CALG_SSL3_SHAMD5
//		HCRYPTKEY hKey			MAC中用到的密钥句柄
//		DWORD dwFlags			总是为0
//		HCRYPTHASH* phHash		创建的HASH句柄	
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPCreateHash(
	HCRYPTPROV hProv,  
	ALG_ID Algid,      
	HCRYPTKEY hKey,    
	DWORD dwFlags,     
	HCRYPTHASH *phHash 
	)
{
	TRACE_FUNCTION("CPCreateHash");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->CreateHash(Algid, hKey, dwFlags, phHash);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		复制HASH
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		待复制的HASH句柄
//		DWORD* pdwReserved		总为NULL
//		DWORD dwFlags			总为0
//		HCRYPTHASH* phHash		复制的HASH句柄	
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPDuplicateHash(
	HCRYPTPROV hProv,    
	HCRYPTHASH hHash,    
	DWORD *pdwReserved,  
	DWORD dwFlags,       
	HCRYPTHASH *phHash    
	)
{
	TRACE_FUNCTION("CPDuplicateHash");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->DuplicateHash(hHash, pdwReserved,dwFlags, phHash);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		销毁HASH
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		HASH句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPDestroyHash(
	HCRYPTPROV hProv, 
	HCRYPTHASH hHash  
	)
{
	TRACE_FUNCTION("CPDestroyHash");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->DestroyHash(hHash);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		获取HASH参数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		HASH句柄
//		DWORD dwParam			参数类型，支持以下取值,意义见MSDN描述
//			HP_ALGID 
//			HP_HASHSIZE 
//			HP_HASHVAL
//		BYTE* pbData			返回的数据
//		DWORD* pdwDataLen		返回数据的长度
//		DWORD dwFlags			总是为0			
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetHashParam(
	HCRYPTPROV hProv,  
	HCRYPTHASH hHash,  
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD *pdwDataLen, 
	DWORD dwFlags      
	)
{
	TRACE_FUNCTION("CPGetHashParam");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->GetHashParam(hHash, dwParam, pbData, pdwDataLen, dwFlags);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		设置HASH参数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		HASH句柄
//		DWORD dwParam			参数类型，支持以下取值,意义见MSDN描述
//			HP_HASHVAL 
//		BYTE* pbData			设置的数据
//		DWORD dwFlags			总是为0			
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPSetHashParam(
	HCRYPTPROV hProv,  
	HCRYPTHASH hHash,  
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD dwFlags      
	)
{
	TRACE_FUNCTION("CPSetHashParam");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->SetHashParam(hHash, dwParam, pbData, dwFlags);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		HASH数据
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		HASH句柄
//		CONST BYTE* pbData		数据
//		DWORD dwDataLen			数据长度
//		DWORD dwFlags			总是为0
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPHashData(
	HCRYPTPROV hProv,    
	HCRYPTHASH hHash,    
	CONST BYTE *pbData,  
	DWORD dwDataLen,     
	DWORD dwFlags        
	)
{
	TRACE_FUNCTION("CPHashData");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->HashData(hHash, pbData, dwDataLen, dwFlags);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		HASH密钥
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		HASH句柄
//		HCRYPTKEY hKey			密钥句柄
//		DWORD dwFlags			总是为0
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPHashSessionKey(
	HCRYPTPROV hProv,  
	HCRYPTHASH hHash,  
	HCRYPTKEY hKey,    
	DWORD dwFlags      
	)
{
	TRACE_FUNCTION("CPHashSessionKey");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->HashSessionKey(hHash, hKey, dwFlags);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		签名HASH
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		HASH句柄
//		DWORD dwKeySpec			签名密钥对类型
//		LPCWSTR sDescription	签名描述
//		DWORD dwFlags			总是为0
//		BYTE* pbSignature		签名值
//		DWORD* pdwSigLen		签名值的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPSignHash(
	HCRYPTPROV hProv,      
	HCRYPTHASH hHash,      
	DWORD dwKeySpec,       
	LPCWSTR sDescription,  
	DWORD dwFlags,         
	BYTE *pbSignature,     
	DWORD *pdwSigLen       
	)
{
	TRACE_FUNCTION("CPSignHash");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->SignHash(hHash, dwKeySpec, sDescription, dwFlags, pbSignature, pdwSigLen);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		验证签名
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		HASH句柄
//		CONST BYTE* pbSignature	签名值
//		DWORD dwSigLen			签名值的长度
//		HCRYPTKEY hPubKey		验证公钥的句柄
//		LPCWSTR sDescription	签名描述
//		DWORD dwFlags			总是为0
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPVerifySignature(
	HCRYPTPROV hProv,      
	HCRYPTHASH hHash,      
	CONST BYTE *pbSignature,  
	DWORD dwSigLen,        
	HCRYPTKEY hPubKey,     
	LPCWSTR sDescription,  
	DWORD dwFlags          
	)
{
	TRACE_FUNCTION("CPVerifySignature");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->VerifySignature(hHash, pbSignature, dwSigLen, hPubKey, sDescription, dwFlags);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		可复原签名
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		DWORD dwKeySpec			签名密钥对类型
//		LPBYTE pbData			待签名数据
//		DWORD dwDataLen			待签名数据的长度
//		DWORD dwFlags			总是为0
//		LPBYTE pbSignature		签名值
//		LPDWORD pdwSigLen		签名值的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPSignRecover(
	HCRYPTPROV hProv,
	DWORD dwKeySpec, 
	LPBYTE pbData,
	DWORD dwDataLen,
	DWORD dwFlags,
	LPBYTE pbSignature,     
	LPDWORD pdwSigLen       
	)
{
	TRACE_FUNCTION("CPSignRecover");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->SignRecover(dwKeySpec, pbData, dwDataLen, dwFlags, pbSignature, pdwSigLen);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		验证还原
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		CONST LPBYTE pbSignature签名值
//		DWORD dwSigLen			签名值的长度
//		HCRYPTKEY hPubKey		验证公钥的句柄
//		DWORD dwFlags			总是为0
//		LPBYTE pbData			复原数据
//		LPDWORD pdwDataLen		复原数据的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPVerifyRecover(
	HCRYPTPROV hProv,
	CONST LPBYTE pbSignature,  
	DWORD dwSigLen,        
	HCRYPTKEY hPubKey,
	DWORD dwFlags,
	LPBYTE pbData,
	LPDWORD pdwDataLen
	)
{
	TRACE_FUNCTION("CPVerifyRecover");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CCSPKeyContainer* pKeyContainer = pCSPObject->GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pKeyContainer->VerifyRecover(pbSignature, dwSigLen, hPubKey, dwFlags, pbData, pdwDataLen);
	
	TRACE_RESULT(bRetVal);

	return bRetVal;
}


//-------------------------------------------------------------------
//
//	PIN Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	功能：
//		校验PIN
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		int nUserType			用户类型
//		LPBYTE pPIN				PIN
//		DWORD dwPINLen			PIN的长度
//		DWORD& nRetryCount		错误后，可重试次数。若正确，则无意义。
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPLogin(
	HCRYPTPROV hProv,
	int nUserType,
	LPBYTE pPIN,
	DWORD dwPINLen,
	DWORD& nRetryCount
	)
{
	TRACE_FUNCTION("CPLogin");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->Login(nUserType, pPIN, dwPINLen, nRetryCount);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		注销
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPLogout(
	HCRYPTPROV hProv
	)
{
	TRACE_FUNCTION("CPLogout");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->Logout();

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		更改当前登录用户的PIN
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		LPBYTE pOldPIN			旧PIN
//		DWORD dwOldPINLen		旧PIN的长度
//		LPBYTE pNewPIN			新PIN
//		DWORD dwNewPINLen		新PIN的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPChangePIN(
	HCRYPTPROV hProv,
	LPBYTE pOldPIN,
	DWORD dwOldPINLen,
	LPBYTE pNewPIN,
	DWORD dwNewPINLen
	)
{
	TRACE_FUNCTION("CPChangePIN");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->ChangePIN(pOldPIN, dwOldPINLen, pNewPIN, dwNewPINLen);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		解锁用户PIN
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv				容器句柄
//		LPBYTE pUserDefaultPIN			解锁后的缺省用户PIN
//		DWORD dwUserDefaultPINLen		解锁后的缺省用户PIN长度
//
//  说明：
//		必须已登录为管理员
//-------------------------------------------------------------------
BOOL WINAPI CPUnlockPIN(
	HCRYPTPROV hProv,
	LPBYTE pUserDefaultPIN,
	DWORD dwUserDefaultPINLen
	)
{
	TRACE_FUNCTION("CPUnlockPIN");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->UnlockPIN(pUserDefaultPIN, dwUserDefaultPINLen);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		获取当前登录用户的类型
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		int& nUserType			用户类型
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserType(
	HCRYPTPROV hProv,
	int& nUserType
	)
{
	TRACE_FUNCTION("CPGetUserType");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	nUserType = pCSPObject->GetUserType();

	return TRUE;
}

//-------------------------------------------------------------------
//
//	UserFile Functions
//
//-------------------------------------------------------------------
//-------------------------------------------------------------------
//	功能：
//		打开、新建或删除指定TOKEN中的一个用户文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV* phProv		文件句柄
//		CHAR* szFileName		文件名称
//		DWORD dwFileSize		文件大小(只对新建文件有意义)
//		DWORD dwFlags			标志
//		DWORD dwIndex			TOKEN索引
//
//  说明：
//		dwFlags的LOWORD为操作模式,HIWORD为创建文件时的权限设定
//-------------------------------------------------------------------
BOOL WINAPI CPAcquireUserFile(
	HCRYPTPROV *phProv,
	CHAR* szFileName,
	DWORD dwFileSize,
	DWORD dwFlags,
	DWORD dwIndex
	)
{
	TRACE_FUNCTION("CPAcquireUserFile");

	BOOL bRetVal = g_theTYCSPManager.AcquireUserFile(phProv, szFileName, dwFileSize, dwFlags, dwIndex);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		打开、新建或删除指定TOKEN中的一个用户文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV* phProv		文件句柄
//		CHAR* szFileName		文件名称
//		DWORD dwFileSize		文件大小(只对新建文件有意义)
//		DWORD dwFlags			标志
//		CHAR* szReaderName		TOKEN名称
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPAcquireUserFile2(
	HCRYPTPROV *phProv,
	CHAR* szFileName,
	DWORD dwFileSize,
	DWORD dwFlags,
	CHAR* szReaderName
	)
{
	TRACE_FUNCTION("CPAcquireUserFile2");

	BOOL bRetVal = g_theTYCSPManager.AcquireUserFile(phProv, szFileName, dwFileSize, dwFlags, szReaderName);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		关闭打开的用户文件句柄
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		文件句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPReleaseUserFile(
	HCRYPTPROV hProv
	)
{
	TRACE_FUNCTION("CPReleaseUserFile");

	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->ReleaseUserFile(hProv);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		读取用户文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		文件句柄
//		DWORD dwReadLen			欲读取的长度
//		LPBYTE pbReadBuffer		读取的数据
//		LPDWORD pdwRealReadLen	实际读取的长度
//		DWORD dwOffset			读取偏移量
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPReadUserFile(
	HCRYPTPROV hProv,
	DWORD dwReadLen,
	LPBYTE pbReadBuffer,
	LPDWORD pdwRealReadLen,
	DWORD dwOffset
	)
{
	TRACE_FUNCTION("CPReadUserFile");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CUserFile* pUserFile = pCSPObject->GetUserFileByHandle(hProv);
	if(pUserFile == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pUserFile->Read(dwReadLen, pbReadBuffer, pdwRealReadLen, dwOffset);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		更新用户文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		文件句柄
//		LPBYTE pbWriteBuffer	写入的数据
//		DWORD dwWriteLen		写入数据的长度
//		DWORD dwOffset			读取偏移量
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPWriteUserFile(
	HCRYPTPROV hProv,
	LPBYTE pbWriteBuffer,
	DWORD dwWriteLen,
	DWORD dwOffset
	)
{
	TRACE_FUNCTION("CPWriteUserFile");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CUserFile* pUserFile = pCSPObject->GetUserFileByHandle(hProv);
	if(pUserFile == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pUserFile->Write(pbWriteBuffer, dwWriteLen, dwOffset);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		获取用户文件的大小
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		文件句柄
//		LPDWORD pdwSize			文件大小
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserFileSize(
	HCRYPTPROV hProv,
	LPDWORD pdwSize
	)
{
	TRACE_FUNCTION("CPGetUserFileSize");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CUserFile* pUserFile = pCSPObject->GetUserFileByHandle(hProv);
	if(pUserFile == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pUserFile->GetSize(pdwSize);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		获取用户文件的名称
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		文件句柄
//		CHAR* szFileName		文件名称
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserFileName(
	HCRYPTPROV hProv,
	CHAR* szFileName
	)
{
	TRACE_FUNCTION("CPGetUserFileName");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	CUserFile* pUserFile = pCSPObject->GetUserFileByHandle(hProv);
	if(pUserFile == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	lstrcpy(szFileName, pUserFile->GetName());

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		获取所有用户文件名的列表
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		TOKEN句柄
//		CHAR* szFileNameList	所有用户文件名字的列表,以0分隔,双0结束
//		LPDWORD pcchSize		[IN]接收区大小/[OUT]实际大小				
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserFileNameList(
	HCRYPTPROV hProv,
	CHAR* szFileNameList,
	LPDWORD pcchSize
	)
{
	TRACE_FUNCTION("CPGetUserFileNameList");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->GetUserFileNameList(szFileNameList, pcchSize);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//
//	TokenInfo Functions
//
//-------------------------------------------------------------------
//-------------------------------------------------------------------
//	功能：
//		获取TOKEN信息
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv			容器句柄
//		LPTOKENINFO pTokenInfo		TOKEN信息
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetTokenInfo(
	HCRYPTPROV hProv,
	LPTOKENINFO pTokenInfo
	)
{
	TRACE_FUNCTION("CPGetTokenInfo");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->GetTokenInfo(pTokenInfo);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		重新获取TOKEN信息
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv			容器句柄
//		LPTOKENINFO pTokenInfo		TOKEN信息
//
//  说明：
//		CPGetTokenInfo会缓存已读取的TOKEN信息，读取一次后以后再调用都
//	返回缓存的TOKEN信息。CPReGetTokenInfo则每次均重新读取
//-------------------------------------------------------------------
BOOL WINAPI CPReGetTokenInfo(
	IN HCRYPTPROV hProv,
	OUT LPTOKENINFO pTokenInfo
	)
{
	TRACE_FUNCTION("CPReGetTokenInfo");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->GetTokenInfo(pTokenInfo, TRUE);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		设置TOKEN信息
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv			容器句柄
//		LPTOKENINFO pTokenInfo		TOKEN信息
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPSetTokenInfo(
	HCRYPTPROV hProv,
	LPTOKENINFO pTokenInfo
	)
{
	TRACE_FUNCTION("CPSetTokenInfo");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->SetTokenInfo(pTokenInfo);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//
//	Format Functions
//
//-------------------------------------------------------------------

#ifndef USE_TYCSPI_STATIC_LIB

//-------------------------------------------------------------------
//	功能：
//		选择包含智能卡的读卡器
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		int& nReaderIndex		读卡器索引
//		CHAR* szReaderName		读卡器名称
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPSelectReader(
	OUT int& nReaderIndex,
	OUT CHAR* szReaderName
	)
{
	nReaderIndex = SelectSmartCardReader(szReaderName);
	if(nReaderIndex < 0)
		return FALSE;
	else
		return TRUE;
}

#endif

//-------------------------------------------------------------------
//	功能：
//		格式化TOKEN
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv			容器句柄
//		LPFORMATINFO pFormatInfo	格式化信息
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPFormat(
	HCRYPTPROV hProv,
	LPFORMATINFO pFormatInfo
	)
{
	TRACE_FUNCTION("CPFormat");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->Format(pFormatInfo);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		格式化TOKEN
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		DWORD dwIndex				索引
//		LPFORMATINFO pFormatInfo	格式化信息
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPFormat2(
	DWORD dwIndex,
	LPFORMATINFO pFormatInfo
	)
{
	TRACE_FUNCTION("CPFormat2");
	
	g_theTYCSPManager.GetCSPCount();
	CTYCSP* pCSPObject = NULL;
	if(g_bUseReaderIndex)
		pCSPObject = g_theTYCSPManager.GetCPSByRealIndex(dwIndex);
	else
		pCSPObject = g_theTYCSPManager.GetCSPAt(dwIndex);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->Format(pFormatInfo);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		格式化TOKEN
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		CHAR* szReaderName			读卡器的名字
//		LPFORMATINFO pFormatInfo	格式化信息
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPFormat3(
	CHAR* szReaderName,
	LPFORMATINFO pFormatInfo
	)
{
	TRACE_FUNCTION("CPFormat3");
	
	g_theTYCSPManager.GetCSPCount();
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByReaderName(szReaderName);
	if(pCSPObject == NULL){
		TRACE_LINE("CSP: %s is not found!\n", szReaderName);
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->Format(pFormatInfo);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		断开TOKEN的连接
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv	容器句柄
//		BOOL bWrite
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPFinalize(
	HCRYPTPROV hProv,
	BOOL bWrite
	)
{
	TRACE_FUNCTION("CPFinalize");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->Finalize(bWrite);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		断开TOKEN的连接
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		DWORD dwIndex		索引
//		BOOL bWrite
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPFinalize2(
	DWORD dwIndex,
	BOOL bWrite
	)
{
	TRACE_FUNCTION("CPFinalize2");
	
	g_theTYCSPManager.GetCSPCount();
	CTYCSP* pCSPObject = NULL;
	if(g_bUseReaderIndex)
		pCSPObject = g_theTYCSPManager.GetCPSByRealIndex(dwIndex);
	else
		pCSPObject = g_theTYCSPManager.GetCSPAt(dwIndex);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->Finalize(bWrite);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		断开TOKEN的连接
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		CHAR* szReaderName	读卡器的名字
//		BOOL bWrite
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPFinalize3(
	CHAR* szReaderName,
	BOOL bWrite
	)
{
	TRACE_FUNCTION("CPFinalize3");
	
	g_theTYCSPManager.GetCSPCount();
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByReaderName(szReaderName);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->Finalize(bWrite);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		设置读写器枚举标志位
//
//	返回：
//		无
//
//  参数：
//		DWORD dwFlag		枚举读卡器的种类
//		BOOL bFilter		是否过滤非天喻读卡器(针对PCSC)
//
//  说明：
//-------------------------------------------------------------------
void WINAPI CPSetReaderEnumFlag(
	IN DWORD dwFlag, 
	IN BOOL bFilter
	)
{
	TRACE_FUNCTION("CPSetReaderEnumFlag");

	g_theTYCSPManager.SetEnumReaderFlag(dwFlag);
	g_theTYCSPManager.SetFilterReader(bFilter);
}


//-------------------------------------------------------------------
//	功能：
//		查询CSP(Token)的数目
//
//	返回：
//		数目
//
//  参数：
//
//  说明：
//-------------------------------------------------------------------
DWORD WINAPI CPGetCSPCount()
{
	TRACE_FUNCTION("CPGetCSPCount");

	return g_theTYCSPManager.GetCSPCount();
}

//-------------------------------------------------------------------
//	功能：
//		获取CSP对应读卡器的名字
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		DWORD dwIndex		索引
//		CHAR* szReaderName	读卡器的名定
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetReaderName(
	DWORD dwIndex,
	CHAR* szReaderName
	)
{
	TRACE_FUNCTION("CPGetReaderName");
	
	g_theTYCSPManager.GetCSPCount();
	
	CTYCSP* pCSPObject = NULL;
	if(g_bUseReaderIndex)
		pCSPObject = g_theTYCSPManager.GetCPSByRealIndex(dwIndex);
	else
		pCSPObject = g_theTYCSPManager.GetCSPAt(dwIndex);
	if(pCSPObject == NULL)
		return FALSE;

	lstrcpy(szReaderName, pCSPObject->GetReaderName());

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		设置字节顺序模式
//
//	返回：
//		无
//
//  参数：
//		ByteOrderMode nMode		字节顺序模式
//
//  说明：
//-------------------------------------------------------------------
void WINAPI CPSetByteOrderMode(
	ByteOrderMode nMode
	)
{
	TRACE_FUNCTION("CPSetByteOrderMode");
	g_ByteOrderMode = nMode;
}

//-------------------------------------------------------------------
//	功能：
//		判断是否以读卡器索引作为查询读卡器的索引
//
//	返回：
//		TRUE:是		FALSE:不是
//
//  参数：
//		无
//
//  说明：
//		缺省为用读卡器列表索引
//-------------------------------------------------------------------
BOOL WINAPI CPIsUseReaderIndex()
{
	TRACE_FUNCTION("CPIsUseReaderIndex");
	return g_bUseReaderIndex;
}

//-------------------------------------------------------------------
//	功能：
//		设置是否以读卡器索引作为查询读卡器的索引
//
//	返回：
//		无
//
//  参数：
//		BOOL bFlag	标志
//
//  说明：
//		缺省为用读卡器列表索引
//-------------------------------------------------------------------
void WINAPI CPSetUseReaderIndex(
	BOOL bFlag
	)
{
	TRACE_FUNCTION("CPSetUseReaderIndex");
	g_bUseReaderIndex = bFlag;
}

//-------------------------------------------------------------------
//	功能：
//		获取PIN的重试信息
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		HCRYPTPROV hProv			容器句柄
//		int nUserType				用户类型
//		int nMaxRetry				最大重试次数
//		int nLeftRetry				剩余重试次数
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetPinRetryInfo(
	HCRYPTPROV hProv,
	int nUserType,
	int& nMaxRetry,
	int& nLeftRetry
	)
{
	TRACE_FUNCTION("CPGetPinRetryInfo");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->GetPinRetryInfo(nUserType, nMaxRetry, nLeftRetry);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		查询容量
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		HCRYPTPROV hProv			容器句柄
//		DWORD& dwTotalSize			总空间(含系统占用)
//		DWORD& dwTotalSize2			总空间(不含系统占用)
//		DWORD& dwUnusedSize			可用空间
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetE2Size(
	HCRYPTPROV hProv,
	DWORD& dwTotalSize,
	DWORD& dwTotalSize2,
	DWORD& dwUnusedSize
	)
{
	TRACE_FUNCTION("CPGetE2Size");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->GetE2Size(dwTotalSize, dwTotalSize2, dwUnusedSize);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		查询容量
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		DWORD dwIndex				索引
//		DWORD& dwTotalSize			总空间(含系统占用)
//		DWORD& dwTotalSize2			总空间(不含系统占用)
//		DWORD& dwUnusedSize			可用空间
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetE2Size2(
	DWORD dwIndex,
	DWORD& dwTotalSize,
	DWORD& dwTotalSize2,
	DWORD& dwUnusedSize
	)
{
	TRACE_FUNCTION("CPGetE2Size2");
	
	g_theTYCSPManager.GetCSPCount();
	CTYCSP* pCSPObject = NULL;
	if(g_bUseReaderIndex)
		pCSPObject = g_theTYCSPManager.GetCPSByRealIndex(dwIndex);
	else
		pCSPObject = g_theTYCSPManager.GetCSPAt(dwIndex);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->GetE2Size(dwTotalSize, dwTotalSize2, dwUnusedSize);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		查询容量
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		CHAR* szReaderName			读卡器的名字
//		DWORD& dwTotalSize			总空间(含系统占用)
//		DWORD& dwTotalSize2			总空间(不含系统占用)
//		DWORD& dwUnusedSize			可用空间
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetE2Size3(
	CHAR* szReaderName,
	DWORD& dwTotalSize,
	DWORD& dwTotalSize2,
	DWORD& dwUnusedSize
	)
{
	TRACE_FUNCTION("CPGetE2Size3");
	
	g_theTYCSPManager.GetCSPCount();
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByReaderName(szReaderName);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->GetE2Size(dwTotalSize, dwTotalSize2, dwUnusedSize);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		查询COS版本
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		DWORD& dwCosVersion				COS版本
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetCosVer(
	CHAR* szReaderName,
	DWORD& dwVersion
	)
{
	TRACE_FUNCTION("CPGetCosVer");
	
	g_theTYCSPManager.GetCSPCount();
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByReaderName(szReaderName);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->GetCosVer(dwVersion);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}


//-------------------------------------------------------------------
//	功能：
//		查询有否SSF33算法
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPIsSSF33Support(
	CHAR* szReaderName
	)
{
	TRACE_FUNCTION("CPIsSSF33Support");
	
	g_theTYCSPManager.GetCSPCount();
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByReaderName(szReaderName);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->IsSSF33Support();

	TRACE_RESULT(bRetVal);

	return bRetVal;
}


//-------------------------------------------------------------------
//	功能：
//		擦除EEPROM
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv			容器句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPEraseEE(
	IN HCRYPTPROV hProv
	)
{
	TRACE_FUNCTION("CPEraseEE");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->EraseE2();

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		擦除EEPROM
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		DWORD dwIndex				索引
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPEraseEE2(
	DWORD dwIndex
	)
{
	TRACE_FUNCTION("CPEraseEE2");
	
	g_theTYCSPManager.GetCSPCount();
	CTYCSP* pCSPObject = NULL;
	if(g_bUseReaderIndex)
		pCSPObject = g_theTYCSPManager.GetCPSByRealIndex(dwIndex);
	else
		pCSPObject = g_theTYCSPManager.GetCSPAt(dwIndex);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->EraseE2();

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		擦除EEPROM
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		CHAR* szReaderName			读卡器的名字
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPEraseEE3(
	CHAR* szReaderName
	)
{
	TRACE_FUNCTION("CPEraseEE3");
	
	g_theTYCSPManager.GetCSPCount();
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByReaderName(szReaderName);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->EraseE2();

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		获取ATR信息
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		BYTE* pbATR				返回的ATR
//		DWORD* pdwATR			返回的ATR的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetATR(
	IN HCRYPTPROV hProv,
	OUT BYTE* pbATR,
	OUT DWORD* pdwATR
	)
{
	TRACE_FUNCTION("CPGetATR");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->GetATR(pbATR, pdwATR);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		向卡发送命令
//
//	返回：
//		TRUE:成功(SW1SW2 = 0x9000或0x61XX)	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		BYTE* pbCommand			命令体
//		DWORD dwCommandLen		命令体的长度
//		BYTE* pbRespond			响应体
//		DWORD* pdwRespondLen	响应体的长度
//		WORD* pwStatus			状态字节
//
//  说明：
//		如果不需要响应体或状态字节,只需赋予NULL
//-------------------------------------------------------------------
BOOL WINAPI CPSendCommand(
	HCRYPTPROV hProv,
	BYTE* pbCommand, 
	DWORD dwCommandLen, 
	BYTE* pbRespond, 
	DWORD* pdwRespondLen, 
	WORD* pwStatus
	)
{
	TRACE_FUNCTION("CPSendCommand");
	
	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->SendCommand(pbCommand, dwCommandLen, pbRespond, pdwRespondLen, pwStatus);
	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		向卡发送命令
//
//	返回：
//		TRUE:成功(SW1SW2 = 0x9000或0x61XX)	FALSE:失败
//
//  参数：
//		DWORD dwIndex			索引
//		BYTE* pbCommand			命令体
//		DWORD dwCommandLen		命令体的长度
//		BYTE* pbRespond			响应体
//		DWORD* pdwRespondLen	响应体的长度
//		WORD* pwStatus			状态字节
//
//  说明：
//		如果不需要响应体或状态字节,只需赋予NULL
//-------------------------------------------------------------------
BOOL WINAPI CPSendCommand2(
	DWORD dwIndex,
	BYTE* pbCommand, 
	DWORD dwCommandLen, 
	BYTE* pbRespond, 
	DWORD* pdwRespondLen, 
	WORD* pwStatus
	)
{
	TRACE_FUNCTION("CPSendCommand2");
	
	g_theTYCSPManager.GetCSPCount();
	CTYCSP* pCSPObject = NULL;
	if(g_bUseReaderIndex)
		pCSPObject = g_theTYCSPManager.GetCPSByRealIndex(dwIndex);
	else
		pCSPObject = g_theTYCSPManager.GetCSPAt(dwIndex);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->SendCommand(pbCommand, dwCommandLen, pbRespond, pdwRespondLen, pwStatus);
	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		向卡发送命令
//
//	返回：
//		TRUE:成功(SW1SW2 = 0x9000或0x61XX)	FALSE:失败
//
//  参数：
//		CHAR* szReaderName		读卡器的名字
//		BYTE* pbCommand			命令体
//		DWORD dwCommandLen		命令体的长度
//		BYTE* pbRespond			响应体
//		DWORD* pdwRespondLen	响应体的长度
//		WORD* pwStatus			状态字节
//
//  说明：
//		如果不需要响应体或状态字节,只需赋予NULL
//-------------------------------------------------------------------
BOOL WINAPI CPSendCommand3(
	CHAR* szReaderName,
	BYTE* pbCommand, 
	DWORD dwCommandLen, 
	BYTE* pbRespond, 
	DWORD* pdwRespondLen, 
	WORD* pwStatus
	)
{
	TRACE_FUNCTION("CPSendCommand3");
	
	g_theTYCSPManager.GetCSPCount();
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByReaderName(szReaderName);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	BOOL bRetVal = pCSPObject->SendCommand(pbCommand, dwCommandLen, pbRespond, pdwRespondLen, pwStatus);
	TRACE_RESULT(bRetVal);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		检测智能卡是否存在
//
//	返回：
//		TRUE:存在	FALSE:不存在
//
//  参数：
//		HCRYPTPROV hProv	容器句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPCheckCardIsExist(
	HCRYPTPROV hProv
	)
{
//	TRACE_FUNCTION("CPCheckCardIsExist");

	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL)
		return FALSE;
	return pCSPObject->CheckCardIsExist();
}

//-------------------------------------------------------------------
//	功能：
//		检测智能卡是否存在
//
//	返回：
//		TRUE:存在	FALSE:不存在
//
//  参数：
//		DWORD dwIndex		索引
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPCheckCardIsExist2(
	DWORD dwIndex
	)
{
//	TRACE_FUNCTION("CPCheckCardIsExist2");
	CTYCSP* pCSPObject = NULL;
	if(g_bUseReaderIndex)
		pCSPObject = g_theTYCSPManager.GetCPSByRealIndex(dwIndex);
	else
		pCSPObject = g_theTYCSPManager.GetCSPAt(dwIndex);
	if(pCSPObject == NULL)
		return FALSE;
	return pCSPObject->CheckCardIsExist();
}

//-------------------------------------------------------------------
//	功能：
//		检测智能卡是否存在
//
//	返回：
//		TRUE:存在	FALSE:不存在
//
//  参数：
//		CHAR* szReaderName	读卡器的名定
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPCheckCardIsExist3(
	CHAR* szReaderName
	)
{
//	TRACE_FUNCTION("CPCheckCardIsExist3");

	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByReaderName(szReaderName);
	if(pCSPObject == NULL)
		return FALSE;
	return pCSPObject->CheckCardIsExist();
}

//-------------------------------------------------------------------
//	功能：
//		检测读卡器是否存在
//
//	返回：
//		TRUE:存在	FALSE:不存在
//
//  参数：
//		HCRYPTPROV hProv	容器句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPCheckReaderIsExist(
	HCRYPTPROV hProv
	)
{
	TRACE_FUNCTION("CPCheckReaderIsExist");

	g_theTYCSPManager.GetCSPCount();

	HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
	if(pCSPObject == NULL)
		return FALSE;

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		检测读卡器是否存在
//
//	返回：
//		TRUE:存在	FALSE:不存在
//
//  参数：
//		DWORD dwIndex		索引
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPCheckReaderIsExist2(
	DWORD dwIndex
	)
{
	TRACE_FUNCTION("CPCheckReaderIsExist2");

	g_theTYCSPManager.GetCSPCount();

	CTYCSP* pCSPObject = NULL;
	if(g_bUseReaderIndex)
		pCSPObject = g_theTYCSPManager.GetCPSByRealIndex(dwIndex);
	else
		pCSPObject = g_theTYCSPManager.GetCSPAt(dwIndex);
	if(pCSPObject == NULL)
		return FALSE;
	
	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		检测读卡器是否存在
//
//	返回：
//		TRUE:存在	FALSE:不存在
//
//  参数：
//		CHAR* szReaderName	读卡器的名定
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPCheckReaderIsExist3(
	CHAR* szReaderName
	)
{
	TRACE_FUNCTION("CPCheckReaderIsExist3");

	g_theTYCSPManager.GetCSPCount();

	CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByReaderName(szReaderName);
	if(pCSPObject == NULL)
		return FALSE;

	return TRUE;
}

/////////////////////////////////////////////////////////////////////
//
//	Only for Static Lib

#ifdef USE_TYCSPI_STATIC_LIB
BOOL WINAPI CPStaticLibInitialize()
{
	if(!g_theTYCSPManager.Initialize())
		return FALSE;

	g_rng.init();

	return TRUE;
}

BOOL WINAPI CPStaticLibFinalize()
{
	return g_theTYCSPManager.Finalize();
}
#endif
