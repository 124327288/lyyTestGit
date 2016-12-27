//-------------------------------------------------------------------
//	本文件为 TY Cryptographic Service Provider 的组成部分
//
//
//	版权所有 天喻信息产业有限公司 (c) 1996 - 2001 保留一切权利
//-------------------------------------------------------------------
#include "stdafx.h"
#include "tycsp.h"
#include "CryptSPI.h"
#include "KeyContainer.h"
  
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/////////////////////////////////////////////////////////////////////
//	class CMyMutex

CMyMutex::CMyMutex()
{
	m_hMutex = NULL;
	m_dwMutCount = 0;
}

CMyMutex::~CMyMutex()
{
	Destroy();
}
//创建NULL DACL
BOOL AddNULLDACLToSecurityAttribute(SECURITY_ATTRIBUTES& sa)
{
	PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
	   SECURITY_DESCRIPTOR_MIN_LENGTH);

	if(pSD == NULL)
		return FALSE;

	if(!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
	{
		LocalFree(pSD);
		return FALSE;
	}

	if (!SetSecurityDescriptorDacl(pSD, TRUE, (PACL)NULL, FALSE))
	{
		LocalFree(pSD);
		return FALSE;
	}

	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = pSD;
	sa.bInheritHandle = FALSE;

	return TRUE;
}
 

BOOL CMyMutex::Create()
{
	if(m_hMutex != NULL)
		return TRUE;
	CString szMutexName = _T("TYCSP Mutex");

	SECURITY_ATTRIBUTES sa = {0};
	AddNULLDACLToSecurityAttribute(sa);

	m_hMutex = CreateMutex(&sa, FALSE, szMutexName);
	if((m_hMutex == NULL) && (ERROR_ACCESS_DENIED == GetLastError()))
	{
		TRACE_LINE(_T("Find mutex\n"));
		m_hMutex = OpenMutex(MUTEX_ALL_ACCESS, TRUE, szMutexName);
	}
	TRACE_LINE(_T("Last error:%08x\n"), GetLastError());
	TRACE_LINE(_T("m_hMutex:%08x\n"), m_hMutex);
	return (m_hMutex != NULL);
}

BOOL CMyMutex::Destroy()
{
	TRACE_FUNCTION(_T("Destroy CMyMutex"));
	if(m_hMutex == NULL)
		return TRUE;
	if(CloseHandle(m_hMutex)){
		m_hMutex = NULL;
		return TRUE;
	}
	else
		return FALSE;
}

BOOL CMyMutex::Lock(DWORD dwTimeOut)
{
	DWORD dwCount = m_dwMutCount++;
	TRACE_LINE(_T("Begin lock:%d\n"), dwCount);
	BOOL bRet = (WaitForSingleObject(m_hMutex, dwTimeOut) == WAIT_OBJECT_0);
	TRACE_LINE(_T("Last error:%08x\n"), GetLastError());
	TRACE_LINE(_T("End lock:%d\n"), dwCount);

	return bRet;
}

BOOL CMyMutex::Unlock()
{
	return ReleaseMutex(m_hMutex);
}

/////////////////////////////////////////////////////////////////////
//	class CMyLock

CMyLock::CMyLock(CMyMutex* pMutex)
{
	m_pMutex = pMutex;
}

CMyLock::~CMyLock()
{
	Unlock();
}

BOOL CMyLock::Lock(DWORD dwTimeOut)
{
	if(!m_pMutex)
		return FALSE;

	BOOL bRet = m_pMutex->Lock(dwTimeOut);

	TRACE_LINE(_T("Lock result:%s\n"), bRet?_T("True") : _T("False"));
	return bRet;
}

BOOL CMyLock::Unlock()
{
	if(!m_pMutex)
		return FALSE;

	return m_pMutex->Unlock();
}


#define CRYPTOAPI_SYNCHRONIZE \
	CMyLock apiLock(&g_apiMutex);\
	g_apiMutex.Create();\
	apiLock.Lock();\


//-------------------------------------------------------------------
//
//	Service Provider Functions
//
//-------------------------------------------------------------------

BOOL WINAPI CPAcquireContext(
	HCRYPTPROV *phProv,
	CHAR *pszContainer,
	DWORD dwFlags,
	PVTableProvStruc pVTable
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	
	TRACE_FUNCTION("CPAcquireContext");

	BOOL bRetVal = g_theTYCSPManager.AcquireContext(phProv, pszContainer, dwFlags, pVTable);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}

BOOL WINAPI CPReleaseContext(
	HCRYPTPROV hProv,
	DWORD dwFlags
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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


BOOL WINAPI CPGetProvParam(
	HCRYPTPROV hProv,  
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD *pdwDataLen, 
	DWORD dwFlags      
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPSetProvParam(
	HCRYPTPROV hProv,  
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD dwFlags      
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPGenKey(
	HCRYPTPROV hProv, 
	ALG_ID Algid,     
	DWORD dwFlags,    
	HCRYPTKEY *phKey  
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPDuplicateKey(
	HCRYPTPROV hProv,    
	HCRYPTKEY hKey,      
	DWORD *pdwReserved,  
	DWORD dwFlags,       
	HCRYPTKEY* phKey     
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPDeriveKey(
	HCRYPTPROV hProv,      
	ALG_ID Algid,          
	HCRYPTHASH hBaseData,  
	DWORD dwFlags,         
	HCRYPTKEY *phKey       
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPDestroyKey(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey     
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPGetKeyParam(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey,    
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD *pdwDataLen, 
	DWORD dwFlags      
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPSetKeyParam(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey,    
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD dwFlags      
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());
 
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

BOOL WINAPI CPImportKey(
	HCRYPTPROV hProv,   
	CONST BYTE *pbData, 
	DWORD dwDataLen,    
	HCRYPTKEY hImpKey,  
	DWORD dwFlags,      
	HCRYPTKEY *phKey    
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPGetUserKey(
	HCRYPTPROV hProv,     
	DWORD dwKeySpec,      
	HCRYPTKEY *phUserKey  
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPGenRandom(
	HCRYPTPROV hProv,  
	DWORD dwLen,       
	BYTE *pbBuffer     
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	TRACE_FUNCTION("CPGenRandom");
	
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

	BOOL bRetVal = pKeyContainer->GenRandom(dwLen, pbBuffer);

	TRACE_RESULT(bRetVal);

	return bRetVal;
}
 
//-------------------------------------------------------------------
//
//	Data Encryption Functions
//
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
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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
//
//	Hashing and Digital Signature Functions
//
//-------------------------------------------------------------------

BOOL WINAPI CPCreateHash(
	HCRYPTPROV hProv,  
	ALG_ID Algid,      
	HCRYPTKEY hKey,    
	DWORD dwFlags,     
	HCRYPTHASH *phHash 
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPDuplicateHash(
	HCRYPTPROV hProv,    
	HCRYPTHASH hHash,    
	DWORD *pdwReserved,  
	DWORD dwFlags,       
	HCRYPTHASH *phHash    
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPDestroyHash(
	HCRYPTPROV hProv, 
	HCRYPTHASH hHash  
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPGetHashParam(
	HCRYPTPROV hProv,  
	HCRYPTHASH hHash,  
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD *pdwDataLen, 
	DWORD dwFlags      
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPSetHashParam(
	HCRYPTPROV hProv,  
	HCRYPTHASH hHash,  
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD dwFlags      
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPHashData(
	HCRYPTPROV hProv,    
	HCRYPTHASH hHash,    
	CONST BYTE *pbData,  
	DWORD dwDataLen,     
	DWORD dwFlags        
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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

BOOL WINAPI CPHashSessionKey(
	HCRYPTPROV hProv,  
	HCRYPTHASH hHash,  
	HCRYPTKEY hKey,    
	DWORD dwFlags      
	)
{
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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
	CRYPTOAPI_SYNCHRONIZE

	AFX_MANAGE_STATE(AfxGetStaticModuleState());

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
