#include "stdafx.h"
#include "CryptSPI.h"
#include "KeyContainer.h"
#include "UserFile.h"
#include "Support.h"

//-------------------------------------------------------------------
//	���ܣ�
//		����Token
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		OUT HCRYPTPROV hProv	�������Ӻ���������
//		DWORD dwIndex			TOKEN��������(�������������б�����)
//
//  ˵����
//		���TOKEN�Ѹ�ʽ������CSP�ļ�ϵͳ���򷵻�VERIFYCONTEXT�����������
//	���򷵻�TOKEN�����Ӿ����
//		�ɵ���CPIsFormatted�����Ƿ��Ѹ�ʽ������CSP���ļ�ϵͳ��
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
//	���ܣ�
//		���ӿ�Ƭ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		CHAR* szReaderName		������������
//
//  ˵����
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
//	���ܣ�
//		��λ��Ƭ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		BYTE* pbATR			ATR����
//		DWORD* pdwATR		ATR�ĳ���
//		ResetMode mode		��λģʽ
//
//  ˵����
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
//	���ܣ�
//		����Token
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		OUT HCRYPTPROV hProv	�������Ӻ���������
//		CHAR* szReaderName		TOKEN������
//
//  ˵����
//		���TOKEN�Ѹ�ʽ������CSP�ļ�ϵͳ���򷵻�VERIFYCONTEXT�����������
//	���򷵻�TOKEN�����Ӿ����
//		�ɵ���CPIsFormatted�����Ƿ��Ѹ�ʽ������CSP���ļ�ϵͳ��
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
//	���ܣ�
//		�ж��Ƿ��Ѹ�ʽ������CSP���ļ�ϵͳ
//
//	���أ�
//		TRUE���Ѹ�ʽ��	FALSE��δ��ʽ��
//
//  ������
//		HCRYPTPROV hProv	�������
//
//  ˵����
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
//	���ܣ�
//		�򿪡��½���ɾ��ָ��TOKEN�е�һ������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV* phProv		���ڴ򿪻��½����ص��������
//		CHAR* pszContainer		��������
//		DWORD dwFlags			֧������ֵ�������MSDN����
//			0
//			CRYPT_VERIFYCONTEXT
//			CRYPT_NEWKEYSET
//			CRYPT_DELETEKEYSET
//		DWORD dwIndex			TOKEN��������(�������������б�����)
//
//  ˵����
//		ȱʡΪ�б�����
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
//	���ܣ�
//		�򿪡��½���ɾ��ָ��TOKEN�е�һ������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV* phProv		���ڴ򿪻��½����ص��������
//		CHAR* pszContainer		��������
//		DWORD dwFlags			֧������ֵ�������MSDN����
//			0
//			CRYPT_VERIFYCONTEXT
//			CRYPT_NEWKEYSET
//			CRYPT_DELETEKEYSET
//		CHAR* szReaderName		TOKEN������
//
//  ˵����
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
//	���ܣ�
//		�رմ򿪵�����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv	�������
//		DWORD dwFlags		����Ϊ0
//
//  ˵����
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
//	���ܣ�
//		��ȡ��������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv	�������
//		DWORD dwParam		�������ͣ�֧������ȡֵ,�����MSDN����
//			PP_CONTAINER
//			PP_ENUMALGS
//			PP_ENUMALGS_EX
//			PP_ENUMCONTAINERS
//			PP_NAME
//			PP_VERSION
//			PP_IMPTYPE
//			PP_PROVTYPE
//		BYTE* pbData		���ص�����
//		DWORD* pdwDataLen	�������ݵĳ���
//		DWORD dwFlags		��ʶ��֧������ȡֵ,�����MSDN����
//			CRYPT_FIRST
//			CRYPT_NEXT
//  ˵����
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
//	���ܣ�
//		������������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv	�������
//		DWORD dwParam		�������ͣ�֧������ȡֵ,�����MSDN����
//		BYTE* pbData		���õ�����
//		DWORD dwFlags		��ʶ��֧������ȡֵ,�����MSDN����
//  ˵����
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
//	���ܣ�
//		������Կ(�Գ���Կ��ǶԳ���Կ)
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		ALG_ID AlgId			��Կ��ʶ��֧������ȡֵ,�����MSDN����
//			CALG_RC2
//			CALG_RC4
//			CALG_3DES
//			CALG_3DES_112
//			CALG_SSF33
//			CALG_RSA_SIGN,AT_SIGNATURE
//			CALG_RSA_KEYX,AT_KEYEXCHANGE
//		DWORD dwFlags			��Կ�������ã�֧������ȡֵ,�����MSDN����
//			CRYPT_EXPORTABLE
//			CRYPT_CREATE_SALT
//			CRYPT_NO_SALT
//			CRYPT_USER_PROTECTED
//		HCRYPTKEY* phKey		��������Կ���
//
//  ˵����
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
//	���ܣ�
//		������Կ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			�����Ƶ���Կ���
//		DWORD* pdwReserved		��ΪNULL
//		DWORD dwFlags			��Ϊ0
//		HCRYPTKEY* phKey		���Ƶ���Կ���
//
//  ˵����
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
//	���ܣ�
//		�������Գ���Կ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		ALG_ID Algid			�㷨��ʶ
//		HCRYPTHASH hBaseData	��������	
//		DWORD dwFlags			��Կ�������ã�֧������ȡֵ,�����MSDN����
//			CRYPT_EXPORTABLE
//			CRYPT_CREATE_SALT
//			CRYPT_NO_SALT
//			CRYPT_USER_PROTECTED
//		HCRYPTKEY* phKey		����������Կ���
//
//  ˵����
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
//	���ܣ�
//		���ٶԳ���Կ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY pKey			��Կ���
//
//  ˵����
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
//	���ܣ�
//		������Կ��
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		DWORD dwKeySpec			��Կ������
//
//  ˵����
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
//	���ܣ�
//		��ȡ��Կ����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			��Կ���
//		DWORD dwParam			�������ͣ�֧������ȡֵ,�����MSDN����
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
//		BYTE* pbData			���ص�����
//		DWORD* pdwDataLen		�������ݵĳ���
//		DWORD dwFlags			����Ϊ0			
//
//  ˵����
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
//	���ܣ�
//		������Կ����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			��Կ���
//		DWORD dwParam			�������ͣ�֧������ȡֵ,�����MSDN����
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
//		BYTE* pbData			���õ�����
//		DWORD dwFlags			����Ϊ0			
//
//  ˵����
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
//	���ܣ�
//		������Կ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			��������Կ���
//		HCRYPTKEY hExpKey		������Կ�õļ�����Կ
//		DWORD dwBlobType		��ԿBLOB������		
//		DWORD dwFlags			����Ϊ0
//		BYTE* pbData			����������
//		DWORD* pdwDataLen		�������ݵĳ���
//
//  ˵����
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
//	���ܣ�
//		������Կ��DER����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKeyPair		��Կ�Ծ��
//		LPBYTE pbDERCode		�����ı���
//		LPDWORD pdwDERCodeLen	�����ı��볤��		
//
//  ˵����
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
//	���ܣ�
//		������Կ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		CONST BYTE *pbData		���������
//		DWORD dwDataLen			�������ݵĳ���
//		HCRYPTKEY hImpKey		����ʱ�����õ���Կ���		
//		DWORD dwFlags			��ʶ��֧������ȡֵ,�����MSDN����
//			CRYPT_EXPORTABLE 
//		HCRYPTKEY *phKey		�����������Կ���
//
//  ˵����
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
//	���ܣ�
//		��ѯ��Կ��
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		DWORD dwKeySpec			��Կ������
//		HCRYPTKEY hKeyPair		��Կ�Ծ��
//
//  ˵����
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
//	���ܣ�
//		���������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		DWORD dwLen				����������ĳ���
//		BYTE pbBuffer			�����������
//
//  ˵����
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
//	���ܣ�
//		����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			������Կ�ľ��
//		HCRYPTHASH hHash		����ͬʱ����HASH
//		BOOL Final				���һ��
//		DWORD dwFlags			����Ϊ0
//		BYTE* pbData			[IN]����/[OUT]����
//		DWORD* pdwDataLen		[IN]���ĳ���/[OUT]���ĳ���
//
//  ˵����
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
//	���ܣ�
//		����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			������Կ�ľ��
//		HCRYPTHASH hHash		����ͬʱ����HASH
//		BOOL Final				���һ��
//		DWORD dwFlags			����Ϊ0
//		BYTE* pbData			[IN]����/[OUT]����
//		DWORD* pdwDataLen		[IN]���ĳ���/[OUT]���ĳ���
//		DWORD dwBufLen			pbData�Ŀռ��С
//
//  ˵����
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
//	���ܣ�
//		RSAԭʼ����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			��Կ�Ծ��
//		LPBYTE pbInData			��������
//		DWORD dwInDataLen		�������ݵĳ���
//		LPBYTE pbOutData		�������
//		LPDWORD pdwOutDataLen	������ݵĳ���
//
//  ˵����
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
//	���ܣ�
//		RSAԭʼ����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			��Կ�Ծ��
//		LPBYTE pbInData			��������
//		DWORD dwInDataLen		�������ݵĳ���
//		LPBYTE pbOutData		�������
//		LPDWORD pdwOutDataLen	������ݵĳ���
//
//  ˵����
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
//	���ܣ�
//		����HASH
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		ALG_ID AlgId			�㷨��ʶ����ȡ����ֵ
//			CALG_MD5
//			CALG_SHA
//			CALG_SSL3_SHAMD5
//		HCRYPTKEY hKey			MAC���õ�����Կ���
//		DWORD dwFlags			����Ϊ0
//		HCRYPTHASH* phHash		������HASH���	
//
//  ˵����
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
//	���ܣ�
//		����HASH
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		�����Ƶ�HASH���
//		DWORD* pdwReserved		��ΪNULL
//		DWORD dwFlags			��Ϊ0
//		HCRYPTHASH* phHash		���Ƶ�HASH���	
//
//  ˵����
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
//	���ܣ�
//		����HASH
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		HASH���
//
//  ˵����
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
//	���ܣ�
//		��ȡHASH����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		HASH���
//		DWORD dwParam			�������ͣ�֧������ȡֵ,�����MSDN����
//			HP_ALGID 
//			HP_HASHSIZE 
//			HP_HASHVAL
//		BYTE* pbData			���ص�����
//		DWORD* pdwDataLen		�������ݵĳ���
//		DWORD dwFlags			����Ϊ0			
//
//  ˵����
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
//	���ܣ�
//		����HASH����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		HASH���
//		DWORD dwParam			�������ͣ�֧������ȡֵ,�����MSDN����
//			HP_HASHVAL 
//		BYTE* pbData			���õ�����
//		DWORD dwFlags			����Ϊ0			
//
//  ˵����
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
//	���ܣ�
//		HASH����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		HASH���
//		CONST BYTE* pbData		����
//		DWORD dwDataLen			���ݳ���
//		DWORD dwFlags			����Ϊ0
//
//  ˵����
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
//	���ܣ�
//		HASH��Կ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		HASH���
//		HCRYPTKEY hKey			��Կ���
//		DWORD dwFlags			����Ϊ0
//
//  ˵����
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
//	���ܣ�
//		ǩ��HASH
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		HASH���
//		DWORD dwKeySpec			ǩ����Կ������
//		LPCWSTR sDescription	ǩ������
//		DWORD dwFlags			����Ϊ0
//		BYTE* pbSignature		ǩ��ֵ
//		DWORD* pdwSigLen		ǩ��ֵ�ĳ���
//
//  ˵����
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
//	���ܣ�
//		��֤ǩ��
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		HASH���
//		CONST BYTE* pbSignature	ǩ��ֵ
//		DWORD dwSigLen			ǩ��ֵ�ĳ���
//		HCRYPTKEY hPubKey		��֤��Կ�ľ��
//		LPCWSTR sDescription	ǩ������
//		DWORD dwFlags			����Ϊ0
//
//  ˵����
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
//	���ܣ�
//		�ɸ�ԭǩ��
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		DWORD dwKeySpec			ǩ����Կ������
//		LPBYTE pbData			��ǩ������
//		DWORD dwDataLen			��ǩ�����ݵĳ���
//		DWORD dwFlags			����Ϊ0
//		LPBYTE pbSignature		ǩ��ֵ
//		LPDWORD pdwSigLen		ǩ��ֵ�ĳ���
//
//  ˵����
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
//	���ܣ�
//		��֤��ԭ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		CONST LPBYTE pbSignatureǩ��ֵ
//		DWORD dwSigLen			ǩ��ֵ�ĳ���
//		HCRYPTKEY hPubKey		��֤��Կ�ľ��
//		DWORD dwFlags			����Ϊ0
//		LPBYTE pbData			��ԭ����
//		LPDWORD pdwDataLen		��ԭ���ݵĳ���
//
//  ˵����
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
//	���ܣ�
//		У��PIN
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		int nUserType			�û�����
//		LPBYTE pPIN				PIN
//		DWORD dwPINLen			PIN�ĳ���
//		DWORD& nRetryCount		����󣬿����Դ���������ȷ���������塣
//
//  ˵����
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
//	���ܣ�
//		ע��
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//
//  ˵����
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
//	���ܣ�
//		���ĵ�ǰ��¼�û���PIN
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		LPBYTE pOldPIN			��PIN
//		DWORD dwOldPINLen		��PIN�ĳ���
//		LPBYTE pNewPIN			��PIN
//		DWORD dwNewPINLen		��PIN�ĳ���
//
//  ˵����
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
//	���ܣ�
//		�����û�PIN
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv				�������
//		LPBYTE pUserDefaultPIN			�������ȱʡ�û�PIN
//		DWORD dwUserDefaultPINLen		�������ȱʡ�û�PIN����
//
//  ˵����
//		�����ѵ�¼Ϊ����Ա
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
//	���ܣ�
//		��ȡ��ǰ��¼�û�������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		int& nUserType			�û�����
//
//  ˵����
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
//	���ܣ�
//		�򿪡��½���ɾ��ָ��TOKEN�е�һ���û��ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV* phProv		�ļ����
//		CHAR* szFileName		�ļ�����
//		DWORD dwFileSize		�ļ���С(ֻ���½��ļ�������)
//		DWORD dwFlags			��־
//		DWORD dwIndex			TOKEN����
//
//  ˵����
//		dwFlags��LOWORDΪ����ģʽ,HIWORDΪ�����ļ�ʱ��Ȩ���趨
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
//	���ܣ�
//		�򿪡��½���ɾ��ָ��TOKEN�е�һ���û��ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV* phProv		�ļ����
//		CHAR* szFileName		�ļ�����
//		DWORD dwFileSize		�ļ���С(ֻ���½��ļ�������)
//		DWORD dwFlags			��־
//		CHAR* szReaderName		TOKEN����
//
//  ˵����
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
//	���ܣ�
//		�رմ򿪵��û��ļ����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�ļ����
//
//  ˵����
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
//	���ܣ�
//		��ȡ�û��ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�ļ����
//		DWORD dwReadLen			����ȡ�ĳ���
//		LPBYTE pbReadBuffer		��ȡ������
//		LPDWORD pdwRealReadLen	ʵ�ʶ�ȡ�ĳ���
//		DWORD dwOffset			��ȡƫ����
//
//  ˵����
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
//	���ܣ�
//		�����û��ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�ļ����
//		LPBYTE pbWriteBuffer	д�������
//		DWORD dwWriteLen		д�����ݵĳ���
//		DWORD dwOffset			��ȡƫ����
//
//  ˵����
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
//	���ܣ�
//		��ȡ�û��ļ��Ĵ�С
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�ļ����
//		LPDWORD pdwSize			�ļ���С
//
//  ˵����
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
//	���ܣ�
//		��ȡ�û��ļ�������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�ļ����
//		CHAR* szFileName		�ļ�����
//
//  ˵����
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
//	���ܣ�
//		��ȡ�����û��ļ������б�
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		TOKEN���
//		CHAR* szFileNameList	�����û��ļ����ֵ��б�,��0�ָ�,˫0����
//		LPDWORD pcchSize		[IN]��������С/[OUT]ʵ�ʴ�С				
//
//  ˵����
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
//	���ܣ�
//		��ȡTOKEN��Ϣ
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			�������
//		LPTOKENINFO pTokenInfo		TOKEN��Ϣ
//
//  ˵����
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
//	���ܣ�
//		���»�ȡTOKEN��Ϣ
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			�������
//		LPTOKENINFO pTokenInfo		TOKEN��Ϣ
//
//  ˵����
//		CPGetTokenInfo�Ỻ���Ѷ�ȡ��TOKEN��Ϣ����ȡһ�κ��Ժ��ٵ��ö�
//	���ػ����TOKEN��Ϣ��CPReGetTokenInfo��ÿ�ξ����¶�ȡ
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
//	���ܣ�
//		����TOKEN��Ϣ
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			�������
//		LPTOKENINFO pTokenInfo		TOKEN��Ϣ
//
//  ˵����
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
//	���ܣ�
//		ѡ��������ܿ��Ķ�����
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		int& nReaderIndex		����������
//		CHAR* szReaderName		����������
//
//  ˵����
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
//	���ܣ�
//		��ʽ��TOKEN
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			�������
//		LPFORMATINFO pFormatInfo	��ʽ����Ϣ
//
//  ˵����
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
//	���ܣ�
//		��ʽ��TOKEN
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		DWORD dwIndex				����
//		LPFORMATINFO pFormatInfo	��ʽ����Ϣ
//
//  ˵����
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
//	���ܣ�
//		��ʽ��TOKEN
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		CHAR* szReaderName			������������
//		LPFORMATINFO pFormatInfo	��ʽ����Ϣ
//
//  ˵����
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
//	���ܣ�
//		�Ͽ�TOKEN������
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv	�������
//		BOOL bWrite
//
//  ˵����
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
//	���ܣ�
//		�Ͽ�TOKEN������
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		DWORD dwIndex		����
//		BOOL bWrite
//
//  ˵����
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
//	���ܣ�
//		�Ͽ�TOKEN������
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		CHAR* szReaderName	������������
//		BOOL bWrite
//
//  ˵����
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
//	���ܣ�
//		���ö�д��ö�ٱ�־λ
//
//	���أ�
//		��
//
//  ������
//		DWORD dwFlag		ö�ٶ�����������
//		BOOL bFilter		�Ƿ���˷�����������(���PCSC)
//
//  ˵����
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
//	���ܣ�
//		��ѯCSP(Token)����Ŀ
//
//	���أ�
//		��Ŀ
//
//  ������
//
//  ˵����
//-------------------------------------------------------------------
DWORD WINAPI CPGetCSPCount()
{
	TRACE_FUNCTION("CPGetCSPCount");

	return g_theTYCSPManager.GetCSPCount();
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡCSP��Ӧ������������
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		DWORD dwIndex		����
//		CHAR* szReaderName	������������
//
//  ˵����
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
//	���ܣ�
//		�����ֽ�˳��ģʽ
//
//	���أ�
//		��
//
//  ������
//		ByteOrderMode nMode		�ֽ�˳��ģʽ
//
//  ˵����
//-------------------------------------------------------------------
void WINAPI CPSetByteOrderMode(
	ByteOrderMode nMode
	)
{
	TRACE_FUNCTION("CPSetByteOrderMode");
	g_ByteOrderMode = nMode;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ж��Ƿ��Զ�����������Ϊ��ѯ������������
//
//	���أ�
//		TRUE:��		FALSE:����
//
//  ������
//		��
//
//  ˵����
//		ȱʡΪ�ö������б�����
//-------------------------------------------------------------------
BOOL WINAPI CPIsUseReaderIndex()
{
	TRACE_FUNCTION("CPIsUseReaderIndex");
	return g_bUseReaderIndex;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�����Ƿ��Զ�����������Ϊ��ѯ������������
//
//	���أ�
//		��
//
//  ������
//		BOOL bFlag	��־
//
//  ˵����
//		ȱʡΪ�ö������б�����
//-------------------------------------------------------------------
void WINAPI CPSetUseReaderIndex(
	BOOL bFlag
	)
{
	TRACE_FUNCTION("CPSetUseReaderIndex");
	g_bUseReaderIndex = bFlag;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡPIN��������Ϣ
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			�������
//		int nUserType				�û�����
//		int nMaxRetry				������Դ���
//		int nLeftRetry				ʣ�����Դ���
//
//  ˵����
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
//	���ܣ�
//		��ѯ����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			�������
//		DWORD& dwTotalSize			�ܿռ�(��ϵͳռ��)
//		DWORD& dwTotalSize2			�ܿռ�(����ϵͳռ��)
//		DWORD& dwUnusedSize			���ÿռ�
//
//  ˵����
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
//	���ܣ�
//		��ѯ����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		DWORD dwIndex				����
//		DWORD& dwTotalSize			�ܿռ�(��ϵͳռ��)
//		DWORD& dwTotalSize2			�ܿռ�(����ϵͳռ��)
//		DWORD& dwUnusedSize			���ÿռ�
//
//  ˵����
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
//	���ܣ�
//		��ѯ����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		CHAR* szReaderName			������������
//		DWORD& dwTotalSize			�ܿռ�(��ϵͳռ��)
//		DWORD& dwTotalSize2			�ܿռ�(����ϵͳռ��)
//		DWORD& dwUnusedSize			���ÿռ�
//
//  ˵����
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
//	���ܣ�
//		��ѯCOS�汾
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		DWORD& dwCosVersion				COS�汾
//
//  ˵����
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
//	���ܣ�
//		��ѯ�з�SSF33�㷨
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//
//  ˵����
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
//	���ܣ�
//		����EEPROM
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			�������
//
//  ˵����
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
//	���ܣ�
//		����EEPROM
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		DWORD dwIndex				����
//
//  ˵����
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
//	���ܣ�
//		����EEPROM
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		CHAR* szReaderName			������������
//
//  ˵����
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
//	���ܣ�
//		��ȡATR��Ϣ
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		BYTE* pbATR				���ص�ATR
//		DWORD* pdwATR			���ص�ATR�ĳ���
//
//  ˵����
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
//	���ܣ�
//		�򿨷�������
//
//	���أ�
//		TRUE:�ɹ�(SW1SW2 = 0x9000��0x61XX)	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		BYTE* pbCommand			������
//		DWORD dwCommandLen		������ĳ���
//		BYTE* pbRespond			��Ӧ��
//		DWORD* pdwRespondLen	��Ӧ��ĳ���
//		WORD* pwStatus			״̬�ֽ�
//
//  ˵����
//		�������Ҫ��Ӧ���״̬�ֽ�,ֻ�踳��NULL
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
//	���ܣ�
//		�򿨷�������
//
//	���أ�
//		TRUE:�ɹ�(SW1SW2 = 0x9000��0x61XX)	FALSE:ʧ��
//
//  ������
//		DWORD dwIndex			����
//		BYTE* pbCommand			������
//		DWORD dwCommandLen		������ĳ���
//		BYTE* pbRespond			��Ӧ��
//		DWORD* pdwRespondLen	��Ӧ��ĳ���
//		WORD* pwStatus			״̬�ֽ�
//
//  ˵����
//		�������Ҫ��Ӧ���״̬�ֽ�,ֻ�踳��NULL
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
//	���ܣ�
//		�򿨷�������
//
//	���أ�
//		TRUE:�ɹ�(SW1SW2 = 0x9000��0x61XX)	FALSE:ʧ��
//
//  ������
//		CHAR* szReaderName		������������
//		BYTE* pbCommand			������
//		DWORD dwCommandLen		������ĳ���
//		BYTE* pbRespond			��Ӧ��
//		DWORD* pdwRespondLen	��Ӧ��ĳ���
//		WORD* pwStatus			״̬�ֽ�
//
//  ˵����
//		�������Ҫ��Ӧ���״̬�ֽ�,ֻ�踳��NULL
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
//	���ܣ�
//		������ܿ��Ƿ����
//
//	���أ�
//		TRUE:����	FALSE:������
//
//  ������
//		HCRYPTPROV hProv	�������
//
//  ˵����
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
//	���ܣ�
//		������ܿ��Ƿ����
//
//	���أ�
//		TRUE:����	FALSE:������
//
//  ������
//		DWORD dwIndex		����
//
//  ˵����
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
//	���ܣ�
//		������ܿ��Ƿ����
//
//	���أ�
//		TRUE:����	FALSE:������
//
//  ������
//		CHAR* szReaderName	������������
//
//  ˵����
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
//	���ܣ�
//		���������Ƿ����
//
//	���أ�
//		TRUE:����	FALSE:������
//
//  ������
//		HCRYPTPROV hProv	�������
//
//  ˵����
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
//	���ܣ�
//		���������Ƿ����
//
//	���أ�
//		TRUE:����	FALSE:������
//
//  ������
//		DWORD dwIndex		����
//
//  ˵����
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
//	���ܣ�
//		���������Ƿ����
//
//	���أ�
//		TRUE:����	FALSE:������
//
//  ������
//		CHAR* szReaderName	������������
//
//  ˵����
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
