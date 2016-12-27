//-------------------------------------------------------------------
//	���ļ�Ϊ TY Cryptographic Service Provider ����ɲ���
//
//
//	��Ȩ���� ������Ϣ��ҵ���޹�˾ (c) 1996 - 2005 ����һ��Ȩ��
//-------------------------------------------------------------------
#include "stdafx.h"
#include "HashObject.h"
#include "CSPKey.h"
#include "MD5.h"
#include "SHA.H"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/////////////////////////////////////////////////////////////////////
// class CCSPHashObject
//
//-------------------------------------------------------------------
//	���ܣ�
//		���캯��
//
//	���أ�
//		��
//
//  ������
//		ALG_ID idAlg		�㷨��ʶ
//
//  ˵����
//-------------------------------------------------------------------
CCSPHashObject::CCSPHashObject(
	ALG_ID idAlg
	)
{
	m_idAlg = idAlg;
	m_pHashModule = NULL;
	if(m_idAlg == CALG_MD5){
		m_pHashModule = new MD5;
		m_dwSize = 16;
	}
	else if(m_idAlg == CALG_SHA){
		m_pHashModule= new SHA;
		m_dwSize = 20;
	}
	else if(m_idAlg == CALG_SSL3_SHAMD5){
		m_pHashModule = NULL;
		m_dwSize = 36;
	}
	memset(m_cValue, 0, sizeof(m_cValue));
	m_bFinished = FALSE;
	m_bEmpty = TRUE;
	m_hHandle = (HCRYPTHASH)this;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��������
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
CCSPHashObject::~CCSPHashObject()
{
	if(m_pHashModule != NULL){
		delete m_pHashModule;
		m_pHashModule = NULL;
	}
}


//-------------------------------------------------------------------
//	���ܣ�
//		��ȡHASHֵ
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		BYTE* pbData		�����HASHֵ	
//		DWORD* pdwDataLen	HASHֵ�ĳ���(�ֽ�)
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPHashObject::GetValue(
	BYTE* pbData,
	DWORD* pdwDataLen
	)
{
	return GetParam(HP_HASHVAL, pbData, pdwDataLen, 0);
}

//-------------------------------------------------------------------
//	���ܣ�
//		����HASHֵ
//
//	���أ�
//		��
//
//  ������
//		BYTE* pbData	HASHֵ
//
//  ˵����
//-------------------------------------------------------------------
void
CCSPHashObject::SetValue(
	BYTE* pbData
	)
{
	SetParam(HP_HASHVAL, pbData, 0);
}

//-------------------------------------------------------------------
//	���ܣ�
//		����HASH����
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		BYTE* pbDigest				HASHֵ
//		LPDWORD pdwDigestLen		HASHֵ�ĳ���
//
//  ˵����
//-------------------------------------------------------------------
void
CCSPHashObject::Finish()
{
	//����Ѿ���������ֱ�ӷ���
	if(m_bFinished)
		return;

	//��ȡHASH���
	if(m_pHashModule != NULL)
		m_pHashModule->Final(m_cValue);

	//���ñ��
	m_bFinished = TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡHASH����״̬
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		LPHASHSTATE	lpHashState			
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPHashObject::GetHashState(
	LPHASHSTATE lpHashState
	)
{
	if(m_pHashModule != NULL)
		return m_pHashModule->GetHashState(lpHashState);
	else
		return FALSE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		����HASH����״̬
//
//	���أ�
//		��
//
//  ������
//		LPHASHSTATE	lpHashState			
//
//  ˵����
//-------------------------------------------------------------------
void
CCSPHashObject::SetHashState(
	LPHASHSTATE lpHashState
	)
{
	if(m_pHashModule != NULL)
		m_pHashModule->SetHashState(lpHashState);
}

//-------------------------------------------------------------------
//	���ܣ�
//		makes an exact copy of a hash and its state
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		DWORD *pdwReserved					����ֵ,����ΪNULL				
//		DWORD dwFlags						����ֵ,����Ϊ0
//		CCSPHashObject* pSourceHash			ԴHASH����
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPHashObject::Duplicate(
	DWORD *pdwReserved,
	DWORD dwFlags,
	CCSPHashObject* pSourceHash
	)
{
	//ԴHASH����������
	ASSERT(pSourceHash != NULL);
	//�㷨��ʶ������ͬ
	ASSERT(GetAlgId() == pSourceHash->GetAlgId());
	//Ŀ��������Ϊ�յ�HASH����
	ASSERT(IsEmpty());

	//�������
	if(pdwReserved != NULL || dwFlags != 0){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	//ԴHASH�������Ϊ��,�������κβ���
	if(pSourceHash->IsEmpty())
		return TRUE;

	//���Դ�����ѽ���HASH����,��ֱ�ӻ�ȡ����HASHֵ
	if(pSourceHash->IsFinished()){
		if(!pSourceHash->GetValue(m_cValue, &m_dwSize)){
			SETLASTERROR(NTE_FAIL);
			return FALSE;
		}
	}
	//�����ȡ���м�HASHֵ���������ݵ�ȫ����״ֵ̬
	else{
		HASHSTATE hashState;
		if(!pSourceHash->GetHashState(&hashState)){
			SETLASTERROR(NTE_FAIL);
			return FALSE;
		}
		SetHashState(&hashState);
	}

	//���Դ�����ѽ���HASH����,��Ŀ�����ҲӦ���
	m_bFinished = pSourceHash->IsFinished();

	//����Ϊ��
	m_bEmpty = FALSE;

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		The call to CPGetHashParam function completes the hash. 
//	After this call, no more data can be added to the hash. 
//	Additional calls to CPHashData or CPHashSessionKey must 
//	fail. 
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		DWORD dwParam			��������
//		BYTE *pbData			����ֵ
//		DWORD *pdwDataLen		����ֵ�ĳ���
//		DWORD dwFlags			��־(δ��,����Ϊ0)
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPHashObject::GetParam(
	DWORD dwParam, 
	BYTE *pbData, 
	DWORD *pdwDataLen, 
	DWORD dwFlags
	)
{
	//�������
	if(pdwDataLen == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if(dwFlags != 0){
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}

	BOOL bRetVal = TRUE;
	//�ж��Ƿ��ǲ�ѯ����
	BOOL bQueryLen = (pbData == NULL);
	if(dwParam == HP_ALGID){
		if(!bQueryLen){
			if(*pdwDataLen < sizeof(m_idAlg)){
				SETLASTERROR(ERROR_MORE_DATA);
				bRetVal = FALSE;
			}
			else
				memcpy(pbData, &m_idAlg, sizeof(m_idAlg));
		}
		*pdwDataLen = sizeof(m_idAlg);
	}
	else if(dwParam == HP_HASHSIZE){
		if(!bQueryLen){
			if(*pdwDataLen < sizeof(m_dwSize)){
				SETLASTERROR(ERROR_MORE_DATA);
				bRetVal = FALSE;
			}
			else
				memcpy(pbData, &m_dwSize, sizeof(m_dwSize));
		}
		*pdwDataLen = sizeof(m_dwSize);
	}
	else if(dwParam == HP_HASHVAL){
		if(!bQueryLen){
			if(*pdwDataLen < m_dwSize){
				SETLASTERROR(ERROR_MORE_DATA);
				bRetVal = FALSE;
			}
			else{
				//����HASH����,�����������m_cValue��
				Finish();
				memcpy(pbData, m_cValue, m_dwSize);
			}
		}
		*pdwDataLen = m_dwSize;
	}
	else{
		SETLASTERROR(NTE_BAD_TYPE);
		bRetVal = FALSE;
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		customizes the operations of a hash object. Typically, the 
//	hash object will be empty. If this is not the case, an 
//	error returned. 
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		DWORD dwParam			��������
//		BYTE *pbData			����ֵ
//		DWORD dwFlags			��־(δ��,����Ϊ0)
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPHashObject::SetParam(
	DWORD dwParam,
	BYTE* pbData,
	DWORD dwFlags
	)
{
	//�������
	if(pbData == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if(dwFlags != 0){
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}

	if(dwParam == HP_HASHVAL){
		if(pbData != NULL){
			//�ж�ָ����ڴ��Ƿ�Ϸ�
			BOOL bIsValid = AfxIsValidAddress(pbData, m_dwSize);
			if(!bIsValid){
				SETLASTERROR(NTE_BAD_DATA);
				return FALSE;
			}
			//����HASH����
			Finish();
			//�滻HASHֵ
			memcpy(m_cValue, pbData, m_dwSize);
			//����Ϊ��
			m_bEmpty = FALSE;
		}
	}
	else{
		SETLASTERROR(NTE_BAD_TYPE);
		return FALSE;
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		feeds data into a specified hash object
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		CONST BYTE* pbData		Ҫ����HASH������
//		DWORD dwDataLen			���ݵĳ���
//		DWORD dwFlags			��־
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPHashObject::HashData(
	CONST BYTE* pbData,
	DWORD dwDataLen,
	DWORD dwFlags
	)
{
	//SSL3_SHAMDE��֧��HashData
	if(m_idAlg == CALG_SSL3_SHAMD5){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}

	//�������
	if(dwFlags != 0){
		if(dwFlags == CRYPT_USERDATA){
			if(dwDataLen != 0){
				SETLASTERROR(NTE_BAD_LEN);
				return FALSE;
			}
		}
		else{
			SETLASTERROR(NTE_BAD_FLAGS);
			return FALSE;
		}
	}

	if(dwDataLen == 0)
		return TRUE;
	else{
		if(pbData == NULL){
			SETLASTERROR(ERROR_INVALID_PARAMETER);
			return FALSE;
		}
	}

	//״̬���
	if(IsFinished()){
		SETLASTERROR(NTE_BAD_HASH_STATE);
		return FALSE;
	}

	//����HASHֵ
	ASSERT(m_pHashModule != NULL);
	m_pHashModule->Update(pbData, static_cast<unsigned int>(dwDataLen));

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		feeds a cryptographic key to a specified hash object. This 
//	allows a key to be hashed without the application having access 
//	to the key material.
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		CCSPKey* pKey		��Կ����
//		DWORD dwFlags		��־λ
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPHashObject::HashSessionKey(
	CCSPKey* pKey,
	DWORD dwFlags
	)
{
	//SSL3_SHAMD5��֧��HashSessionKey
	if(m_idAlg == CALG_SSL3_SHAMD5){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}
	ASSERT(pKey != NULL);

	//��ȡKey Material
	BYTE* pbKeyMaterial = NULL;
	DWORD dwLength;
	if(!pKey->GetKeyMaterial(NULL, &dwLength)){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}

	if(dwLength == 0)
		return TRUE;
	
	pbKeyMaterial = new BYTE[dwLength];
	if(pbKeyMaterial == NULL){
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}
	//Little Endian
	VERIFY(pKey->GetKeyMaterial(pbKeyMaterial, &dwLength));

	//ȱʡ��Big Endian
	if(!(dwFlags & CRYPT_LITTLE_ENDIAN)){
		ByteReverse(pbKeyMaterial, dwLength);
		TRACE_LINE("\n��Big Endian�ķ�ʽ\n");
	}

	BOOL bRetVal = HashData(pbKeyMaterial, dwLength, 0);
	delete pbKeyMaterial;

	return bRetVal;
}
