//-------------------------------------------------------------------
//	本文件为 TY Cryptographic Service Provider 的组成部分
//
//
//	版权所有 天喻信息产业有限公司 (c) 1996 - 2005 保留一切权利
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
//	功能：
//		构造函数
//
//	返回：
//		无
//
//  参数：
//		ALG_ID idAlg		算法标识
//
//  说明：
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
//	功能：
//		析构函数
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
CCSPHashObject::~CCSPHashObject()
{
	if(m_pHashModule != NULL){
		delete m_pHashModule;
		m_pHashModule = NULL;
	}
}


//-------------------------------------------------------------------
//	功能：
//		获取HASH值
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		BYTE* pbData		输出的HASH值	
//		DWORD* pdwDataLen	HASH值的长度(字节)
//
//  说明：
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
//	功能：
//		设置HASH值
//
//	返回：
//		无
//
//  参数：
//		BYTE* pbData	HASH值
//
//  说明：
//-------------------------------------------------------------------
void
CCSPHashObject::SetValue(
	BYTE* pbData
	)
{
	SetParam(HP_HASHVAL, pbData, 0);
}

//-------------------------------------------------------------------
//	功能：
//		结束HASH运算
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		BYTE* pbDigest				HASH值
//		LPDWORD pdwDigestLen		HASH值的长度
//
//  说明：
//-------------------------------------------------------------------
void
CCSPHashObject::Finish()
{
	//如果已经结束，则直接返回
	if(m_bFinished)
		return;

	//获取HASH结果
	if(m_pHashModule != NULL)
		m_pHashModule->Final(m_cValue);

	//设置标记
	m_bFinished = TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		获取HASH对象状态
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		LPHASHSTATE	lpHashState			
//
//  说明：
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
//	功能：
//		设置HASH对象状态
//
//	返回：
//		无
//
//  参数：
//		LPHASHSTATE	lpHashState			
//
//  说明：
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
//	功能：
//		makes an exact copy of a hash and its state
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		DWORD *pdwReserved					保留值,必须为NULL				
//		DWORD dwFlags						保留值,必须为0
//		CCSPHashObject* pSourceHash			源HASH对象
//
//  说明：
//-------------------------------------------------------------------
BOOL
CCSPHashObject::Duplicate(
	DWORD *pdwReserved,
	DWORD dwFlags,
	CCSPHashObject* pSourceHash
	)
{
	//源HASH对象必须存在
	ASSERT(pSourceHash != NULL);
	//算法标识必须相同
	ASSERT(GetAlgId() == pSourceHash->GetAlgId());
	//目标对象必须为空的HASH对象
	ASSERT(IsEmpty());

	//参数检测
	if(pdwReserved != NULL || dwFlags != 0){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	//源HASH对象如果为空,则不需做任何操作
	if(pSourceHash->IsEmpty())
		return TRUE;

	//如果源对象已结束HASH计算,则直接获取最后的HASH值
	if(pSourceHash->IsFinished()){
		if(!pSourceHash->GetValue(m_cValue, &m_dwSize)){
			SETLASTERROR(NTE_FAIL);
			return FALSE;
		}
	}
	//否则获取其中间HASH值及缓冲数据等全部的状态值
	else{
		HASHSTATE hashState;
		if(!pSourceHash->GetHashState(&hashState)){
			SETLASTERROR(NTE_FAIL);
			return FALSE;
		}
		SetHashState(&hashState);
	}

	//如果源对象已结束HASH计算,则目标对象也应如此
	m_bFinished = pSourceHash->IsFinished();

	//不再为空
	m_bEmpty = FALSE;

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		The call to CPGetHashParam function completes the hash. 
//	After this call, no more data can be added to the hash. 
//	Additional calls to CPHashData or CPHashSessionKey must 
//	fail. 
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		DWORD dwParam			参数类型
//		BYTE *pbData			参数值
//		DWORD *pdwDataLen		参数值的长度
//		DWORD dwFlags			标志(未用,必须为0)
//
//  说明：
//-------------------------------------------------------------------
BOOL
CCSPHashObject::GetParam(
	DWORD dwParam, 
	BYTE *pbData, 
	DWORD *pdwDataLen, 
	DWORD dwFlags
	)
{
	//参数检测
	if(pdwDataLen == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if(dwFlags != 0){
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}

	BOOL bRetVal = TRUE;
	//判断是否是查询长度
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
				//结束HASH运算,并将结果放于m_cValue中
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
//	功能：
//		customizes the operations of a hash object. Typically, the 
//	hash object will be empty. If this is not the case, an 
//	error returned. 
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		DWORD dwParam			参数类型
//		BYTE *pbData			参数值
//		DWORD dwFlags			标志(未用,必须为0)
//
//  说明：
//-------------------------------------------------------------------
BOOL
CCSPHashObject::SetParam(
	DWORD dwParam,
	BYTE* pbData,
	DWORD dwFlags
	)
{
	//参数检测
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
			//判断指向的内存是否合法
			BOOL bIsValid = AfxIsValidAddress(pbData, m_dwSize);
			if(!bIsValid){
				SETLASTERROR(NTE_BAD_DATA);
				return FALSE;
			}
			//结束HASH运算
			Finish();
			//替换HASH值
			memcpy(m_cValue, pbData, m_dwSize);
			//不再为空
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
//	功能：
//		feeds data into a specified hash object
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		CONST BYTE* pbData		要计算HASH的数据
//		DWORD dwDataLen			数据的长度
//		DWORD dwFlags			标志
//
//  说明：
//-------------------------------------------------------------------
BOOL
CCSPHashObject::HashData(
	CONST BYTE* pbData,
	DWORD dwDataLen,
	DWORD dwFlags
	)
{
	//SSL3_SHAMDE不支持HashData
	if(m_idAlg == CALG_SSL3_SHAMD5){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}

	//参数检测
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

	//状态检测
	if(IsFinished()){
		SETLASTERROR(NTE_BAD_HASH_STATE);
		return FALSE;
	}

	//计算HASH值
	ASSERT(m_pHashModule != NULL);
	m_pHashModule->Update(pbData, static_cast<unsigned int>(dwDataLen));

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		feeds a cryptographic key to a specified hash object. This 
//	allows a key to be hashed without the application having access 
//	to the key material.
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		CCSPKey* pKey		密钥对象
//		DWORD dwFlags		标志位
//
//  说明：
//-------------------------------------------------------------------
BOOL
CCSPHashObject::HashSessionKey(
	CCSPKey* pKey,
	DWORD dwFlags
	)
{
	//SSL3_SHAMD5不支持HashSessionKey
	if(m_idAlg == CALG_SSL3_SHAMD5){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}
	ASSERT(pKey != NULL);

	//获取Key Material
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

	//缺省按Big Endian
	if(!(dwFlags & CRYPT_LITTLE_ENDIAN)){
		ByteReverse(pbKeyMaterial, dwLength);
		TRACE_LINE("\n按Big Endian的方式\n");
	}

	BOOL bRetVal = HashData(pbKeyMaterial, dwLength, 0);
	delete pbKeyMaterial;

	return bRetVal;
}
