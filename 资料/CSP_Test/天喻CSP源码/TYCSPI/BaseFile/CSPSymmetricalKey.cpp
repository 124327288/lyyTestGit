 //CSPSymmetricalKey.cpp
#include <stdAfx.h>
#include "cspkey.h"
#include "rng.h"

CCSPSymmetricalKey::CCSPSymmetricalKey(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken
		//BOOL bExtractable,
		//BOOL bPrivate
		):CCSPKey(pKeyContainer, ulAlgId,bToken/*,bExtractable,bPrivate*/)
{
	m_bFinished = TRUE;
	m_pCBCPaddedEncryptor = NULL;
	m_pCBCPaddedDecryptor = NULL;
	
}

CCSPSymmetricalKey::~CCSPSymmetricalKey()
{
//	if (m_bFinished == FALSE)
	{
		if (m_pCBCPaddedEncryptor)
		{
			delete m_pCBCPaddedEncryptor;
			m_pCBCPaddedEncryptor = NULL;
		}
		if (m_pCBCPaddedDecryptor)
		{
			delete m_pCBCPaddedDecryptor;
			m_pCBCPaddedDecryptor = NULL;
		}
			
	}
	m_arbKeyContent.RemoveAll();
	CCSPKey::~CCSPKey();
}

CCSPSymmetricalKey::CCSPSymmetricalKey(
		CCSPSymmetricalKey & src
		) : CCSPKey(src)
{
	m_arbKeyContent.Copy(src.m_arbKeyContent);
	m_bFinished = TRUE;
}
//------------------------------------------------------
/*
功能：传人密钥的值
输入：	bitlen－key的长度
		keyContent-key内容

输入：
说明：该函数自动按照bitlen取keyContent的长度
*/
//------------------------------------------------------
/*BOOL CCSPSymmetricalKey::Create(
	DWORD bitlen,
	CONST BYTE* keyContent
	)
{
	m_ulKeyLen = bitlen;
	//LC_RNG rng(765);
	BYTE * tmp = new BYTE[bitlen/8];
	g_rng.GetBlock(tmp,bitlen/8);
	CopyByteToArray(m_arbKeyContent,tmp,bitlen/8);
	delete tmp;
	return TRUE;
}*/

BOOL CCSPSymmetricalKey::Create(
		DWORD bitlen,
		DWORD dwFlags
		) 
{
	m_ulKeyLen = bitlen;
	//m_dwEffectiveKeyLen = m_ulKeyLen+m_ulSaltLen;
	BOOL bRet = CCSPKey::Create(bitlen,dwFlags);
	if (bRet == FALSE)
		return FALSE;
	
	
	BYTE * tmp = new BYTE[(m_ulKeyLen+m_ulSaltLen)/8];
	//LC_RNG rng(765);
	g_rng.GetBlock(tmp,(m_ulKeyLen+m_ulSaltLen)/8);
	if ((m_dwFlags&CRYPT_CREATE_SALT == 0)&&(m_ulSaltLen>0))
	{
		memset(tmp+m_ulKeyLen/8,0,m_ulSaltLen/8);
	}
	CopyByteToArray(m_arbKeyContent,tmp,m_ulKeyLen/8+m_ulSaltLen/8);
	//change the salt value
	CopyByteToArray(m_arbSalt,tmp+m_ulKeyLen/8,m_ulSaltLen/8);
	delete tmp;
	return TRUE;
}
//Create the object on the card
BOOL CCSPSymmetricalKey::CreateOnToken(
	ULONG ulIndex
	)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}

//Destroy the object on the card
BOOL CCSPSymmetricalKey::DestroyOnToken()
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}

BOOL CCSPSymmetricalKey::LoadFromToken(
	//BYTE* DEREncodedStr,
	//ULONG ulDEREncodedStrLen,
	ULONG ulIndex
	)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}

BOOL CCSPSymmetricalKey::SetParam(
	DWORD dwParam,           // in
	BYTE *pbData,            // in
	DWORD dwFlags            // in
	)
{
	if ((dwParam == KP_SALT)||(dwParam == KP_SALT_EX))
	{
		BYTE *tmp = new BYTE[m_ulKeyLen/8 + m_ulSaltLen/8];
		memcpy(tmp,m_arbKeyContent.GetData(),m_ulKeyLen/8);
		memcpy(tmp+m_ulKeyLen/8,pbData,m_ulSaltLen/8);
		CopyByteToArray(m_arbKeyContent,tmp,m_ulKeyLen/8+m_ulSaltLen/8);
		delete tmp;
	}
	return CCSPKey::SetParam(dwParam,pbData,dwFlags);
}
BOOL CCSPSymmetricalKey::GetParam(
	DWORD dwParam,          // in
	BYTE *pbData,           // out
	DWORD *pdwDataLen,      // in, out
	DWORD dwFlags			// in
	)
{
	return CCSPKey::GetParam(dwParam,pbData,pdwDataLen,dwFlags);
}
/*BOOL CCSPSymmetricalKey::Duplicate(
	DWORD *pdwReserved,		// in
	DWORD dwFlags,			// in
	CCSPKey * pKey			// out
	)

{
	return TRUE;
}*/
/*BOOL CCSPSymmetricalKey::GetKeyBlob(
	DWORD dwBlobType,			// in
	BYTE *pbKeyBlob,			// out
	DWORD *dwKeyBlobLen			// in, out
	)
{
	return TRUE;
}*/
BOOL CCSPSymmetricalKey::Export(
	CCSPKey *pPubKey,				// in
	DWORD dwBlobType,				// in
	DWORD dwFlags,					// in
	BYTE *pbKeyBlob,				// out
	DWORD *dwKeyBlobLen			// in, out
	)
{
	return TRUE;
}

BOOL CCSPSymmetricalKey::Encrypt(
	CCSPHashObject* pHash,		// in
	BOOL Final,					// in
	DWORD dwFlags,				// in
	BYTE *pbData,				// in, out
	DWORD *pdwDataLen,			// in, out
	DWORD dwBufLen				// in
	)
{
	return TRUE;
}
BOOL CCSPSymmetricalKey::Decrypt(
	CCSPHashObject* pHash,			// in
	BOOL Final,						// in
	DWORD dwFlags,					// in
	BYTE *pbData,					// in, out
	DWORD *pdwDataLen				// in, out
	)
{
	return TRUE;
}

BOOL CCSPSymmetricalKey::SignHash(
	CCSPHashObject* pHash,           // in
	LPCWSTR sDescription,			// in
	DWORD dwFlags,					// in
	BYTE *pbSignature,				// out
	DWORD *pdwSigLen				// in, out
	)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}
BOOL CCSPSymmetricalKey::VerifySignature(
	CCSPHashObject* pHash,			// in
	CONST BYTE *pbSignature,		// in
	DWORD dwSigLen,					// in
	LPCWSTR sDescription,			// in
	DWORD dwFlags					// in
	)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}
BOOL CCSPSymmetricalKey::GetKeyMaterial(
	BYTE * pOutData,
	DWORD * dwOutDataLen
	)
{
	return FillDataBuffer(pOutData,dwOutDataLen,
		m_arbKeyContent.GetData(),m_ulKeyLen/8);
}

void CCSPSymmetricalKey::CreatebyBlob(
		BYTE * pBlob,
		DWORD dwBlobLen
		)
{
	CopyByteToArray(m_arbKeyContent,pBlob,dwBlobLen);
	if (m_ulSaltLen/8)
	{
		CopyByteToArray(m_arbSalt,pBlob+m_ulKeyLen/8,m_ulSaltLen/8);
	}
}
