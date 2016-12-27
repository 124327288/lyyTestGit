#include <stdAfx.h>
#include "cspkey.h"
#include "DERCoding.h"
#include "KeyContainer.h"

_tagPathTable g_cPathTable =
{
	{0x3f,0x00},	//mfPath
	{0x2f,0x01},	//dirPath
	{0x50,0x32},	//tokenInfoPath
	{0x50,0x33},	//fileTablePath

	{0x60,0x80},	//prkdfPath

	{0x00,0x01},	//prkStartPath
	{0x80,0x01},	//prkexStarPath
	{0x00,0x10},	//pukStartPath

	{0x01,0x01},	//eccprkStartPath
	{0x81,0x01},	//eccprkexStarPath
	{0x01,0x11},	//eccpukStartPath

	{0x83,0x01},	//skStartPath
	{0x84,0x01},	//certStartPath
	{0x87,0x01},	//dataStartPath

	{0x50,0x29},	//文件系统版本号路径

	0x5a,			//eitherNeed
	0x0f,			//free

	0xFB,			//bufSize, 60改成FB, 251个字节,加上4个字节的MAC; chenji/2005-12-22
	0x104,       	//rsaPukFileLen 0x98 ==> 0x104
	0x280,          //rsaPrkFileLen 0x164==> 0x280
	0x110,			//rsaPrkExFileLen 0x90 ==>0x110

	0x44,			//eccPukFileLen 68
	0x24,			//eccPrkFileLen 36
	0x3c,			//eccPrkExFileLen 60

	0x03,			//fileTableHeadLen
	0x06,			//fileTableRecLen
	
	0x15,			//prkAttrLen
};

CCSPKey::CCSPKey(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	/*= FALSE*/
		//BOOL bExtractable /*= TRUE*/,
		//BOOL bPrivate /*= FALSE*/
		)
{
	ASSERT(pKeyContainer != NULL);
	m_pKeyContainer = pKeyContainer;
	m_hHandle = HCRYPTKEY(this);
	m_bToken = bToken;
	m_RealObjReaded = FALSE;
	//m_bExtractable = bExtractable;
	//m_bPrivate = bPrivate;
	m_bAuthId = 0;
	m_bLogged = FALSE;
	m_ulAlgId = ulAlgId;
	m_dwBlockLen = 0;
	m_ulKeyLen = 0;
	m_dwPermissions = 0x3b;
	//m_dwPermissions |= (bExtractable?CRYPT_EXPORT:0);
	m_dwPadding = PKCS5_PADDING;
	m_dwMode = 0;
	m_dwModeBits = 0;
	m_dwEffectiveKeyLen = 0;
	m_ulSaltLen = 0;
	m_ulIvLen = 0;
	m_RealObjPath[0] = 0;
	m_RealObjPath[1] = 0;
	m_bHandleValid = TRUE;
	m_ulIndex = -1;
}

CCSPKey::CCSPKey(
		CCSPKey & srcCSPKey
		)
{
	m_pKeyContainer = srcCSPKey.m_pKeyContainer;
	m_ulIndex = srcCSPKey.m_ulIndex;
	m_hHandle = HCRYPTKEY(this);
	m_bToken = srcCSPKey.m_bToken;
	m_dwFlags = srcCSPKey.m_dwFlags;
	m_bAuthId = srcCSPKey.m_bAuthId;
	m_bLogged =	srcCSPKey.m_bLogged;
	m_ulAlgId = srcCSPKey.m_ulAlgId;
	m_dwBlockLen = srcCSPKey.m_dwBlockLen;
	m_ulKeyLen = srcCSPKey.m_ulKeyLen;
	m_arbSalt.Copy(srcCSPKey.m_arbSalt);
	m_ulSaltLen = srcCSPKey.m_ulSaltLen;
	m_dwPermissions = srcCSPKey.m_dwPermissions;
	m_arbIv.Copy(srcCSPKey.m_arbIv);
	m_ulIvLen = srcCSPKey.m_ulIvLen;
	m_dwPadding = srcCSPKey.m_dwPadding;
	m_dwMode = srcCSPKey.m_dwMode;
	m_dwModeBits = srcCSPKey.m_dwModeBits;
	m_dwEffectiveKeyLen = srcCSPKey.m_dwEffectiveKeyLen;
	m_szUserName = srcCSPKey.m_szUserName;
	m_szUserAccount = srcCSPKey.m_szUserAccount;
	m_RealObjPath[0] = srcCSPKey.m_RealObjPath[0];
	m_RealObjPath[1] = srcCSPKey.m_RealObjPath[1];
	m_RealObjReaded = srcCSPKey.m_RealObjReaded;
	m_bHandleValid = srcCSPKey.m_bHandleValid;
}

CCSPKey::~CCSPKey()
{
	m_arbSalt.RemoveAll();
	m_arbIv.RemoveAll();
}

CTYCSP* CCSPKey::GetCSPObject() const
{
	return m_pKeyContainer->GetCSPObject();
}

BOOL CCSPKey::CreateOnToken(
		ULONG ulIndex
		)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}
//------------------------------------------------------
/*
功能：产生密钥
输入：	bitlen－key的长度
		dwFlags

输入：
说明：
*/
//------------------------------------------------------
BOOL CCSPKey::Create(
	DWORD bitlen,
	DWORD dwFlags
	)
{
	m_dwFlags = dwFlags;
	m_dwPermissions |= ((dwFlags&CRYPT_EXPORTABLE)?CRYPT_EXPORT:0);
	m_RealObjReaded = TRUE;
	return TRUE;
}
BOOL CCSPKey::DestroyOnToken()
{
	return FALSE;
}

BOOL CCSPKey::LoadFromToken(
		//BYTE* DEREncodedStr,
		//ULONG ulDEREncodedStrLen,
		ULONG ulIndex
		)
{
	return FALSE;
}

BOOL CCSPKey::LogIn(
		CString szUserName,
		CString szUserAccount
		)
{
	m_bLogged = TRUE;
	m_szUserName = szUserName;
	m_szUserAccount = szUserAccount;
	return TRUE;
}

BOOL CCSPKey::SetParam(
		DWORD dwParam,           // in
		BYTE *pbData,            // in
		DWORD dwFlags            // in
		)
{
	if ((m_dwPermissions&CRYPT_WRITE) == 0)
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}
	if (dwFlags != 0)
	{
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}

	if ((m_dwPermissions&CRYPT_WRITE) == 0)
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	switch (dwParam)
	{
	case KP_SALT:
	case KP_SALT_EX:
		CopyByteToArray(m_arbSalt,pbData,m_ulSaltLen/8);
		break;
	case KP_PERMISSIONS:
		if (*((DWORD*)(pbData)) >	(CRYPT_ENCRYPT|   
								CRYPT_DECRYPT|   
								CRYPT_EXPORT |   
								CRYPT_READ |  
								CRYPT_WRITE |    
								CRYPT_MAC    ))
		{
			SETLASTERROR(NTE_BAD_FLAGS);
			return FALSE;
		}
		if (((*((DWORD*)(pbData)))&CRYPT_EXPORT)&&(!(m_dwPermissions&CRYPT_EXPORT)))
		{
			SETLASTERROR(NTE_BAD_FLAGS);
			return FALSE;
		}
		m_dwPermissions = *((DWORD*)(pbData));
		break;
	case KP_IV:
		CopyByteToArray(m_arbIv,pbData,m_ulIvLen/8);
		break;
	case KP_PADDING:
		if (*((DWORD*)(pbData)) != PKCS5_PADDING)
		{
			SETLASTERROR(NTE_BAD_FLAGS);
			return FALSE;
		}
		m_dwPadding = *((DWORD*)(pbData));
		break;
	case KP_MODE:
		if (*((DWORD*)(pbData)) > CRYPT_MODE_CFB)
		{
			SETLASTERROR(NTE_BAD_FLAGS);
			return FALSE;
		}
		m_dwMode = *((DWORD*)(pbData));
		break;
	case KP_MODE_BITS:
		m_dwModeBits = *((DWORD*)(pbData));
		break;
	case KP_EFFECTIVE_KEYLEN:
		m_dwEffectiveKeyLen = *((DWORD*)(pbData));
		break;
	default:
		SETLASTERROR(NTE_BAD_TYPE);
		return FALSE;
	}
	
	return TRUE;
}


BOOL CCSPKey::GetParam(
		DWORD dwParam,          // in
		BYTE *pbData,           // out
		DWORD *pdwDataLen,      // in, out
		DWORD dwFlags			// in
		)
{

	if (dwFlags != 0)
	{
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}

	/*if ((m_dwPermissions&CRYPT_READ) == 0)
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}*/
	
	switch (dwParam)
	{
	case KP_ALGID:
		return FillDataBuffer(pbData,pdwDataLen,(BYTE*)(&m_ulAlgId),4);
		break;
	case KP_BLOCKLEN:
		return FillDataBuffer(pbData,pdwDataLen,(BYTE*)(&m_dwBlockLen),4);
		break;
	case KP_KEYLEN:
		return FillDataBuffer(pbData,pdwDataLen,(BYTE*)(&m_ulKeyLen),4);
		break;
	case KP_SALT:
		return FillDataBuffer(pbData,pdwDataLen,m_arbSalt.GetData(),m_ulSaltLen/8);
		break;
	case KP_PERMISSIONS:
		return FillDataBuffer(pbData,pdwDataLen,(BYTE*)(&m_dwPermissions),4);
		break;
	case KP_IV:
		return FillDataBuffer(pbData,pdwDataLen,m_arbIv.GetData(),m_ulIvLen/8);
		break;
	case KP_PADDING:
		return FillDataBuffer(pbData,pdwDataLen,(BYTE*)(&m_dwPadding),4);
		break;
	case KP_MODE:
		return FillDataBuffer(pbData,pdwDataLen,(BYTE*)(&m_dwMode),4);
		break;
	case KP_MODE_BITS:
		return FillDataBuffer(pbData,pdwDataLen,(BYTE*)(&m_dwModeBits),4);
		break;
	case KP_EFFECTIVE_KEYLEN:
		return FillDataBuffer(pbData,pdwDataLen,(BYTE*)(&m_dwEffectiveKeyLen),4);
		break;
	default:
		{
			SETLASTERROR(NTE_BAD_TYPE);
			return FALSE;
		}
	}
	return TRUE;
}

/*BOOL CCSPKey::Duplicate(
		DWORD *pdwReserved,		// in
		DWORD dwFlags,			// in
		CCSPKey * pKey			// out
		)
{
	return TRUE;
}*/

//BOOL CCSPKey::Create(
//		CONST BYTE *pbKeyBlob,			// in
//		DWORD  dwKeyBlobLen			// in
		//BYTE * pbUserAccount /*= NULL*/,	// in
		//DWORD dwUserAccountLen /*= 0*/		// in
//		)
//{
//	return TRUE;
//}*/

/*BOOL CCSPKey::GetKeyBlob(
		DWORD dwBlobType,			// in
		BYTE *pbKeyBlob,			// out
		DWORD *dwKeyBlobLen			// in, out
		//BYTE * pbUserAccount ,	// in
		//DWORD dwUserAccountLen 		// in
		)
{
	return TRUE;
}*/
BOOL CCSPKey::Import(
		CONST BYTE *pbData,     // in
		DWORD  dwDataLen,       // in
		CCSPKey *pPubKey,      // in
		DWORD dwFlags          // in
		)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}
BOOL CCSPKey::DeriveKey(
		DWORD dwBitLen,
		CCSPHashObject* pHash,		// in
		DWORD       dwFlags      // in
		)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}
BOOL CCSPKey::Export(
		CCSPKey *pPubKey,				// in
		DWORD dwBlobType,				// in
		DWORD dwFlags,					// in
		BYTE *pbKeyBlob,				// out
		DWORD *dwKeyBlobLen			// in, out
		)
{
	if ((m_dwPermissions&CRYPT_EXPORT) == 0)
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}
	return TRUE;
}

BOOL CCSPKey::Encrypt(
		CCSPHashObject* pHash,		// in
		BOOL Final,					// in
		DWORD dwFlags,				// in
		BYTE *pbData,				// in, out
		DWORD *pdwDataLen,			// in, out
		DWORD dwBufLen				// in
		)
{
	if ((m_dwPermissions&CRYPT_ENCRYPT) == 0)
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}
	return TRUE;
}

BOOL CCSPKey::Decrypt(
		CCSPHashObject* pHash,			// in
		BOOL Final,						// in
		DWORD dwFlags,					// in
		BYTE *pbData,					// in, out
		DWORD *pdwDataLen				// in, out
		)
{
	if ((m_dwPermissions&CRYPT_DECRYPT) == 0)
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}
	return TRUE;
}



BOOL CCSPKey::SignHash(
		CCSPHashObject* pHash,           // in
		LPCWSTR sDescription,			// in
		DWORD dwFlags,					// in
		BYTE *pbSignature,				// out
		DWORD *pdwSigLen				// in, out
		)
{
	return TRUE;
}

BOOL CCSPKey::VerifySignature(
		CCSPHashObject* hHash,			// in
		CONST BYTE *pbSignature,		// in
		DWORD dwSigLen,					// in
		LPCWSTR sDescription,			// in
		DWORD dwFlags					// in
		)
{
	return TRUE;
}

BOOL CCSPKey::GetKeyMaterial(
		BYTE * pOutData,
		DWORD * dwOutDataLen
		)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}
void CCSPKey::CopyByteToArray(
		byteArray & array,
		BYTE * pData,
		DWORD dwDataLen
		)
{
	array.RemoveAll();
	for (DWORD i=0;i<dwDataLen;i++)
	{
		array.Add(pData[i]);
	}
}


BOOL CCSPKey::FillDataBuffer(
		BYTE *pbData,           // out
		DWORD *pdwDataLen,      // in, out
		BYTE *pbsrcData,
		DWORD dwNeedLen			// in
		)
{
	if (pbData == NULL)
	{
		*pdwDataLen = dwNeedLen;
		return TRUE;
	}
	else if (*pdwDataLen < dwNeedLen)
	{
		*pdwDataLen = dwNeedLen;
		SETLASTERROR(ERROR_MORE_DATA);
		return FALSE;
	}
	memcpy(pbData,pbsrcData,dwNeedLen);
	*pdwDataLen = dwNeedLen;
	return TRUE;
}

BOOL 
CCSPKey::WriteFileEx(
	FILEHANDLE hFile, 
	SHARE_XDF * pXdfRec, 
	ULONG ulUpdateOffset, 
	ULONG ulUpdateLen, 
	BYTE* pNewData, 
	ULONG ulNewDataLen, 
	ULONG ulFileLen
	)
{
	BYTE* pOldData = pXdfRec->cContent;
	ULONG ulOldDataLen = pXdfRec->ulDataLen;
	ULONG ulDataLen = 0;
	if (pNewData == NULL)
		ulNewDataLen = 0;

	//不需要挪动
	if (ulUpdateLen == ulNewDataLen)
	{
		//比较内容的异同
		for (ULONG i =0;i<ulNewDataLen;i++)
		{
			if (pOldData[ulUpdateOffset+i] != pNewData[i])
				break;
		}
		if (i < ulNewDataLen)
		{
			BOOL rv = GetCSPObject()->WriteFile(hFile, pNewData+i, ulNewDataLen-i, ulUpdateOffset+i);
			if (rv == TRUE)
			{
				//修改内存中的df映象
				memcpy(pOldData+ulUpdateOffset+i,pNewData+i,ulNewDataLen-i);
			}
			return rv;
		}
		else 
			return TRUE;
	}
	
	ulDataLen = (ulNewDataLen>ulUpdateLen?ulNewDataLen:ulUpdateLen)
				+ulOldDataLen-(ulUpdateOffset+ulUpdateLen);
	if (ulDataLen+ulUpdateOffset > ulFileLen)
	{
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}
		

	ULONG tmpLen = ulDataLen
		+ (2>ulFileLen-ulDataLen-ulUpdateOffset?ulFileLen-ulDataLen-ulUpdateOffset:2);
	BYTE* pData = new BYTE[tmpLen];
	memset(pData,0x00,tmpLen);
	if (ulNewDataLen)
		memcpy(pData,pNewData,ulNewDataLen);
	memcpy(pData+ulNewDataLen,
			pOldData+ulUpdateOffset+ulUpdateLen,
			ulOldDataLen-(ulUpdateOffset+ulUpdateLen));
	//后面的补0
	ulOldDataLen = ulNewDataLen+ulOldDataLen-ulUpdateLen;
	/*if (ulNewDataLen<ulUpdateLen)
		memset(pData+ulOldDataLen-ulUpdateOffset,
				0x00,ulUpdateLen-ulNewDataLen);*/
	BOOL rv =GetCSPObject()->WriteFile(hFile, pData,tmpLen,ulUpdateOffset);
	if (rv == TRUE)
	{
		//修改内存中的df映象
		memcpy(pOldData+ulUpdateOffset,pData,tmpLen);
		pXdfRec->ulDataLen = ulOldDataLen;
	}
	delete pData;
	return rv;
}

void CCSPKey::SetIndex(ULONG ulIndex)
{
	m_ulIndex = ulIndex;
}
ULONG CCSPKey::GetIndex()
{
	return m_ulIndex;
}

void CCSPKey::SwapInt(
		BYTE * pInt,
		DWORD dwLen
		)
{
	BYTE tmp;
	for (DWORD i = 0; i<dwLen/2; i++)
	{
		tmp = pInt[i];
		pInt[i] = pInt[dwLen-1-i];
		pInt[dwLen-1-i] = tmp;
	}
}

void CCSPKey::CreatebyBlob(
		BYTE * pBlob,
		DWORD dwBlobLen
		)
{
}

BOOL CCSPKey::ReadRealObject(
		)
{
	if (m_bToken)
		return m_RealObjReaded;
	else
		return TRUE;
}