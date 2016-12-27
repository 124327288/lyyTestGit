//CSPRc2Key.cpp

#include <stdAfx.h>
#include "cspkey.h" 

CCSPRc2Key::CCSPRc2Key(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	/*= FALSE*/
		//BOOL bExtractable /*= TRUE*/,
		//BOOL bPrivate /*= FALSE*/
		):CCSPSymmetricalKey(pKeyContainer, ulAlgId,bToken/*,bExtractable,bPrivate*/)
{
	m_dwBlockLen = 64;
	m_ulKeyLen = RC2_DEFAULT_LEN;
	//m_dwEffectiveKeyLen = m_ulKeyLen;
	m_dwEffectiveKeyLen = RC2_DEF_EFF_LEN;
	m_pRC2Encryption = NULL;
	m_pRC2Decryption = NULL;
	m_ulIvLen = m_dwBlockLen;
	for (int i=0;i<m_dwBlockLen/8;i++)
		m_arbIv.Add(0x00);
}

CCSPRc2Key::CCSPRc2Key(
		CCSPRc2Key &src
		) :CCSPSymmetricalKey(src)
{

}

	//析构函数
CCSPRc2Key::~CCSPRc2Key()
{
//	if (m_bFinished == FALSE)
	{
		if (m_pRC2Encryption)
		{
			delete m_pRC2Encryption;
			m_pRC2Encryption = NULL;
		}
		if (m_pRC2Decryption)
		{
			delete m_pRC2Decryption;
			m_pRC2Decryption = NULL;
		}
	}
	CCSPSymmetricalKey::~CCSPSymmetricalKey();
}


//Create the object on the card
BOOL CCSPRc2Key::CreateOnToken(
	ULONG ulIndex
	)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}

//Destroy the object on the card
BOOL CCSPRc2Key::DestroyOnToken()
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}

BOOL CCSPRc2Key::LoadFromToken(
	//BYTE* DEREncodedStr,
	//ULONG ulDEREncodedStrLen,
	ULONG ulIndex
	)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}

BOOL CCSPRc2Key::Create(
		DWORD bitlen,
		DWORD dwFlags
		)
{
	if (bitlen%8 != 0)
	{
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}
	if (m_dwFlags &CRYPT_NO_SALT)
	{
		m_ulSaltLen = 0;
	}
	else
	{
		m_ulSaltLen = RC2_DEFAULT_LEN - bitlen;
	}
	return CCSPSymmetricalKey::Create(bitlen,dwFlags);
}


BOOL CCSPRc2Key::SetParam(
	DWORD dwParam,           // in
	BYTE *pbData,            // in
	DWORD dwFlags            // in
	)
{
	//只支持CRYPT_MODE_ECB、CRYPT_MODE_CBC
	if (dwParam==KP_MODE)
	{
		DWORD mode = *((DWORD*)pbData);
		if ((mode!=CRYPT_MODE_ECB)&&(mode!=CRYPT_MODE_CBC))
		{
			SETLASTERROR(NTE_BAD_FLAGS);
			return FALSE;
		}
	}
	return CCSPSymmetricalKey::SetParam(dwParam,pbData,dwFlags);
}
BOOL CCSPRc2Key::GetParam(
	DWORD dwParam,          // in
	BYTE *pbData,           // out
	DWORD *pdwDataLen,      // in, out
	DWORD dwFlags			// in
	)
{
	return CCSPSymmetricalKey::GetParam(dwParam,pbData,pdwDataLen,dwFlags);
}
/*BOOL CCSPRc2Key::Duplicate(
	DWORD *pdwReserved,		// in
	DWORD dwFlags,			// in
	CCSPKey * pKey			// out
	)

{
	return TRUE;
}*/
/*BOOL CCSPRc2Key::GetKeyBlob(
	DWORD dwBlobType,			// in
	BYTE *pbKeyBlob,			// out
	DWORD *dwKeyBlobLen			// in, out
	)
{
	return TRUE;
}*/
BOOL CCSPRc2Key::DeriveKey(
		DWORD dwBitLen,
		CCSPHashObject* pHash,		// in
		DWORD       dwFlags      // in
		)
{
	
	if (dwFlags > (CRYPT_EXPORTABLE|
		CRYPT_CREATE_SALT
		|CRYPT_NO_SALT|
		CRYPT_USER_PROTECTED)
		)
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}
	if (pHash == NULL)
	{
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	m_dwFlags = dwFlags;
	m_dwPermissions |= ((dwFlags&CRYPT_EXPORTABLE)?CRYPT_EXPORT:0);
	m_ulKeyLen = dwBitLen;

	if (dwFlags&CRYPT_NO_SALT)
	{
		m_ulSaltLen = 0;
	}
	else
	{
		m_ulSaltLen = RC2_DEFAULT_LEN - m_ulKeyLen;
	}

	DWORD tmpLen;
	BOOL bRet = pHash->GetValue(NULL,&tmpLen);
	if (bRet == FALSE)
		return FALSE;
	if (tmpLen < m_ulKeyLen/8+m_ulSaltLen/8)
	{
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	BYTE * tmp = new BYTE[tmpLen];
	bRet = pHash->GetValue(tmp,&tmpLen);
	if (bRet == FALSE)
	{
		delete tmp;
		return FALSE;
	}
		

	if (dwFlags&CRYPT_CREATE_SALT == 0)
	{
		memset(tmp+m_ulKeyLen/8,0,m_ulSaltLen/8);
	}

	CreatebyBlob(tmp,m_ulKeyLen/8+m_ulSaltLen/8);
	delete tmp;
	return TRUE;
}

BOOL CCSPRc2Key::Import(
		CONST BYTE *pbData,     // in
		DWORD  dwDataLen,       // in
		CCSPKey *pPubKey,      // in
		DWORD dwFlags          // in
		)
{
	if (pPubKey == NULL)
	{
		SETLASTERROR(NTE_NO_KEY);
		return FALSE;
	}
	if (dwDataLen != sizeof(BLOBHEADER)+ sizeof(ALG_ID)+pPubKey->GetBlockLen()/8)
	{
		SETLASTERROR(NTE_BAD_DATA);
		return FALSE;
	}
	BYTE * tmp = new BYTE[dwDataLen];
	memcpy(tmp,pbData,dwDataLen);

	BLOBHEADER *bh = (BLOBHEADER*)pbData;
	if(bh->bType != SIMPLEBLOB)
	{
		SETLASTERROR(NTE_BAD_TYPE);
		return FALSE;
	}
	
	pbData += sizeof(BLOBHEADER);

	//decrypt the data
	DWORD tmpLen = dwDataLen - sizeof(BLOBHEADER) - sizeof(ALG_ID);
	BOOL bRet = pPubKey->Decrypt(NULL,TRUE,NULL,
		tmp+sizeof(BLOBHEADER)+sizeof(ALG_ID),
		&tmpLen);
	if (bRet == FALSE)
		return FALSE;

	BYTE KeyContent[RC2_DEFAULT_LEN];
	memset(KeyContent,0,RC2_DEFAULT_LEN);
	memcpy(KeyContent,tmp+sizeof(BLOBHEADER)+sizeof(ALG_ID),tmpLen);
	m_ulKeyLen = tmpLen*8;
	m_ulSaltLen = RC2_DEFAULT_LEN - m_ulKeyLen;
	if (dwFlags & CRYPT_NO_SALT)
	{
		m_ulSaltLen = 0;
	}
	m_dwFlags = dwFlags;
	m_dwPermissions |= ((dwFlags&CRYPT_EXPORTABLE)?CRYPT_EXPORT:0);
	//m_dwEffectiveKeyLen = m_ulKeyLen+m_ulSaltLen;
	m_dwEffectiveKeyLen = RC2_DEF_EFF_LEN;
	CreatebyBlob(KeyContent,(m_ulKeyLen+m_ulSaltLen)/8);
	return TRUE;
}

BOOL CCSPRc2Key::Export(
	CCSPKey *pPubKey,				// in
	DWORD dwBlobType,				// in
	DWORD dwFlags,					// in
	BYTE *pbKeyBlob,				// out
	DWORD *dwKeyBlobLen			// in, out
	)
{
	if (pPubKey == NULL)
	{
		SETLASTERROR(NTE_NO_KEY);
		return FALSE;
	}
	if (dwBlobType != SIMPLEBLOB)
	{
		SETLASTERROR(NTE_BAD_TYPE);
		return FALSE;
	}
	if ((m_dwPermissions&CRYPT_EXPORT) == 0)
	{
		SETLASTERROR(NTE_BAD_KEY_STATE);
		return FALSE;
	}

	DWORD tmpLen;
	DWORD NeedLen;
	if (pPubKey != NULL)
	{
		tmpLen = pPubKey->GetBlockLen()/8;
	}
	else
	{
		tmpLen = 0;
	}
	NeedLen = tmpLen +(sizeof(BLOBHEADER) + sizeof(DWORD));

	
	if (pbKeyBlob == NULL)
	{
		*dwKeyBlobLen = NeedLen;
		return TRUE;
	}
	
	if (*dwKeyBlobLen < NeedLen)
	{
		*dwKeyBlobLen = NeedLen;
		SETLASTERROR(ERROR_MORE_DATA);
		return FALSE;
	}

	//encrypt the key
	DWORD keylen = m_arbKeyContent.GetSize();
	BYTE * tmp = new BYTE[tmpLen];
	memcpy(tmp,m_arbKeyContent.GetData(),keylen);
	BOOL bRet = pPubKey->Encrypt(NULL,TRUE,NULL,tmp,&keylen,tmpLen);
	if (bRet == FALSE)
	{
		delete tmp;
		return FALSE;
	}
	memcpy(pbKeyBlob+sizeof(BLOBHEADER)+sizeof(DWORD),tmp,keylen);
	delete tmp;

	*dwKeyBlobLen = keylen + sizeof(BLOBHEADER) + sizeof(DWORD);

	BLOBHEADER bh;
	bh.bType = dwBlobType;
	bh.bVersion = DEFAULT_BLOB_VERSION;
	bh.reserved = NULL;
	bh.aiKeyAlg = m_ulAlgId;

	memcpy(pbKeyBlob,(BYTE *)(&bh),sizeof(BLOBHEADER));
	*((DWORD *)(pbKeyBlob+sizeof(BLOBHEADER))) = pPubKey->GetAlgId();

	return TRUE;
}


BOOL CCSPRc2Key::Encrypt(
	CCSPHashObject* pHash,		// in
	BOOL Final,					// in
	DWORD dwFlags,				// in
	BYTE *pbData,				// in, out
	DWORD *pdwDataLen,			// in, out
	DWORD dwBufLen				// in
	)
{
	if(*pdwDataLen == 0)
	{
		if(!Final)
			return TRUE;
		if(pbData == NULL)
		{
			*pdwDataLen = m_dwBlockLen/8;
			return TRUE;
		}
	}


	if (dwFlags != 0)
	{
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}
	

	if (dwBufLen < m_dwBlockLen/8)
	{
		SETLASTERROR(NTE_BAD_LEN);
		return FALSE;
	}

	BOOL bRet;

	
	if (pHash != NULL)
	{
		//need hash 
		bRet = pHash->HashData(pbData,*pdwDataLen,NULL);
		if (bRet = FALSE)
			return FALSE;
	}
	if ((*pdwDataLen % (m_dwBlockLen/8)!= 0)&&(Final == FALSE))
	{
		SETLASTERROR(NTE_BAD_DATA);
		return FALSE;
	}

	if (/*m_bFinished*/m_pRC2Encryption == NULL)
	{
		m_pRC2Encryption = new RC2Encryption(m_arbKeyContent.GetData(),
			(m_ulKeyLen+m_ulSaltLen)/8,m_dwEffectiveKeyLen);
	}

	if (m_dwMode == CRYPT_MODE_ECB)
	{
		if (dwBufLen < (*pdwDataLen+8)/8*8)
		{
			SETLASTERROR(NTE_BAD_LEN);
			return FALSE;
		}
		
		if(Final)
		{
			BYTE pad = m_dwBlockLen/8 - (*pdwDataLen%8);
			for (BYTE j=0;j<pad;j++)
				pbData[*pdwDataLen+j] = pad;

			*pdwDataLen = (*pdwDataLen+8)/8*8;
		}

		for (DWORD i=0;i<(*pdwDataLen);i+=m_dwBlockLen/8)
		{
			m_pRC2Encryption->ProcessBlock(pbData+i);
		}
	}
	else if ((m_dwMode == CRYPT_MODE_CBC)||(m_dwMode == 0))
	{
		if (/*m_bFinished*/m_pCBCPaddedEncryptor == NULL)
		{
			m_pCBCPaddedEncryptor = new CBCPaddedEncryptor(*m_pRC2Encryption,
				m_arbIv.GetData());
		}
		m_pCBCPaddedEncryptor->Put(pbData,*pdwDataLen);
		if (Final)
		{
			m_pCBCPaddedEncryptor->InputFinished();
		}
		DWORD tmpLen = m_pCBCPaddedEncryptor->MaxRetrieveable();
		BYTE * tmp = new BYTE[tmpLen];
		tmpLen = m_pCBCPaddedEncryptor->Get(tmp,tmpLen);
		if (dwBufLen < tmpLen)
		{
			delete tmp;
			SETLASTERROR(NTE_BAD_LEN);
			return FALSE;
		}
		*pdwDataLen = tmpLen;
		memcpy(pbData,tmp,tmpLen);
		delete tmp;
		//update the IV
		//CopyByteToArray(m_arbIv,pbData,*pdwDataLen);
	}
	else
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	m_bFinished = FALSE;

	if (Final)
	{
		if (m_pRC2Encryption)
		{
			delete m_pRC2Encryption;
			m_pRC2Encryption = NULL;
		}
		if (m_pCBCPaddedEncryptor)
		{
			delete m_pCBCPaddedEncryptor;
			m_pCBCPaddedEncryptor = NULL;
		}
		m_bFinished = TRUE;
	}
	return TRUE;	
}
BOOL CCSPRc2Key::Decrypt(
	CCSPHashObject* pHash,			// in
	BOOL Final,						// in
	DWORD dwFlags,					// in
	BYTE *pbData,					// in, out
	DWORD *pdwDataLen				// in, out
	)
{
	BOOL bRet = TRUE;

	/*if ((m_dwPermissions&CRYPT_DECRYPT) == 0)
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}*/

	if ((pbData == NULL)||(*pdwDataLen == 0))
		return TRUE;

	if (dwFlags != 0)
	{
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}
	
	if (*pdwDataLen % (m_dwBlockLen/8) != 0)
	{
		SETLASTERROR(NTE_BAD_DATA);
		return FALSE;
	}

	
	

	if (/*m_bFinished*/m_pRC2Decryption == NULL)
	{
		m_pRC2Decryption = new RC2Decryption(m_arbKeyContent.GetData(),
			(m_ulKeyLen+m_ulSaltLen)/8,m_dwEffectiveKeyLen);
	}

	if (m_dwMode == CRYPT_MODE_ECB)
	{
		/*if (*pdwDataLen % (m_dwBlockLen/8) != 0)
		{
			SETLASTERROR(NTE_BAD_DATA);
			return FALSE;
		}
		if (dwBufLen < (*pdwDataLen+7)/8*8)
		{
			SETLASTERROR(NTE_BAD_LEN);
			return FALSE;
		}*/

		for (DWORD i=0;i<*pdwDataLen;i+=m_dwBlockLen/8)
		{
			m_pRC2Decryption->ProcessBlock(pbData+i);
		}
		
		BYTE pad = pbData[*pdwDataLen-1];
		if ((pad > 8)||(pad == 0))
		{
			SETLASTERROR(NTE_BAD_DATA);
			return FALSE;
		}
		for (BYTE j=0; j<pad; j++)
		{
			if(pbData[*pdwDataLen-1-j]!=pad)
			{
				SETLASTERROR(NTE_BAD_DATA);
				return FALSE;
			}
		}
		*pdwDataLen -= pad;
		//*pdwDataLen = (*pdwDataLen+7)/8*8;
	}
	else if ((m_dwMode == CRYPT_MODE_CBC)||(m_dwMode == 0))
	{
		if (/*m_bFinished*/m_pCBCPaddedDecryptor == NULL)
		{
			m_pCBCPaddedDecryptor = new CBCPaddedDecryptor(*m_pRC2Decryption,
				m_arbIv.GetData());
		}
		m_pCBCPaddedDecryptor->Put(pbData,*pdwDataLen);
		if (Final)
		{
			m_pCBCPaddedDecryptor->InputFinished();
		}
		DWORD tmpLen = m_pCBCPaddedDecryptor->MaxRetrieveable();
		BYTE * tmp = new BYTE[tmpLen];
		tmpLen = m_pCBCPaddedDecryptor->Get(tmp,tmpLen);
		/*if (dwBufLen < tmpLen)
		{
			SETLASTERROR(NTE_BAD_LEN);
			return FALSE;
		}*/
		/*if (*pdwDataLen == tmpLen)
		{
			delete tmp;
			SETLASTERROR(NTE_BAD_DATA);
			return FALSE;
		}*/
		*pdwDataLen = tmpLen;
		memcpy(pbData,tmp,tmpLen);
		delete tmp;
		//update the IV
		//CopyByteToArray(m_arbIv,pbData,*pdwDataLen);
	}
	else
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	m_bFinished = FALSE;

	if (Final)
	{
		if (m_pRC2Decryption)
		{
			delete m_pRC2Decryption;
			m_pRC2Decryption = NULL;
		}
		if (m_pCBCPaddedDecryptor)
		{
			delete m_pCBCPaddedDecryptor;
			m_pCBCPaddedDecryptor = NULL;
		}
		
		m_bFinished = TRUE;
	}

	if (pHash != NULL)
	{
		//need hash 
		bRet = pHash->HashData(pbData,*pdwDataLen,NULL);
	}
	return bRet;
}

BOOL CCSPRc2Key::SignHash(
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
BOOL CCSPRc2Key::VerifySignature(
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
