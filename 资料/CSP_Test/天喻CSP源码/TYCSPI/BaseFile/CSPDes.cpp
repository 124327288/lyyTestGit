//CSPDes.cpp


#include "stdAfx.h"
#include "cspkey.h" 

#ifndef CSPDES_CPP
#define CSPDES_CPP

template <class E,class D>
CCSPDesTmpl<E,D>::CCSPDesTmpl(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	/*= FALSE*/
		//BOOL bExtractable /*= TRUE*/,
		//BOOL bPrivate /*= FALSE*/
		):CCSPSymmetricalKey(pKeyContainer, ulAlgId,bToken/*,bExtractable,bPrivate*/)
{
	m_dwBlockLen = E::BLOCKSIZE*8;
	m_ulKeyLen = D::KEYLENGTH*8;
	m_dwEffectiveKeyLen = m_ulKeyLen;
	m_pDESEncryption = NULL;
	m_pDESDecryption = NULL;
	m_ulIvLen = m_dwBlockLen;
	for (int i=0;i<m_dwBlockLen/8;i++)
		m_arbIv.Add(0x00);
}

template <class E,class D>
CCSPDesTmpl<E,D>::CCSPDesTmpl(
		CCSPDesTmpl &src
		) :CCSPSymmetricalKey(src)
{

}

	//析构函数
template <class E,class D>
CCSPDesTmpl<E,D>::~CCSPDesTmpl()
{
//	if (m_bFinished == FALSE)
	{
		if (m_pDESEncryption)
		{
			delete m_pDESEncryption;
			m_pDESEncryption = NULL;
		}
		if (m_pDESDecryption)
		{
			delete m_pDESDecryption;
			m_pDESDecryption = NULL;
		}

	}
	CCSPSymmetricalKey::~CCSPSymmetricalKey();
}

template <class E,class D>
BOOL CCSPDesTmpl<E,D>::Create(
		DWORD bitlen,
		DWORD dwFlags
		)
{
	if (bitlen%64 != 0)
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
		m_ulSaltLen = E::KEYLENGTH*8 - bitlen;
	}
	return CCSPSymmetricalKey::Create(bitlen,dwFlags);
}

template <class E,class D>
BOOL CCSPDesTmpl<E,D>::SetParam(
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
template <class E,class D>
BOOL CCSPDesTmpl<E,D>::DeriveKey(
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
		m_ulSaltLen = (E::KEYLENGTH*8) - m_ulKeyLen;
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
template <class E,class D>
BOOL CCSPDesTmpl<E,D>::Import(
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

	BYTE KeyContent[E::KEYLENGTH];
	memset(KeyContent,0,E::KEYLENGTH);
	memcpy(KeyContent,tmp+sizeof(BLOBHEADER)+sizeof(ALG_ID),tmpLen);
	m_ulKeyLen = tmpLen*8;
	m_ulSaltLen = (E::KEYLENGTH*8) - m_ulKeyLen;
	if (dwFlags & CRYPT_NO_SALT)
	{
		m_ulSaltLen = 0;
	}
	m_dwFlags = dwFlags;
	m_dwPermissions |= ((dwFlags&CRYPT_EXPORTABLE)?CRYPT_EXPORT:0);
	m_dwEffectiveKeyLen = m_ulKeyLen+m_ulSaltLen;
	CreatebyBlob(KeyContent,(m_ulKeyLen+m_ulSaltLen)/8);
	return TRUE;
}
template <class E,class D>
BOOL CCSPDesTmpl<E,D>::Export(
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
template <class E,class D>
BOOL CCSPDesTmpl<E,D>::Encrypt(
	CCSPHashObject* pHash,		// in
	BOOL Final,					// in
	DWORD dwFlags,				// in
	BYTE *pbData,				// in, out
	DWORD *pdwDataLen,			// in, out
	DWORD dwBufLen				// in
	)
{
	DWORD dwBlockByteLen = m_dwBlockLen/8;

	if(*pdwDataLen == 0)
	{
		if(!Final)
			return TRUE;
		if(pbData == NULL)
		{
			*pdwDataLen = dwBlockByteLen;
			return TRUE;
		}
	}
	

	if (dwFlags != 0)
	{
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}
	

	if (dwBufLen < dwBlockByteLen)
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
	
	//不需要hash时
	if ((*pdwDataLen % dwBlockByteLen!= 0)&&(Final == FALSE))
	{
		SETLASTERROR(NTE_BAD_DATA);
		return FALSE;
	}
	
	if (/*m_bFinished*/m_pDESEncryption == NULL)
	{
		m_pDESEncryption = new E(m_arbKeyContent.GetData());
	}

	if (m_dwMode == CRYPT_MODE_ECB)
	{
		DWORD dwRespLen = *pdwDataLen;
		if(Final)
			dwRespLen = (*pdwDataLen+dwBlockByteLen)/dwBlockByteLen*dwBlockByteLen;

		if (dwBufLen < dwRespLen)
		{
			SETLASTERROR(NTE_BAD_LEN);
			return FALSE;
		}
		if(Final)
		{
			BYTE pad = dwBlockByteLen - (*pdwDataLen%dwBlockByteLen);
			for (BYTE j=0;j<pad;j++)
				pbData[*pdwDataLen+j] = pad;
			*pdwDataLen = dwRespLen;
		}

		for (DWORD i=0;	i<dwRespLen; i+=dwBlockByteLen)
		{
			m_pDESEncryption->ProcessBlock(pbData+i);
		}
	}
	else if ((m_dwMode == CRYPT_MODE_CBC)||(m_dwMode == 0))
	{
		if (/*m_bFinished*/m_pCBCPaddedEncryptor == NULL)
		{
			m_pCBCPaddedEncryptor = new CBCPaddedEncryptor(*m_pDESEncryption,
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
		if (m_pDESEncryption)
		{
			delete m_pDESEncryption;
			m_pDESEncryption = NULL;
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
template <class E,class D>
BOOL CCSPDesTmpl<E,D>::Decrypt(
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

	DWORD dwBlockByteLen = m_dwBlockLen/8;
	if ((pbData == NULL)||(*pdwDataLen == 0))
		return TRUE;

	if (dwFlags != 0)
	{
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}
	
	if (*pdwDataLen % dwBlockByteLen != 0)
	{
		SETLASTERROR(NTE_BAD_DATA);
		return FALSE;
	}

	
	

	if (/*m_bFinished*/m_pDESDecryption == NULL)
	{
		m_pDESDecryption = new D(m_arbKeyContent.GetData());
	}

	if (m_dwMode == CRYPT_MODE_ECB)
	{

		for (DWORD i=0;i<*pdwDataLen;i+=dwBlockByteLen)
		{
			m_pDESDecryption->ProcessBlock(pbData+i);
		}
		
		if(Final)
		{
			BYTE pad = pbData[*pdwDataLen-1];
			if ((pad > dwBlockByteLen)||(pad == 0))
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
		}
	}
	else if ((m_dwMode == CRYPT_MODE_CBC)||(m_dwMode == 0))
	{
		if (/*m_bFinished*/m_pCBCPaddedDecryptor == NULL)
		{
			m_pCBCPaddedDecryptor = new CBCPaddedDecryptor(*m_pDESDecryption,
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
		if (m_pDESDecryption)
		{
			delete m_pDESDecryption;
			m_pDESDecryption = NULL;
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

#endif

