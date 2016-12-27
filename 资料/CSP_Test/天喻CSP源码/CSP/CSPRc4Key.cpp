//CSPRc4Key.cpp

#include <stdAfx.h>
#include "cspkey.h" 
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


#define SK_LOOP(n) \
{ \
	tmp=d[(n)]; \
	id2 = (data[id1] + tmp + id2) & 0xff; \
	if (++id1 == len) \
		id1=0; \
	d[(n)]=d[id2]; \
	d[id2]=tmp; \
}

#define LOOP(in,out) \
		x=((x+1)&0xff); \
		tx=d[x]; \
		y=(tx+y)&0xff; \
		d[x]=ty=d[y]; \
		d[y]=tx; \
		(out) = d[(tx+ty)&0xff]^ (in);

#define RC4_LOOP(a,b,i)	LOOP(a[i],b[i])



CCSPRc4Key::CCSPRc4Key(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	/*= FALSE*/
		//BOOL bExtractable /*= TRUE*/,
		//BOOL bPrivate /*= FALSE*/
		):CCSPSymmetricalKey(pKeyContainer, ulAlgId,bToken/*,bExtractable,bPrivate*/)
{
	m_dwBlockLen = 0;
	m_ulKeyLen = RC4_DEFAULT_LEN;
	m_dwEffectiveKeyLen = 0;
	//m_pRC2Encryption = NULL;
	//m_pRC2Decryption = NULL;
	for (int i=0;i<m_dwBlockLen/8;i++)
		m_arbIv.Add(0x00);

	m_x = 0;
	m_y = 0;
	for (i=0; i<256; i++)
		m_pData[i] = i;
}

CCSPRc4Key::CCSPRc4Key(
		CCSPRc4Key &src
		) :CCSPSymmetricalKey(src)
{
	m_x = src.m_x;
	m_y = src.m_y;
	for (int i=0;i<256;i++)
		m_pData[i] = src.m_pData[i];
}

	//析构函数
CCSPRc4Key::~CCSPRc4Key()
{
	/*if (m_bFinished = FALSE)
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
	}*/
	CCSPSymmetricalKey::~CCSPSymmetricalKey();
}


BOOL CCSPRc4Key::Create(
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
		m_ulSaltLen = RC4_DEFAULT_LEN - bitlen;
	}
	BOOL bRet = CCSPSymmetricalKey::Create(bitlen,dwFlags);
	if (bRet == FALSE)
		return FALSE;

	//init the key
	ResetKey();
	return TRUE;
}


BOOL CCSPRc4Key::SetParam(
	DWORD dwParam,           // in
	BYTE *pbData,            // in
	DWORD dwFlags            // in
	)
{
	//只支持CRYPT_MODE_ECB、CRYPT_MODE_CBC
	if (dwParam==KP_MODE)
	{
		DWORD mode = *((DWORD*)pbData);
		if (mode!=CRYPT_MODE_OFB)
		{
			SETLASTERROR(NTE_BAD_FLAGS);
			return FALSE;
		}
	}
	return CCSPSymmetricalKey::SetParam(dwParam,pbData,dwFlags);
}


BOOL CCSPRc4Key::DeriveKey(
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
		m_ulSaltLen = RC4_DEFAULT_LEN - m_ulKeyLen;
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

BOOL CCSPRc4Key::Import(
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

	BYTE KeyContent[RC4_DEFAULT_LEN/8];
	memset(KeyContent,0,RC4_DEFAULT_LEN/8);
	memcpy(KeyContent,tmp+sizeof(BLOBHEADER)+sizeof(ALG_ID),tmpLen);
	m_ulKeyLen = tmpLen*8;
	m_ulSaltLen = RC4_DEFAULT_LEN - m_ulKeyLen;
	if (dwFlags & CRYPT_NO_SALT)
	{
		m_ulSaltLen = 0;
	}
	m_dwFlags = dwFlags;
	m_dwPermissions |= ((dwFlags&CRYPT_EXPORTABLE)?CRYPT_EXPORT:0);
	CreatebyBlob(KeyContent,(m_ulKeyLen+m_ulSaltLen)/8);
	//init the key
	ResetKey();
	return TRUE;
}

BOOL CCSPRc4Key::Export(
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
	DWORD keyLen = m_arbKeyContent.GetSize();
	BYTE * tmp = new BYTE[tmpLen];
	memcpy(tmp,m_arbKeyContent.GetData(),keyLen);
	BOOL bRet = pPubKey->Encrypt(NULL,TRUE,NULL,tmp,&keyLen,tmpLen);
	if (bRet == FALSE)
	{
		delete tmp;
		return FALSE;
	}
		
	memcpy(pbKeyBlob+sizeof(BLOBHEADER)+sizeof(DWORD),tmp,keyLen);
	delete tmp;

	*dwKeyBlobLen = keyLen + sizeof(BLOBHEADER) + sizeof(DWORD);

	BLOBHEADER bh;
	bh.bType = dwBlobType;
	bh.bVersion = DEFAULT_BLOB_VERSION;
	bh.reserved = NULL;
	bh.aiKeyAlg = m_ulAlgId;

	memcpy(pbKeyBlob,(BYTE *)(&bh),sizeof(BLOBHEADER));
	*((DWORD *)(pbKeyBlob+sizeof(BLOBHEADER))) = pPubKey->GetAlgId();

	return TRUE;
}

BOOL CCSPRc4Key::Encrypt(
	CCSPHashObject* pHash,		// in
	BOOL Final,					// in
	DWORD dwFlags,				// in
	BYTE *pbData,				// in, out
	DWORD *pdwDataLen,			// in, out
	DWORD dwBufLen				// in
	)
{
	DWORD dwBlockByteLen = m_dwBlockLen/8;

	if((NULL == pHash) && (NULL == pbData))
	{
		//Only return length
		if(Final)
		{
			*pdwDataLen = ((*pdwDataLen / dwBlockByteLen) + 1) *dwBlockByteLen;
			return TRUE;
		}
		if((*pdwDataLen % dwBlockByteLen) != 0)
		{
			SETLASTERROR(NTE_BAD_LEN);
			return FALSE;
		}
		return TRUE;
	}

	if (dwFlags != 0)
	{
		SETLASTERROR(NTE_BAD_FLAGS);
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

	if (*pdwDataLen == 0)
		return TRUE;

	if (m_bFinished)
	{
		ResetKey();
	}

	if ((m_dwMode == CRYPT_MODE_OFB)||(m_dwMode == 0))
	{
		BYTE *pbOutData = new BYTE[*pdwDataLen];
		Crypt(*pdwDataLen,pbData,pbOutData);
		memcpy(pbData,pbOutData,*pdwDataLen);
		delete pbOutData;
	}
	else
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	m_bFinished = FALSE;

	if (Final)
	{
		m_bFinished = TRUE;
	}
	return TRUE;	
}
BOOL CCSPRc4Key::Decrypt(
	CCSPHashObject* pHash,			// in
	BOOL Final,						// in
	DWORD dwFlags,					// in
	BYTE *pbData,					// in, out
	DWORD *pdwDataLen				// in, out
	)
{
	BOOL bRet = TRUE;

	if ((pbData == NULL)||(*pdwDataLen == 0))
		return TRUE;

	if (dwFlags != 0)
	{
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}

	if (m_bFinished)
	{
		ResetKey();
	}
	

	m_bFinished = FALSE;

	BYTE *pbOutData = new BYTE[*pdwDataLen];
	Crypt(*pdwDataLen,pbData,pbOutData);
	memcpy(pbData,pbOutData,*pdwDataLen);
	delete pbOutData;

	if (Final)
	{
		m_bFinished = TRUE;
	}

	if (pHash != NULL)
	{
		//need hash 
		bRet = pHash->HashData(pbData,*pdwDataLen,NULL);
	}
	return bRet;
}

void CCSPRc4Key::Crypt(
		ULONG len,
		CONST BYTE *indata,
		BYTE *outdata
		)
{
	register UINT *d;
	register UINT x,y,tx,ty;
	int i;

	x=m_x;     
	y=m_y;     
	d=m_pData;
	
	i=(int)(len>>3L);
	if (i)
	{
		for (;;)
		{
			RC4_LOOP(indata,outdata,0);
			RC4_LOOP(indata,outdata,1);
			RC4_LOOP(indata,outdata,2);
			RC4_LOOP(indata,outdata,3);
			RC4_LOOP(indata,outdata,4);
			RC4_LOOP(indata,outdata,5);
			RC4_LOOP(indata,outdata,6);
			RC4_LOOP(indata,outdata,7);

			indata+=8;
			outdata+=8;

			if (--i == 0)
				break;
		}
	}
	i=(int)len&0x07;
	if (i)
	{
		for (;;)
		{
			RC4_LOOP(indata,outdata,0); if (--i == 0) break;
			RC4_LOOP(indata,outdata,1); if (--i == 0) break;
			RC4_LOOP(indata,outdata,2); if (--i == 0) break;
			RC4_LOOP(indata,outdata,3); if (--i == 0) break;
			RC4_LOOP(indata,outdata,4); if (--i == 0) break;
			RC4_LOOP(indata,outdata,5); if (--i == 0) break;
			RC4_LOOP(indata,outdata,6); if (--i == 0) break;
		}
	}               
	m_x=x;     
	m_y=y;
}

void CCSPRc4Key::ResetKey()
{
	m_x = 0;
	m_y = 0;
	for (unsigned int i=0; i<256; i++)
		m_pData[i] = i;
	register UINT tmp;
	register int id1,id2;
	register UINT *d;
	d = m_pData;
	BYTE * data = m_arbKeyContent.GetData();
	int len = m_arbKeyContent.GetSize();

	id1=id2=0;     

	for (i=0; i < 256; i+=4)
	{
		SK_LOOP(i+0);
		SK_LOOP(i+1);
		SK_LOOP(i+2);
		SK_LOOP(i+3);
	}
}