//CSPSSF33.cpp


#include "stdAfx.h"
#include "cspkey.h" 
#include "cardtrans.h"

CCSPSSF33Key::CCSPSSF33Key():CCSPSSF33Base()
{
}



CCSPSSF33Key::CCSPSSF33Key(
			 CCSPKeyContainer* pKeyContainer,
			 ULONG ulAlgId,
			 BOOL bToken	// = FALSE
			 //BOOL bExtractable = TRUE,
			 //BOOL bPrivate = FALSE
			 ):CCSPSSF33Base(pKeyContainer,ulAlgId,bToken)
{
}

//析构函数
CCSPSSF33Key::~CCSPSSF33Key()
{
	CCSPSSF33Base::~CCSPDesTmpl();
}
BOOL CCSPSSF33Key::Encrypt(
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
	if ((*pdwDataLen % dwBlockByteLen!= 0)&&(Final == FALSE))
	{
		SETLASTERROR(NTE_BAD_DATA);
		return FALSE;
	}

	BYTE cCommand[256];
	WORD wSW;
	CTYCSP * pCSPObject = GetCSPObject();
	CCardTrans trans(pCSPObject);
	if (trans.BeginTrans() == FALSE) {
		return FALSE;
	}
	//安装ssf33密钥
	memcpy(cCommand, "\x80\xd4\x01\x00\x18\x03\x01\x02\x0a\x0f\x00\x0f\xff", 13);
	memcpy(cCommand + 13, m_arbKeyContent.GetData(), 16);
	BOOL bRetVal = pCSPObject->SendCommand(cCommand, 13 + 16, NULL, NULL, &wSW);
	//老的文件系统中没有预先安装SSF33密钥
	if(bRetVal == FALSE){
		if(wSW != 0x9403) return FALSE;
		memcpy(cCommand, "\x80\xd4\x00\x00\x18\x03\x01\x02\x0a\x0f\x00\x0f\xff", 13);
		memcpy(cCommand + 13, m_arbKeyContent.GetData(), 16);
		if(!pCSPObject->SendCommand(cCommand, 13 + 16))
			return FALSE;
	}
	
	if (/*m_bFinished*/m_pDESEncryption == NULL)
	{
		m_pDESEncryption = new SF33_Encryption(m_arbKeyContent.GetData(),GetCSPObject());
	}

	if (m_dwMode == CRYPT_MODE_ECB)
	{
		
		if (dwBufLen < (*pdwDataLen+dwBlockByteLen)/dwBlockByteLen*dwBlockByteLen)
		{
			SETLASTERROR(NTE_BAD_LEN);
			return FALSE;
		}
		
		if(Final)
		{
			BYTE pad = dwBlockByteLen - (*pdwDataLen%dwBlockByteLen);
			for (BYTE j=0;j<pad;j++)
				pbData[*pdwDataLen+j] = pad;

			*pdwDataLen = (*pdwDataLen+dwBlockByteLen)/dwBlockByteLen*dwBlockByteLen;
		}

		m_pDESEncryption->Process(pbData,*pdwDataLen);
	}
	else if ((m_dwMode == CRYPT_MODE_CBC)||(m_dwMode == 0))
	{
		if (/*m_bFinished*/m_pCBCPaddedEncryptor == NULL)
		{
			BYTE pbSalt[16] = {0};
			memcpy(pbSalt, m_arbIv.GetData(), sizeof(pbSalt));
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

BOOL CCSPSSF33Key::Decrypt(
	CCSPHashObject* pHash,			// in
	BOOL Final,						// in
	DWORD dwFlags,					// in
	BYTE *pbData,					// in, out
	DWORD *pdwDataLen				// in, out
	)
{
	BOOL bRet = TRUE;

	DWORD dwBlockByteLen = m_dwBlockLen/8;
	if((pbData == NULL) || (*pdwDataLen == 0))
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

	BYTE cCommand[256];
	WORD wSW;
	CTYCSP * pCSPObject = GetCSPObject();
	CCardTrans trans(pCSPObject);
	if (trans.BeginTrans() == FALSE) {
		return FALSE;
	}
	memcpy(cCommand, "\x80\xd4\x01\x00\x18\x03\x01\x02\x0a\x0f\x00\x0f\xff", 13);
	memcpy(cCommand + 13, m_arbKeyContent.GetData(), 16);
	BOOL bRetVal = pCSPObject->SendCommand(cCommand, 13 + 16, NULL, NULL, &wSW);
	//老的文件系统中没有预先安装SSF33密钥
	if(bRetVal == FALSE){
		if(wSW != 0x9403) return FALSE;
		memcpy(cCommand, "\x80\xd4\x00\x00\x18\x03\x01\x02\x0a\x0f\x00\x0f\xff", 13);
		memcpy(cCommand + 13, m_arbKeyContent.GetData(), 16);
		if(!pCSPObject->SendCommand(cCommand, 13 + 16))
			return FALSE;
	}
	
	if (m_pDESDecryption == NULL)
	{
		m_pDESDecryption = new SF33_Decryption(m_arbKeyContent.GetData(),pCSPObject);
	}

	if (m_dwMode == CRYPT_MODE_ECB)
	{
		m_pDESDecryption->Process(pbData,*pdwDataLen);

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
		*pdwDataLen = tmpLen;
		memcpy(pbData,tmp,tmpLen);
		delete tmp;
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





















