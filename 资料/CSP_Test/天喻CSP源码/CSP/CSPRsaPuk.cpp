//CSPRsaPuk.cpp

#include "stdAfx.h"
#include "cspkey.h"

#include "Integer.h"
#include "rsa.h"
#include "pkcspad.h"
#include "rng.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CCSPRsaPuk::CCSPRsaPuk(
	CCSPKeyContainer* pKeyContainer,
	ULONG ulAlgId,
	BOOL bToken
	) : CCSPAsymmetricalKey(pKeyContainer, ulAlgId, bToken)
{
	m_pRsa = NULL;
}

CCSPRsaPuk::CCSPRsaPuk (
	CCSPRsaPuk &src
	) : CCSPAsymmetricalKey(src)
{
	m_dwBitLen = src.m_dwBitLen;
	Integer n = src.m_pRsa->GetModulus();
	Integer e = src.m_pRsa->GetExponent();
	m_pRsa = new RSAFunction(n,e);
}

CCSPRsaPuk::~CCSPRsaPuk()
{
	if (m_pRsa)
	{
		delete m_pRsa;
		m_pRsa = NULL;
	}
		
	CCSPAsymmetricalKey::~CCSPAsymmetricalKey();
}


BOOL CCSPRsaPuk::Create(
	DWORD bitlen,
	DWORD pubexp,
	CONST BYTE* modulus
	)
{
	m_dwBlockLen = bitlen;
	m_dwBitLen = bitlen;
	m_ulKeyLen = bitlen;


	BYTE *tmp = new BYTE[bitlen/8];
	memcpy(tmp,modulus,bitlen/8);
	SwapInt(tmp,bitlen/8);
	Integer n(tmp,bitlen/8);
	delete tmp;

	Integer e(pubexp);
	
	if(m_pRsa != NULL){
		delete m_pRsa;
		m_pRsa = NULL;
	}
	m_pRsa = new RSAFunction(n,e);

	return TRUE;
}

BOOL CCSPRsaPuk::SWRawRSAEncryption(
	BYTE * pData
	)
{
	Integer x(pData,m_dwBitLen/8);
	m_pRsa->ApplyFunction(x).Encode(pData,m_dwBitLen/8);
	return TRUE;
}

BOOL CCSPRsaPuk::HWRawRSAEncryption(
	BYTE * pData
	)
{
	return SWRawRSAEncryption(pData);//��������ʽ
	/*if(GetCSPObject()->GetCardType() == CPU_PKI){
		//��ʼ����
		GetCSPObject()->BeginTransaction();
		
		if (m_dwBitLen == 1024)
		{
			BYTE pbCmd[256];
			pbCmd[0] = 0x80;
			pbCmd[1] = 0xC6;
			pbCmd[2] = m_pubID[0];
			pbCmd[3] = m_pubID[1];
			pbCmd[4] = 0x80;
			memcpy(pbCmd + 5, pData, 0x80);
			DWORD dwOutDataLen = 256;
			BOOL bRetVal = GetCSPObject()->SendCommand(
				pbCmd, pbCmd[4]+5, pData, &dwOutDataLen
				);
		}
		else if (m_dwBitLen == 2048)
		{
			
			//RSA Encrypt & Decrypt Operation����������RSA��������ִ�мӽ���			
			//;------------������Կ	
			//80 38 01 F0 04 ��ԿID ˽ԿID 
			BYTE pbCmd[256];
			pbCmd[0] = 0x80;
			pbCmd[1] = 0x38;
			pbCmd[2] = 0x01;
			pbCmd[3] = 0xF0;
			pbCmd[4] = 0x04;
			pbCmd[5] = m_pubID[0];
			pbCmd[6] = m_pubID[1];
			pbCmd[7] = m_RealObjPath[0];
			pbCmd[8] = m_RealObjPath[1];
			DWORD dwOutDataLen;
			BOOL bRetVal = GetCSPObject()->SendCommand(
				pbCmd, 9, NULL, NULL
				);

			//;------------�������ݸ�128λ
			//80 38 01 c2 80 pdata[High]
			pbCmd[0] = 0x80;
			pbCmd[1] = 0x38;
			pbCmd[2] = 0x01;
			pbCmd[3] = 0xC2;
			pbCmd[4] = 0x80;
			memcpy(pbCmd+5,pData,0x80);
			bRetVal = GetCSPObject()->SendCommand(
				pbCmd, 5+0x80, NULL, NULL
				);
			//;------------�������ݵ�128λ
			//80 38 01 C1 80 pdata[Low]
			pbCmd[0] = 0x80;
			pbCmd[1] = 0x38;
			pbCmd[2] = 0x01;
			pbCmd[3] = 0xC1;
			pbCmd[4] = 0x80;
			memcpy(pbCmd+5,pData+0x80,0x80);
			bRetVal = GetCSPObject()->SendCommand(
				pbCmd, 5+0x80, NULL, NULL
				);
			//ִ�н���
			//80 3A 01 00 00        4s Le= 0x100 ��Ӧ����+9000
			pbCmd[0] = 0x80;
			pbCmd[1] = 0x3A;
			pbCmd[2] = 0x01;
			pbCmd[3] = 0x00;
			pbCmd[4] = 0x00;
			dwOutDataLen = 256;
			//
			bRetVal = GetCSPObject()->SendCommand(
				pbCmd, 5, pData, &dwOutDataLen
				);			
			
		}
		else
		{
			goto error_proc;
		}
		//��������
		GetCSPObject()->EndTransaction();
	}
	else return FALSE;

	return TRUE;

error_proc:
	GetCSPObject()->EndTransaction();
	return FALSE;*/
}

BOOL CCSPRsaPuk::IsNeedHWCalc()
{
	if(GetCSPObject()->GetCryptMode() == SOFTWARE)
		return FALSE;

	if ((m_bToken == TRUE) && ((m_dwPermissions & CRYPT_EXPORT) == 0))
	{
		return TRUE;
	}

	return FALSE;
}

BOOL 
CCSPRsaPuk::Encrypt(
	CCSPHashObject* pHash,
	BOOL Final,
	DWORD dwFlags,
	BYTE* pbData,
	DWORD* pdwDataLen,
	DWORD dwBufLen
	)
{
	//��ȡ��Կ����
	if(!ReadRealObject())
		return FALSE;

	//�������
	if(pdwDataLen == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	//�ж��Ƿ���������Ҫ����
	if(NULL == pHash)
	{
		//ֻ֧�ֵ�������
		if(((*pdwDataLen) > (m_dwBitLen / 8 - 11)) || (*pdwDataLen == 0))
		{
			SETLASTERROR(NTE_BAD_DATA);
			return FALSE;
		}
		
		if(NULL == pbData)
		{
			*pdwDataLen = m_dwBitLen / 8;
			return TRUE;
		}
	}

	//�ж�����ռ��Ƿ��㹻
	if(dwBufLen < (m_dwBitLen / 8)){
		SETLASTERROR(NTE_BAD_LEN);
		return FALSE;
	}

	BOOL bRetVal = TRUE;
	if(pHash != NULL){
		bRetVal = pHash->HashData(pbData, *pdwDataLen, NULL);
		if (bRetVal = FALSE)
			return FALSE;
	}

	//�������
	PKCS_EncryptionPaddingScheme pad;
	LPBYTE pbPadData = new BYTE[m_dwBitLen / 8];
	pad.Pad(g_rng, pbData, *pdwDataLen, pbPadData, m_dwBitLen - 1);
	*pdwDataLen = m_dwBitLen / 8;
	memcpy(pbData, pbPadData, *pdwDataLen);
	delete pbPadData;

	//����
	for(DWORD i = 0; i < (*pdwDataLen); i += (m_dwBitLen / 8)){
		if (IsNeedHWCalc())
			bRetVal = HWRawRSAEncryption(pbData + i);
		else
			bRetVal = SWRawRSAEncryption(pbData + i);
		if(!bRetVal){
			SETLASTERROR(NTE_FAIL);
			return FALSE;
		}
	}

	//�������ĵ��ֽ�˳��
	SwapInt(pbData,*pdwDataLen);

	return TRUE;	
}

BOOL 
CCSPRsaPuk::VerifySignature(
	CCSPHashObject* pHash,
	CONST BYTE* pbSignature,
	DWORD dwSigLen,
	LPCWSTR sDescription,
	DWORD dwFlags
	)
{
	TRACE_LINE("dwFlags = %08x\n", dwFlags);

	//�ж��Ƿ���ǩ����Ҫ��֤
	if((pbSignature == NULL) || (dwSigLen == 0))
		return TRUE;

	//��֧�ֵ����У��
	if(dwSigLen != m_dwBitLen/8){
		SETLASTERROR(NTE_BAD_SIGNATURE);
		return FALSE;
	}

	if((dwFlags != 0) && (dwFlags != CRYPT_NOHASHOID)){
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}
	
	//��ȡ��Կ����
	if(!ReadRealObject())
		return FALSE;

	//����ǩ��
	LPBYTE pbDupSig = new BYTE[dwSigLen];
	memcpy(pbDupSig, pbSignature, dwSigLen);

	//����ǩ�����ֽ�˳��
	SwapInt(pbDupSig, dwSigLen);

	//���ù�Կ����
	BOOL bRetVal = TRUE;
	if(IsNeedHWCalc())
		bRetVal = HWRawRSAEncryption(pbDupSig);
	else
		bRetVal = SWRawRSAEncryption(pbDupSig);
	if (bRetVal == FALSE)
	{
		delete pbDupSig;
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}
	
	//ȥ�����
	PKCS_SignaturePaddingScheme pad;
	DWORD cbUnpadData = pad.MaxUnpaddedLength(m_dwBitLen - 1);
	LPBYTE pbUnpadData = new BYTE[cbUnpadData];
	if(pbUnpadData == NULL){
		delete pbDupSig;
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}
	cbUnpadData = pad.Unpad(pbDupSig, m_dwBitLen - 1, pbUnpadData);
	delete pbDupSig;
	if(cbUnpadData == 0){
		delete pbUnpadData;
		SETLASTERROR(NTE_BAD_DATA);
		return FALSE;
	}

	//�Ƚ�
	int i;
	BYTE pbHash[HASH_MAX_SIZE];
	DWORD cbHash = HASH_MAX_SIZE;
	if(dwFlags == 0){
		switch (pHash->GetAlgId()){
		case CALG_SHA:
			{
				if(cbUnpadData != 0x23){
					delete pbUnpadData;
					SETLASTERROR(NTE_BAD_SIGNATURE);
					return FALSE;
				}

				for (i = 0; i < SHAdecorationlen; i++){
					if(SHAdecoration[i] != pbUnpadData[i]){
						delete pbUnpadData;
						SETLASTERROR(NTE_BAD_SIGNATURE);
						return FALSE;
					}
				}
				
				pHash->GetValue(pbHash, &cbHash);
				for(i = 0; i < 0x14; i++){
					if (pbHash[i] != pbUnpadData[i + SHAdecorationlen]){
						delete pbUnpadData;
						SETLASTERROR(NTE_BAD_SIGNATURE);
						return FALSE;
					}
				}
				
				delete pbUnpadData;
			}
			break;
		case CALG_MD5:
			{
				if(cbUnpadData != 0x22){
					delete pbUnpadData;
					SETLASTERROR(NTE_BAD_SIGNATURE);
					return FALSE;
				}

				for(i = 0; i < MD5decorationlen; i++){
					if(MD5decoration[i] != pbUnpadData[i]){
						delete pbUnpadData;
						SETLASTERROR(NTE_BAD_SIGNATURE);
						return FALSE;
					}
				}
				
				pHash->GetValue(pbHash, &cbHash);
				for (i = 0; i < 0x10; i++){
					if(pbHash[i] != pbUnpadData[i + MD5decorationlen]){
						delete pbUnpadData;
						SETLASTERROR(NTE_BAD_SIGNATURE);
						return FALSE;
					}
				}
				
				delete pbUnpadData;
			}
			break;
		case CALG_SSL3_SHAMD5:
			{
				pHash->GetValue(pbHash, &cbHash);

				if(cbUnpadData != cbHash){
					delete pbUnpadData;
					SETLASTERROR(NTE_BAD_SIGNATURE);
					return FALSE;
				}

				if(memcmp(pbHash, pbUnpadData, cbHash)){
					delete pbUnpadData;
					SETLASTERROR(NTE_BAD_SIGNATURE);
					return FALSE;
				}
				
				delete pbUnpadData;
			}
			break;
		}
	}
	else if(dwFlags == CRYPT_NOHASHOID){
		pHash->GetValue(pbHash, &cbHash);

		if(cbUnpadData != cbHash){
			delete pbUnpadData;
			SETLASTERROR(NTE_BAD_SIGNATURE);
			return FALSE;
		}

		if(memcmp(pbHash, pbUnpadData, cbHash)){
			delete pbUnpadData;
			SETLASTERROR(NTE_BAD_SIGNATURE);
			return FALSE;
		}
		
		delete pbUnpadData;
	}
	
	return TRUE;
}
BOOL CCSPRsaPuk::Import(
		CONST BYTE *pbData,     // in
		DWORD  dwDataLen,       // in
		CCSPKey *pPubKey,      // in
		DWORD dwFlags          // in
		)
{
	if (pPubKey != NULL)
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}
	
	BLOBHEADER *bh = (BLOBHEADER*)pbData;
	if(bh->bType != PUBLICKEYBLOB)
	{
		SETLASTERROR(NTE_BAD_TYPE);
		return FALSE;
	}
	m_dwFlags = dwFlags;

	pbData += sizeof(BLOBHEADER);

	RSAPUBKEY* rsapuk = (RSAPUBKEY*)pbData;
	if (rsapuk->magic != 0x31415352)
	{
		SETLASTERROR(NTE_BAD_DATA);
		return FALSE;
	}
	pbData += sizeof(RSAPUBKEY);
	if (dwDataLen != sizeof(BLOBHEADER)+sizeof(RSAPUBKEY)+rsapuk->bitlen/8)
	{
		SETLASTERROR(NTE_BAD_DATA);
		return FALSE;
	}
	return Create(rsapuk->bitlen,rsapuk->pubexp,
		pbData);
	
}
BOOL CCSPRsaPuk::Export(
		CCSPKey *pPubKey,				// in
		DWORD dwBlobType,				// in
		DWORD dwFlags,					// in
		BYTE *pbKeyBlob,				// out
		DWORD *dwKeyBlobLen			// in, out
		)
{
	if (!ReadRealObject())
		return FALSE;
	if (pPubKey != NULL)
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}
	if (dwBlobType != PUBLICKEYBLOB)
	{
		SETLASTERROR(NTE_BAD_TYPE);
		return FALSE;
	}
	/*if ((m_dwPermissions&CRYPT_EXPORT) == 0)
	{
		SETLASTERROR(NTE_BAD_KEY_STATE);
		return FALSE;
	}*/

	DWORD NeedLen = m_dwBitLen/8 +sizeof(BLOBHEADER) + sizeof(RSAPUBKEY);
	
	
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

	*dwKeyBlobLen = NeedLen;

	BLOBHEADER bh;
	bh.bType = dwBlobType;
	bh.bVersion = DEFAULT_BLOB_VERSION;
	bh.reserved = NULL;
	bh.aiKeyAlg = m_ulAlgId;
	memcpy(pbKeyBlob,(BYTE *)(&bh),sizeof(BLOBHEADER));

	RSAPUBKEY rsapuk;
	rsapuk.bitlen = m_dwBitLen;
	rsapuk.magic = 0x31415352;
	rsapuk.pubexp = m_pRsa->GetExponent().ConvertToLong();
	TRACE_LINE("e:%x",rsapuk.pubexp);
	memcpy(pbKeyBlob+sizeof(BLOBHEADER),(BYTE *)(&rsapuk),sizeof(RSAPUBKEY));

	m_pRsa->GetModulus().Encode(pbKeyBlob+sizeof(BLOBHEADER)+sizeof(RSAPUBKEY),m_dwBitLen/8);
	
	SwapInt(pbKeyBlob+sizeof(BLOBHEADER)+sizeof(RSAPUBKEY),m_dwBitLen/8);
	TRACE_LINE("n:\n");
	TRACE_DATA((pbKeyBlob+sizeof(BLOBHEADER)+sizeof(RSAPUBKEY)),m_dwBitLen/8);
	return TRUE;
}