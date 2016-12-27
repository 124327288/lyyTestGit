//CSPRsaPuk.cpp

#include <stdAfx.h>
#include "cspkey.h"

#include "Integer.h"
#include "rsa.h"
#include "pkcspad.h"
#include "rng.h"

//���캯��
CCSPRsaPuk::CCSPRsaPuk(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken
		):CCSPAsymmetricalKey(pKeyContainer, ulAlgId,bToken/*,bExtractable,bPrivate*/)
{
	m_pRsa = NULL;
}
CCSPRsaPuk::CCSPRsaPuk (
		CCSPRsaPuk & src
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

//------------------------------------------------------
/*
���ܣ�������Կ��ֵ
���룺	bitlen��ģ��
		pubexp��e
		modulus��n
���룺
˵�����ú����Զ�����ģ��ȡmodulus�ĳ���
*/
//------------------------------------------------------
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

//-----------------------------------------------------------
/*
���ܣ����ù�Կ��������(���ʵ��)
���룺pData---�����ܵ����ݣ�����ȡģ��
�����pData�������ܺ������
˵�����ú��������κ����
	  ��Կ�ĸ����Ѿ���������ݶ�Ӧ��ʱbig-endian
*/
//-----------------------------------------------------------
BOOL CCSPRsaPuk::SWRawRSAEncryption(
	BYTE * pData
	)
{
	Integer x(pData,m_dwBitLen/8);
	m_pRsa->ApplyFunction(x).Encode(pData,m_dwBitLen/8);
	return TRUE;
}

//-----------------------------------------------------------
/*
���ܣ����ù�Կ��������(Ӳ��ʵ��)
���룺pData---�����ܵ����ݣ�����ȡģ��
�����pData�������ܺ������
˵�����ú��������κ����
	  ��Կ�ĸ����Ѿ���������ݶ�Ӧ��ʱbig-endian
*/
//-----------------------------------------------------------
BOOL CCSPRsaPuk::HWRawRSAEncryption(
	BYTE * pData
	)
{
	return SWRawRSAEncryption(pData);
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

BOOL CCSPRsaPuk::Encrypt(
		CCSPHashObject* pHash,		// in
		BOOL Final,					// in
		DWORD dwFlags,				// in
		BYTE *pbData,				// in, out
		DWORD *pdwDataLen,			// in, out
		DWORD dwBufLen				// in
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
	if((pbData == NULL) || (*pdwDataLen == 0))
		return TRUE;

	//�ж�����ռ��Ƿ��㹻
	if(dwBufLen < (m_dwBitLen / 8)){
		SETLASTERROR(NTE_BAD_LEN);
		return FALSE;
	}

	//ֻ֧�ֵ�������
	if((*pdwDataLen) >= (m_dwBitLen / 8 - 11)){
		SETLASTERROR(NTE_BAD_DATA);
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
	for(int i = 0; i < (*pdwDataLen); i += (m_dwBitLen / 8)){
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

BOOL CCSPRsaPuk::VerifySignature(
		CCSPHashObject* pHash,			// in
		CONST BYTE *pbSignature,		// in
		DWORD dwSigLen,					// in
		LPCWSTR sDescription,			// in
		DWORD dwFlags					// in
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

//-------------------------------------------------------------------
//	���ܣ�
//		��֤����ԭ����
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		CONST LPBYTE pbSignature
//		DWORD dwSigLen   
//		DWORD dwFlags
//		LPBYTE pbData
//		LPDWORD pdwDataLen
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPRsaPuk::VerifyRecover(
	CONST LPBYTE pbSignature,  
	DWORD dwSigLen,     
	DWORD dwFlags,
	LPBYTE pbData,
	LPDWORD pdwDataLen
	)
{
	//��ȡ��Կ
	if (!ReadRealObject())
		return FALSE;

	//�������
	if(pdwDataLen == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if(pbSignature == NULL || dwSigLen == 0){
		*pdwDataLen = 0;
		return TRUE;
	}

	if(dwSigLen != m_dwBitLen / 8){
		SETLASTERROR(NTE_BAD_SIGNATURE);
		return FALSE;
	}

	//��֤
	BYTE pbSigTmp[256];
	memcpy(pbSigTmp, pbSignature, dwSigLen);
	SwapInt(pbSigTmp, dwSigLen);

	BOOL bRetVal;
	if (IsNeedHWCalc())
		bRetVal = HWRawRSAEncryption(pbSigTmp);
	else
		bRetVal = SWRawRSAEncryption(pbSigTmp);
	if(!bRetVal){
		SETLASTERROR(NTE_BAD_SIGNATURE);
		return FALSE;
	}

	TRACE_LINE("Result of VerifyRecover:\n");
	TRACE_DATA(pbSigTmp,dwSigLen);

	//ȥ������ȡ����
	PKCS_SignaturePaddingScheme pad;
	*pdwDataLen = pad.Unpad(pbSigTmp, dwSigLen*8-1, pbData);
	if(*pdwDataLen == 0){
		SETLASTERROR(NTE_BAD_SIGNATURE);
		return FALSE;
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

BOOL CCSPRsaPuk::RSARawEncrypt(
	LPBYTE pbInData,
	DWORD dwInDataLen,
	LPBYTE pbOutData,
	LPDWORD pdwOutDataLen
	)
{
	//��ȡ��Կ
	if (!ReadRealObject()){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}

	//�������
	if(pbInData == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	//����������ݳ���
	if(dwInDataLen != m_dwBitLen / 8){
		SETLASTERROR(NTE_BAD_LEN);
		return FALSE;
	}

	//�������ռ�
	if (pbOutData == NULL){
		*pdwOutDataLen = m_dwBitLen / 8;
		return TRUE;
	}
	if (*pdwOutDataLen < m_dwBitLen / 8){
		SETLASTERROR(ERROR_MORE_DATA);
		return FALSE;
	}
	*pdwOutDataLen = m_dwBitLen / 8;

	//˽Կ����
	memcpy(pbOutData, pbInData, dwInDataLen);
	BOOL bRetVal = TRUE;
	if (IsNeedHWCalc())
		bRetVal = HWRawRSAEncryption(pbOutData);
	else
		bRetVal = SWRawRSAEncryption(pbOutData);

	return bRetVal;
}