//CSPEccPuk.cpp

#include "stdAfx.h"
#include "cspkey.h"

#include "Integer.h"
#include "pkcspad.h"
#include "rng.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CCSPEccPuk::CCSPEccPuk(
	CCSPKeyContainer* pKeyContainer,
	ULONG ulAlgId,
	BOOL bToken
	) : CCSPAsymmetricalKey(pKeyContainer, ulAlgId, bToken)
{
	m_pEcc = NULL;
}

CCSPEccPuk::CCSPEccPuk (
	CCSPEccPuk &src
	) : CCSPAsymmetricalKey(src)
{
	m_dwBitLen = src.m_dwBitLen;
	m_pEcc = src.m_pEcc;
	m_pubID[0] = src.m_pubID[0];
	m_pubID[1] = src.m_pubID[1];
}

CCSPEccPuk::~CCSPEccPuk()
{
	if (m_pEcc)
	{
		delete m_pEcc;
		m_pEcc = NULL;
	}	
	CCSPAsymmetricalKey::~CCSPAsymmetricalKey();
}

BOOL CCSPEccPuk::SWRawEccEncryption(//不支持
	BYTE * pData,
	BYTE *pDataOut,
	DWORD *dwOutDataLen
	)
{
	return FALSE;
}

BOOL CCSPEccPuk::HWRawEccEncryption(
	BYTE * pData,
	BYTE *pDataOut,
	DWORD *dwOutDataLen
	)
{
	//80 c2 00 21 18 %rand
	if(GetCSPObject()->GetCardType() == CPU_PKI){
		//开始事务
		GetCSPObject()->BeginTransaction();
		
		if (m_dwBitLen == 192)
		{
			BYTE pbCmd[256];
			pbCmd[0] = 0x80;
			pbCmd[1] = 0xC2;
			pbCmd[2] = m_pubID[0];
			pbCmd[3] = m_pubID[1];
			pbCmd[4] = 0x18;
			memcpy(pbCmd + 5, pData, 0x18);
			*dwOutDataLen = 256;
			BOOL bRetVal = GetCSPObject()->SendCommand(
				pbCmd, pbCmd[4]+5, pDataOut, dwOutDataLen
				);
		}
		else
		{
			goto error_proc;
		}
		//结束事务
		GetCSPObject()->EndTransaction();
	}
	else return FALSE;

	return TRUE;

error_proc:
	GetCSPObject()->EndTransaction();
	return FALSE;
}

BOOL CCSPEccPuk::SWRawEccVerify(//不支持
	BYTE * pData,
	BYTE *pDataOut,
	DWORD *dwOutDataLen
	)
{
	return FALSE;
}

BOOL CCSPEccPuk::HWRawEccVerify(
	BYTE * pData,
	BYTE *pDataOut,
	DWORD *dwOutDataLen
	)
{
	//80 cE 00 21 48 %rand
	if(GetCSPObject()->GetCardType() == CPU_PKI){
		//开始事务
		GetCSPObject()->BeginTransaction();
		
		if (m_dwBitLen == 192)
		{
			BYTE pbCmd[256];
			pbCmd[0] = 0x80;
			pbCmd[1] = 0xCE;
			pbCmd[2] = m_pubID[0];
			pbCmd[3] = m_pubID[1];
			pbCmd[4] = 0x48;
			memcpy(pbCmd + 5, pData, 0x48);
			*dwOutDataLen = 256;
			BOOL bRetVal = GetCSPObject()->SendCommand(
				pbCmd, pbCmd[4]+5, pDataOut, dwOutDataLen
				);
			//返回数据无dwOutDataLen=0;
		}
		else
		{
			goto error_proc;
		}
		//结束事务
		GetCSPObject()->EndTransaction();
	}
	else return FALSE;

	return TRUE;

error_proc:
	GetCSPObject()->EndTransaction();
	return FALSE;
}

BOOL CCSPEccPuk::IsNeedHWCalc()
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
CCSPEccPuk::Encrypt(
	CCSPHashObject* pHash,
	BOOL Final,
	DWORD dwFlags,
	BYTE* pbData,
	DWORD* pdwDataLen,
	DWORD dwBufLen
	)
{
	//读取公钥对象
	if(!ReadRealObject())
		return FALSE;

	//参数检测
	if(pdwDataLen == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	//判断是否有数据需要加密
	if(NULL == pHash)
	{
		//只支持单块数据
//		if(((*pdwDataLen) > (m_dwBitLen / 8 )) || (*pdwDataLen == 0))
//		{
//			SETLASTERROR(NTE_BAD_DATA);
//			return FALSE;
//		}
		
		if(NULL == pbData)
		{
			*pdwDataLen = m_dwBitLen / 8;
			return TRUE;
		}
	}	

	BOOL bRetVal = TRUE;
	if(pHash != NULL){
		bRetVal = pHash->HashData(pbData, *pdwDataLen, NULL);
		if (bRetVal = FALSE)
			return FALSE;
	}

	//加密填充 
	ECCPad pad;
	DWORD dwPadDataLen = 0;
	BOOL bRet = pad.Pad(pbData,*pdwDataLen,NULL,dwPadDataLen,m_dwBitLen/8);
	if (!bRet) {
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}
	LPBYTE pbPadData = new BYTE[dwPadDataLen];
	if(pbPadData == NULL){
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}

	bRet = pad.Pad(pbData,*pdwDataLen,pbPadData,dwPadDataLen,m_dwBitLen/8);
	if (!bRet) {
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}
	LPBYTE pbDataOut = new BYTE[dwPadDataLen*3];
	if(pbDataOut == NULL){
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}

	//判断输出空间是否足够
	if(dwBufLen < (dwPadDataLen/(m_dwBitLen/8)*3)){
		SETLASTERROR(NTE_BAD_LEN);
		return FALSE;
	}

	DWORD pbOutDataLen =256;
	*pdwDataLen = 0;//用于计算输出长度
	//加密
	for(DWORD i = 0; i < (dwPadDataLen); i += (m_dwBitLen / 8)){
		if (IsNeedHWCalc())
			bRetVal = HWRawEccEncryption(pbPadData + i,(pbDataOut+*pdwDataLen),&pbOutDataLen);
		else
			bRetVal = SWRawEccEncryption(pbPadData + i,(pbDataOut+*pdwDataLen),&pbOutDataLen);
		if(!bRetVal){
			SETLASTERROR(NTE_FAIL);
			return FALSE;
		}
		*pdwDataLen += pbOutDataLen;
	}

	memcpy(pbData,pbDataOut,*pdwDataLen);
	//交换密文的字节顺序
	SwapInt(pbData,*pdwDataLen);

	if (NULL != pbPadData)
	{
		delete [] pbPadData;
		pbPadData = NULL;
	}
	if (NULL != pbDataOut)
	{
		delete [] pbDataOut;
		pbDataOut = NULL;
	}
	return TRUE;	
}

BOOL 
CCSPEccPuk::VerifySignature(
	CCSPHashObject* pHash,
	CONST BYTE* pbSignature,
	DWORD dwSigLen,
	LPCWSTR sDescription,
	DWORD dwFlags
	)
{
	TRACE_LINE("dwFlags = %08x\n", dwFlags);

	//判断是否有签名需要验证
	if((pbSignature == NULL) || (dwSigLen == 0))
		return TRUE;

	//是否为块长的整数倍
	if(dwSigLen % (m_dwBitLen/8*3)!=0){
		SETLASTERROR(NTE_BAD_SIGNATURE);
		return FALSE;
	}

	if((dwFlags != 0) && (dwFlags != CRYPT_NOHASHOID)){
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}
	
	//读取公钥对象
	if(!ReadRealObject())
		return FALSE;

	//复制签名
	LPBYTE pbDupSig = new BYTE[dwSigLen];
	memcpy(pbDupSig, pbSignature, dwSigLen);

	LPBYTE pbDupSigOut = new BYTE[dwSigLen/3];
	DWORD dwDupSigOutLen = 24;
	//交换签名的字节顺序
	SwapInt(pbDupSig, dwSigLen);

	
	BOOL bRetVal = TRUE;
	DWORD nLen =0;//用于计算数据长度
	
	for(int i = 0; i < dwSigLen; i += (m_dwBitLen*3/ 8)){
		if(IsNeedHWCalc())
			bRetVal = HWRawEccVerify(pbDupSig+i,pbDupSigOut+nLen,&dwDupSigOutLen);
		else
			bRetVal = SWRawEccVerify(pbDupSig+i,pbDupSigOut+nLen,&dwDupSigOutLen);
		if (bRetVal == FALSE)
		{
			delete pbDupSig;
			delete pbDupSigOut;
			SETLASTERROR(NTE_FAIL);
			return FALSE;
		}
		nLen += m_dwBitLen/8;
	}
	delete pbDupSig;//
	if (pbDupSigOut != NULL) {
		delete [] pbDupSigOut;
	}
	/*dwDupSigOutLen = nLen;
	memcpy(pbDupSig,pbDupSigOut,dwDupSigOutLen);
	//去掉填充
	ECCPad pad;
	DWORD dwDataOutLen = 0 ;
	BOOL bRet = pad.UnPad(pbDupSig,dwDupSigOutLen,NULL,dwDataOutLen,m_dwBitLen/8);
	if (!bRet) {
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}

	LPBYTE pbUnpadData = new BYTE[dwDataOutLen];
	if(pbUnpadData == NULL){
		delete pbDupSig;
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}

	bRet = pad.UnPad(pbDupSig,dwDupSigOutLen,pbUnpadData,dwDataOutLen,m_dwBitLen/8);
	if (!bRet) {
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}

	delete pbDupSig;

	//比较
	BYTE pbHash[HASH_MAX_SIZE];
	DWORD cbHash = HASH_MAX_SIZE;
	if(dwFlags == 0){
		switch (pHash->GetAlgId()){
		case CALG_SHA:
			{
				if(dwDataOutLen != 0x23){
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
				if(dwDataOutLen != 0x22){
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

				if(dwDataOutLen != cbHash){
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

		if(dwDataOutLen != cbHash){
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
	}*/	
	return TRUE;
}
BOOL CCSPEccPuk::Import(
		CONST BYTE *pbData,     // in
		DWORD  dwDataLen,       // in
		CCSPKey *pPubKey,      // in
		DWORD dwFlags          // in
		)
{
	SETLASTERROR(NTE_FAIL);
	return FALSE;
	
}
BOOL CCSPEccPuk::Export(
		CCSPKey *pPubKey,				// in
		DWORD dwBlobType,				// in
		DWORD dwFlags,					// in
		BYTE *pbKeyBlob,				// out
		DWORD *dwKeyBlobLen			// in, out
		)
{
	SETLASTERROR(NTE_FAIL);
	return FALSE;
}