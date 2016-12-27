//CSPEccPrk.cpp
#include <stdAfx.h>
#include "cspkey.h"
#include "DERCoding.h"

#include "Integer.h"
#include "pkcspad.h"
#include "queue.h"
#include "Ecc.h"
#ifdef _DEBUG
//#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
extern DWORD g_dwEccSignAlgid,g_dwEccKeyxAlgid;
CCSPEccPrk::CCSPEccPrk(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken
		):CCSPEccPuk(pKeyContainer, ulAlgId,bToken)
{
	m_ulExFilePath = 0;
	m_CertPath[0] = 0;
	m_CertPath[1] = 0;
	m_pInvertableEcc = NULL;
}

CCSPEccPrk::CCSPEccPrk(
		CCSPEccPrk & src
		) : CCSPEccPuk(src)
{
	m_ulExFilePath = src.m_ulExFilePath;
	memcpy(m_CertPath,src.m_CertPath,2);
	m_arbCert.Copy(src.m_arbCert);
	m_pInvertableEcc = src.m_pInvertableEcc;
}

CCSPEccPrk::~CCSPEccPrk()
{
	if (m_pInvertableEcc)
	{
		delete m_pInvertableEcc;
		m_pInvertableEcc = NULL;
	}
	m_arbCert.RemoveAll();
	CCSPEccPuk::~CCSPEccPuk();
}

BOOL CCSPEccPrk::Create(
		DWORD bitlen,
		DWORD dwFlags
		)
{
	if (bitlen%16 != 0)
	{
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}
	if (dwFlags&CRYPT_EXPORTABLE)
	{
		dwFlags &= (~CRYPT_EXPORTABLE);
	}
	BOOL bRet = CCSPAsymmetricalKey::Create(bitlen,dwFlags);
	if (bRet == FALSE)
		return FALSE;
	m_dwBlockLen = bitlen;
	m_dwBitLen = bitlen;
	m_ulKeyLen = bitlen;
	if (IsNeedHWGenKey())
		return HWGenKey(bitlen);
	return SWGenKey(bitlen);
}

BOOL CCSPEccPrk::HWGenKey(
		DWORD bitlen
		)
{
	m_dwBlockLen = bitlen;
	m_dwBitLen = bitlen;
	m_ulKeyLen = bitlen;

	if (m_pInvertableEcc)
	{
		delete m_pInvertableEcc;
		m_pInvertableEcc = NULL;
	}

	if(m_pEcc)
	{
		delete m_pEcc;
		m_pEcc = NULL;
	}

	if (m_dwFlags & CRYPT_USER_PROTECTED)
		m_bAuthId = DEFAULT_AUTH_ID;

	GetCSPObject()->BeginTransaction();
	
	if (IsPrivate())
	{
		if(!GetCSPObject()->IsLogin()){
			GetCSPObject()->EndTransaction();
			SETLASTERROR(NTE_PERM);
			return FALSE;
		}
	}
	
	BOOL bRet;
	if ((m_RealObjPath[0] ==0)&&(m_RealObjPath[1] ==0))
	{
		if(GetCSPObject()->GetCardType() == CPU_PKI){
			//����˽Կ������չ�ļ�
			WORD flag = 0x0000|FILETYPE_PRKEX_ECC | FILE_UNUSED | ((m_bAuthId&0xf0)<<4);
			bRet = GetCSPObject()->GetWorkableFile(flag, g_cPathTable.eccPrkExFileLen, m_RealObjPath);
			if (bRet == FALSE)
			{
				GetCSPObject()->EndTransaction();
				return FALSE;
			}

			//������Կ�ļ�
			BYTE pukFilePath[2] = {0, 0};
			flag = 0x0000|FILETYPE_PUK_ECC | FILE_UNUSED ;
			bRet = GetCSPObject()->GetWorkableFile(flag, g_cPathTable.eccPukFileLen, pukFilePath);
			if (bRet == FALSE)
			{
				GetCSPObject()->EndTransaction();
				return FALSE;
			}

			memcpy(m_pubID, pukFilePath, 2);
			//������Կ�Ժ�ֱ��д�빫˽Կ�ļ���
			BYTE pbCmd[256];
			memcpy(pbCmd, "\x80\x48\x00\x00\x04", 5);
			//˽Կ�ļ���ʶ��
			memcpy(pbCmd + 5, m_RealObjPath, 2);
			//��Կ�ļ����
			memcpy(pbCmd + 7, pukFilePath, 2);
			bRet = GetCSPObject()->SendCommand(pbCmd, pbCmd[4] + 5);
			if (bRet == FALSE)
			{
				GetCSPObject()->EndTransaction();
				return FALSE;
			}
			
			memcpy(m_pubID, pukFilePath, 2);
			/*��ECC��Կ�ļ����ܶ�����ֻ�������ܿ��ڲ������������
			//��ȡ��Կ��,ɾ����Կ�ļ�
			BYTE *pbPubKeyData = new BYTE[192 / 8 *2];
			FILEHANDLE hPukFile = NULL;
			bRet = GetCSPObject()->OpenFile(pukFilePath, &hPukFile);
			if (bRet == FALSE)
			{
				GetCSPObject()->EndTransaction();
				return FALSE;
			}
			DWORD dwPubKeyDataLen;
			bRet = GetCSPObject()->ReadFile(hPukFile, 0x30, pbPubKeyData, &dwPubKeyDataLen);
			GetCSPObject()->CloseFile(hPukFile);
			if (bRet == FALSE)
			{
				GetCSPObject()->EndTransaction();
				return FALSE;
			}
			GetCSPObject()->DeleteFile(pukFilePath);
			
			m_pEcc = new ECCFunction(Integer(pbPubKeyData, 0x30));			
			*/			
		}
		else{
			GetCSPObject()->EndTransaction();
			return FALSE;
		}
	}
	GetCSPObject()->EndTransaction();
	return TRUE;
}
BOOL CCSPEccPrk::SWGenKey(
		DWORD bitlen
		)
{
	return FALSE;
}


BOOL CCSPEccPrk::CreateOnToken(
		ULONG ulIndex
		)
{
	ASSERT(m_bToken == TRUE);
	GetCSPObject()->BeginTransaction();
	if (IsPrivate())
	{
		if(!GetCSPObject()->IsLogin()){
			GetCSPObject()->EndTransaction();
			SETLASTERROR(NTE_PERM);
			return FALSE;
		}
	}
	if (m_ulIndex != -1)
	{
		DestroyOnToken();
	}
	m_ulIndex = ulIndex;
	if (m_dwFlags&CRYPT_USER_PROTECTED)
		m_bAuthId = DEFAULT_AUTH_ID;
	BOOL bRet;
	BYTE cmd[256];
	ULONG ulFileLen;
	DWORD tmpLen;
	FILEHANDLE hFile = NULL;

	//write the real object
	if (IsNeedHWCalc())
	{
		//��˽Կ�ļ��ķ�ʽ����

		//���ҿ������ڱ���˽Կ��·��
		WORD ulStaus = 0x9000;
		if ((m_RealObjPath[0] ==0)&&(m_RealObjPath[1] ==0))
		{
			if(GetCSPObject()->GetCardType() == CPU_PKI){
				//����˽Կ������չ�ļ�
				WORD flag = 0x0000|FILETYPE_PRKEX_ECC|FILE_UNUSED;
				flag |= ((m_bAuthId&0xf0)<<4);
				bRet = GetCSPObject()->GetWorkableFile(flag, g_cPathTable.eccPrkExFileLen, m_RealObjPath);
				if (bRet == FALSE)
					goto error_proc;
			
				//ѡ��˽Կ�ļ���д��˽Կ
				FILEHANDLE hPriFile = NULL;
				bRet = GetCSPObject()->OpenFile(m_RealObjPath, &hPriFile);
				if (bRet == FALSE)
					goto error_proc;

				BYTE pbPriKeyData[0x18]; 
				DWORD dwPriKeyDataLen = 0;
				m_pInvertableEcc->GetPriKey().Encode(pbPriKeyData + dwPriKeyDataLen, 0x18);
				dwPriKeyDataLen += 0x18;				
				
				bRet = GetCSPObject()->WriteFile(hPriFile, pbPriKeyData, dwPriKeyDataLen);
				GetCSPObject()->CloseFile(hPriFile);
				if (bRet == FALSE)
					goto error_proc;
			}
			else
			{
				goto error_proc;
			}
		}
		//select the extension file that hold the puk
		m_ulExFilePath = (m_RealObjPath[0]<<8) + m_RealObjPath[1]
			- (g_cPathTable.eccprkStartPath[0]<<8) - g_cPathTable.eccprkStartPath[1]
			+ (g_cPathTable.eccprkexStarPath[0]<<8) + g_cPathTable.eccprkexStarPath[1];

		BYTE ExFilePath[2];
		ExFilePath[0] = BYTE(m_ulExFilePath >> 8);
		ExFilePath[1] = BYTE(m_ulExFilePath);
		FILEHANDLE hExFile = NULL;
		bRet = GetCSPObject()->OpenFile(ExFilePath, &hExFile, NULL);
		if (bRet == FALSE)
			goto error_proc;
		
		/*��ECC��Կ�ļ����ܶ�����ֻ�������ܿ��ڲ��������������GenKey m_pEccû�еõ�
		ByteQueue bt;
		m_pEcc->DEREncode(bt);
		DWORD tmpLen = bt.CurrentSize();
		BYTE *tmp = new BYTE[tmpLen];
		tmpLen = bt.Get(tmp,tmpLen);
		bRet = GetCSPObject()->WriteFile(hExFile, tmp, tmpLen, 0);
		GetCSPObject()->CloseFile(hExFile);
		if (bRet == FALSE)
		{
			delete tmp;
			goto error_proc;
		}
		delete tmp;
		*/
	}
	

	//write the attribute of the key in the prkdf
	if(!GetCSPObject()->OpenFile(g_cPathTable.prkdfPath, &hFile, &ulFileLen))
		goto error_proc;

	SHARE_XDF XdfRec;
	bRet = GetCSPObject()->GetXdf(DFTYPE_PRK,&XdfRec);
	ULONG ulOffset,ulLen;
	GetKeyOffsetInXdf(&XdfRec,m_ulIndex,ulOffset,ulLen);

	cmd[0] = 0x30;
	tmpLen = 2;
	memcpy(cmd+tmpLen,&m_dwFlags,sizeof(DWORD));
	tmpLen += sizeof(DWORD);
	memcpy(cmd+tmpLen,&m_bAuthId,sizeof(BYTE));
	tmpLen += sizeof(BYTE);
	memcpy(cmd+tmpLen,&m_ulAlgId,sizeof(ALG_ID));
	tmpLen += sizeof(ALG_ID);
	memcpy(cmd+tmpLen,&m_dwPermissions,sizeof(DWORD));
	tmpLen += sizeof(DWORD);
	memcpy(cmd+tmpLen,&m_dwBitLen,sizeof(DWORD));
	tmpLen += sizeof(DWORD);
	memcpy(cmd+tmpLen,&m_RealObjPath,2);
	tmpLen += 2;
	memcpy(cmd+tmpLen,&m_CertPath,2);
	tmpLen += 2;
	cmd[1] = tmpLen-2;
	
	bRet = WriteFileEx(hFile, &XdfRec,ulOffset,ulLen,cmd,tmpLen,ulFileLen);
	//�����ռ���ǿ��������Ƭ���ٴγ���
	if (bRet == FALSE)
	{
		if (GetLastError() == NTE_NO_MEMORY)
		{
			GetCSPObject()->RemoveXdfFragment(&XdfRec);
			GetKeyOffsetInXdf(&XdfRec,m_ulIndex,ulOffset,ulLen);
			bRet = WriteFileEx(hFile, &XdfRec,ulOffset,ulLen,cmd,tmpLen,ulFileLen);
		}
	}
	GetCSPObject()->CloseFile(hFile);
	if (bRet == FALSE)
	{
		goto error_proc;
	}
	bRet = GetCSPObject()->SetXdf(DFTYPE_PRK,&XdfRec);
	if (bRet == FALSE)
	{
		goto error_proc;
	}
	GetCSPObject()->EndTransaction();

	GetCSPObject()->AddModify();
	
	return TRUE;
error_proc:
	GetCSPObject()->EndTransaction();
	return FALSE;
}

BOOL CCSPEccPrk::DestroyOnToken()
{
	GetCSPObject()->BeginTransaction();
	if(IsPrivate())
	{
		if(!GetCSPObject()->IsLogin()){
			GetCSPObject()->EndTransaction();
			SETLASTERROR(NTE_PERM);
			return FALSE;
		}
	}

	DWORD dwFileSize;
	FILEHANDLE hFile = NULL;
	if(!GetCSPObject()->OpenFile(g_cPathTable.prkdfPath, &hFile, &dwFileSize)){
		GetCSPObject()->EndTransaction();
		return FALSE;
	}

	SHARE_XDF XdfRec;
	if(!GetCSPObject()->GetXdf(DFTYPE_PRK,&XdfRec)){
		GetCSPObject()->CloseFile(hFile);
		GetCSPObject()->EndTransaction();
		return FALSE;
	}
	
	ULONG ulOffset,ulLen;
	if (!GetKeyOffsetInXdf(&XdfRec,m_ulIndex,ulOffset,ulLen)){
		GetCSPObject()->CloseFile(hFile);
		GetCSPObject()->EndTransaction();
		return FALSE;
	}

	//ֱ����ɾ�����
	BYTE data = DESTROIED_TAG;
	if(!GetCSPObject()->WriteFile(hFile, &data, 1, ulOffset)){
		GetCSPObject()->CloseFile(hFile);
		GetCSPObject()->EndTransaction();
		return FALSE;
	}
	
	XdfRec.cContent[ulOffset] = data;
	GetCSPObject()->SetXdf(DFTYPE_PRK, &XdfRec);
	GetCSPObject()->CloseFile(hFile);

	if(!GetCSPObject()->DeleteFile(m_RealObjPath)){
		GetCSPObject()->EndTransaction();
		return FALSE;
	}

	if (IsNeedHWCalc())
	{
		BYTE exFilePath[2];
		exFilePath[0] = (BYTE)(m_ulExFilePath >> 8);
		exFilePath[1] = (BYTE)m_ulExFilePath;
		if(!GetCSPObject()->DeleteFile(exFilePath)){
			GetCSPObject()->EndTransaction();
			return FALSE;
		}
	}
	
	GetCSPObject()->DeleteFile(m_CertPath);

	GetCSPObject()->EndTransaction();
	
	GetCSPObject()->AddModify();

	return TRUE;
}

BOOL CCSPEccPrk::ReadRealObject(
		)
{
	GetCSPObject()->BeginTransaction();
	if (IsPrivate())
	{
		if(!GetCSPObject()->IsLogin()){
			GetCSPObject()->EndTransaction();
			SETLASTERROR(NTE_PERM);
			return FALSE;
		}
	}

	if(m_RealObjReaded){
		GetCSPObject()->EndTransaction();
		return TRUE;
	}

	if (IsNeedHWCalc())
	{
		ULONG ulPathStart = (g_cPathTable.eccprkStartPath[0]<<8)
						+g_cPathTable.eccprkStartPath[1];
		ULONG ulPath = (m_RealObjPath[0]<<8) + m_RealObjPath[1];
		m_ulExFilePath = (g_cPathTable.eccprkexStarPath[0]<<8)
						+g_cPathTable.eccprkexStarPath[1];
		m_ulExFilePath += ulPath - ulPathStart;

		//selet the extersion file
		FILEHANDLE hFile = NULL;
		DWORD dwFileSize;
		BYTE FilePath[2];
		FilePath[0] = BYTE(m_ulExFilePath >> 8);
		FilePath[1] = BYTE(m_ulExFilePath);
		if(!GetCSPObject()->OpenFile(FilePath, &hFile, &dwFileSize))
			goto error_proc;

		/*//read ��ECC��Կ�ļ����ܶ�����ֻ�������ܿ��ڲ������������
		BYTE *tmp = new BYTE[dwFileSize];
		BOOL bRet = GetCSPObject()->ReadFile(hFile, dwFileSize, tmp, &dwFileSize, 0);

		ByteQueue bt;
		bt.Put(tmp,dwFileSize);
		delete tmp;
		m_pInvertableEcc = new InvertableECCFunction(bt);
		if(m_pEcc != NULL)
			delete m_pEcc;
		m_pEcc = new ECCFunction(m_pInvertableEcc->GetPubKey());
        
		
		if(!bRet){
			delete tmp;
			goto error_proc;
		}*/
		GetCSPObject()->CloseFile(hFile);	

	}
	else goto error_proc;

	GetCSPObject()->EndTransaction();
	m_RealObjReaded = TRUE;

	return TRUE;
error_proc:
	GetCSPObject()->EndTransaction();
	return FALSE;
}

BOOL CCSPEccPrk::LoadFromToken(
		ULONG ulIndex
		)
{
	m_ulIndex = ulIndex;
	SHARE_XDF XdfRec;
	GetCSPObject()->GetXdf(DFTYPE_PRK,&XdfRec);
	ULONG ulOffset,ulLen;
	if(!GetKeyOffsetInXdf(&XdfRec,m_ulIndex,ulOffset,ulLen))
		return FALSE;
	
	if (XdfRec.cContent[ulOffset] == DESTROIED_TAG)
	{
		SETLASTERROR(NTE_NO_KEY);
		return FALSE;
	}
	//Խ��tag��len
	ulOffset += 2;
	m_dwFlags = *((DWORD *)(XdfRec.cContent+ulOffset));
	ulOffset += sizeof(DWORD);
	m_bAuthId = *((BYTE *)(XdfRec.cContent+ulOffset));
	ulOffset += sizeof(BYTE);
	m_ulAlgId = *((ALG_ID *)(XdfRec.cContent+ulOffset));
	ulOffset += sizeof(ALG_ID);
	m_dwPermissions = *((DWORD *)(XdfRec.cContent+ulOffset));
	ulOffset += sizeof(DWORD);
	m_dwBitLen = *((DWORD *)(XdfRec.cContent+ulOffset));
	ulOffset += sizeof(DWORD);
	m_ulKeyLen = m_dwBitLen;
	m_dwBlockLen = m_dwBitLen;
	memcpy(&m_RealObjPath,XdfRec.cContent+ulOffset,2);
	ulOffset += 2;
	memcpy(&m_CertPath,XdfRec.cContent+ulOffset,2);

	m_ulExFilePath = (m_RealObjPath[0]<<8) + m_RealObjPath[1]
		- (g_cPathTable.eccprkStartPath[0]<<8) - g_cPathTable.eccprkStartPath[1]
		+ (g_cPathTable.eccprkexStarPath[0]<<8) + g_cPathTable.eccprkexStarPath[1];

	
	return TRUE;

}
//-----------------------------------------------------------
/*
���ܣ�����˽Կ��������(���ʵ��)
���룺pData---�����ܵ����ݣ�����ȡģ��
�����pData�������ܺ������
˵�����ú��������κ����
	  ��Կ�ĸ����Ѿ���������ݶ�Ӧ��ʱbig-endian
*/
//-----------------------------------------------------------
BOOL CCSPEccPrk::SWRawEccDecryption(
	BYTE * pData,
	BYTE *pDataOut,
	DWORD *dwOutDataLen
	)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;

}

//-----------------------------------------------------------
/*
���ܣ�����˽Կ��������(Ӳ����ʵ��)
���룺pData---�����ܵ����ݣ�����ȡģ��
�����pData�������ܺ������
˵�����ú��������κ����
	  ��Կ�ĸ����Ѿ���������ݶ�Ӧ��ʱbig-endian
*/
//-----------------------------------------------------------
BOOL CCSPEccPrk::HWRawEccDecryption(
	BYTE * pData,
	BYTE *pDataOut,
	DWORD *pdwOutDataLen
	)
{
	if(GetCSPObject()->GetCardType() == CPU_PKI){
		//��ʼ����
		GetCSPObject()->BeginTransaction();

		BYTE pbCmd[256];
		pbCmd[0] = 0x80;
		pbCmd[1] = 0xC4;
		pbCmd[2] = m_RealObjPath[0];
		pbCmd[3] = m_RealObjPath[1];
		pbCmd[4] = 0x48;
		memcpy(pbCmd + 5, pData, 0x48);
		*pdwOutDataLen = 24;
		BOOL bRetVal = GetCSPObject()->SendCommand(
			pbCmd, pbCmd[4]+5, pDataOut, pdwOutDataLen
			);

		//��������
		GetCSPObject()->EndTransaction();

		return bRetVal;
	}
	else
		return FALSE;


}

BOOL CCSPEccPrk::SWRawEccSign(
	BYTE * pData,
	BYTE *pDataOut,
	DWORD *dwOutDataLen
	)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;

}

BOOL CCSPEccPrk::HWRawEccSign(
	BYTE * pData,
	BYTE *pDataOut,
	DWORD *pdwOutDataLen
	)
{
	if(GetCSPObject()->GetCardType() == CPU_PKI){
		//��ʼ����
		GetCSPObject()->BeginTransaction();

		BYTE pbCmd[256];
		pbCmd[0] = 0x80;
		pbCmd[1] = 0xD0;
		pbCmd[2] = m_RealObjPath[0];
		pbCmd[3] = m_RealObjPath[1];
		pbCmd[4] = 0x18;
		memcpy(pbCmd + 5, pData, 0x18);
		*pdwOutDataLen = 24;
		BOOL bRetVal = GetCSPObject()->SendCommand(
			pbCmd, pbCmd[4]+5, pDataOut, pdwOutDataLen
			);

		//��������
		GetCSPObject()->EndTransaction();

		return bRetVal;
	}
	else
		return FALSE;


}

BOOL CCSPEccPrk::SignHash(
	CCSPHashObject* pHash,
	LPCWSTR sDescription,
	DWORD dwFlags,
	BYTE* pbSignature,
	DWORD* pdwSigLen
	)
{
	//�������
	if(pdwSigLen == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}	

	//��ȡ����
	if (!ReadRealObject())
		return FALSE;

	//��ȡHASHֵ
	DWORD cbHash = 0;
	BOOL bRetVal = pHash->GetValue(NULL, &cbHash);
	if(bRetVal == FALSE)
		return FALSE;
	LPBYTE pbHash = new BYTE[cbHash];
	if(pbHash == NULL){
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}

	bRetVal = pHash->GetValue(pbHash, &cbHash);
	if(bRetVal == FALSE){
		delete pbHash;
		return FALSE;
	}
	
	//ǩ��ǰ�������
	LPBYTE pbUnpadData = NULL;
	DWORD cbUnpadData = 0;
	switch(dwFlags){
	case 0:
		{
			switch (pHash->GetAlgId()){	
			case CALG_SHA:
				cbUnpadData = cbHash + SHAdecorationlen;
				pbUnpadData = new BYTE[cbUnpadData];
				memcpy(pbUnpadData, SHAdecoration, SHAdecorationlen);
				memcpy(pbUnpadData + SHAdecorationlen, pbHash, cbHash);
				break;
			case CALG_MD5:
				cbUnpadData = cbHash + MD5decorationlen;
				pbUnpadData = new BYTE[cbUnpadData];
				memcpy(pbUnpadData, MD5decoration, MD5decorationlen);
				memcpy(pbUnpadData + MD5decorationlen, pbHash, cbHash);
				break;
			case CALG_SSL3_SHAMD5:
				cbUnpadData = cbHash;
				pbUnpadData = new BYTE[cbUnpadData];
				memcpy(pbUnpadData, pbHash, cbHash);
				break;
			}
		}
		break;
	case CRYPT_NOHASHOID:
		cbUnpadData = cbHash;
		pbUnpadData = new BYTE[cbUnpadData];
		memcpy(pbUnpadData, pbHash, cbHash);
		break;
	default:
		delete pbHash;
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}
	delete pbHash;
	if(pbUnpadData == NULL){
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}

	ECCPad pad;
	DWORD dwPadDataLen = 0 ;
	BOOL bRet = pad.Pad(pbUnpadData,cbUnpadData,NULL,dwPadDataLen,m_dwBitLen/8);
	if (!bRet) {
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}

	LPBYTE pbPadedData = new BYTE[dwPadDataLen];
	if(pbPadedData == NULL){
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}

	//���õ�Ŀ��ֻ��Ϊ���ж�����Ĵ�С
	if(pbSignature == NULL){
		(*pdwSigLen) = dwPadDataLen*3;
		return TRUE;
	}

	//�ж�����ռ��Ƿ��㹻
	if((*pdwSigLen) < dwPadDataLen*3){
		SETLASTERROR(ERROR_MORE_DATA);
		return FALSE;
	}
	
	bRet = pad.Pad(pbUnpadData,cbUnpadData,pbPadedData,dwPadDataLen,m_dwBitLen/8);
	if (!bRet) {
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}	
	delete pbUnpadData;

	DWORD nLen =0;//���ڼ������ݳ���
	for(int i = 0; i < dwPadDataLen; i += (m_dwBitLen/ 8)){
		//˽Կǩ��
		if(IsNeedHWCalc())
			bRetVal = HWRawEccSign(pbPadedData+i,pbSignature+nLen,pdwSigLen);//  [10/19/2007]
		else
			bRetVal = SWRawEccSign(pbPadedData+i,pbSignature+nLen,pdwSigLen);//  [10/19/2007]
		if(!bRetVal){
			delete pbPadedData;
			SETLASTERROR(NTE_FAIL);
			return FALSE;
		}
		nLen += *pdwSigLen;
	}

    *pdwSigLen = nLen;
	//���
	delete pbPadedData;
	SwapInt(pbSignature, *pdwSigLen);
	
	return TRUE;
}

BOOL CCSPEccPrk::Decrypt(
	CCSPHashObject* pHash,
	BOOL Final,
	DWORD dwFlags,
	BYTE* pbData,
	DWORD* pdwDataLen
	)
{
	//�������
	if(pdwDataLen == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	//�ж��Ƿ���������Ҫ����
	if(pbData == NULL){
		(*pdwDataLen) = 0;
		return TRUE;
	}
	if((*pdwDataLen) == 0)
		return TRUE;

	//�������ݱ�����ģ����������
	DWORD cbInputData = *pdwDataLen;
	if(cbInputData % (m_dwBitLen / 8) != 0){
		SETLASTERROR(NTE_BAD_DATA);
		return FALSE;
	}

	//������������
	LPBYTE pbInputData = new BYTE[cbInputData];
	if(pbInputData == NULL){
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}
	memcpy(pbInputData, pbData, cbInputData);

	//�����������ݵ�˳��
	SwapInt(pbInputData, cbInputData);
	
	//��ȡ˽Կ����
	if(!ReadRealObject()){
		delete [] pbInputData;
		return FALSE;
	}
	
	BOOL bRetVal = TRUE;
	DWORD dwDataOutLen = 0; 
	DWORD nLen =0;//���ڼ�����ܺ����ݳ���
	for(int i = 0; i < cbInputData; i += (m_dwBitLen*3 / 8)){
		//˽Կ����
		if(IsNeedHWCalc())
			bRetVal = HWRawEccDecryption(pbInputData + i,pbData+nLen,pdwDataLen);
		else
			bRetVal = SWRawEccDecryption(pbInputData + i,pbData+nLen,pdwDataLen);
		if(!bRetVal){
			delete [] pbInputData;
			SETLASTERROR(NTE_FAIL);
			return FALSE;
		}
		nLen += *pdwDataLen;
	}	
	//		ȥ�����
	ECCPad pad;
	
	bool bRet = pad.UnPad(pbData,nLen,NULL,dwDataOutLen,m_dwBitLen/8);
	if (!bRet){
		delete pbInputData;
		SETLASTERROR(NTE_FAIL);
		return false;
	}
	LPBYTE pbUnpaddedData = new BYTE[dwDataOutLen];
	if(pbUnpaddedData == NULL){
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}

	bRet = pad.UnPad(pbData,nLen,pbUnpaddedData,dwDataOutLen,m_dwBitLen/8);
	memcpy(pbData, pbUnpaddedData, dwDataOutLen);
	
	//�Խ��ܺ��������HASH����
	if(pHash != NULL){
		bRetVal = pHash->HashData(pbData, dwDataOutLen, NULL);
		if(!bRetVal){
			delete [] pbUnpaddedData;
			delete [] pbInputData;
			return FALSE;
		}
	}
	if (pbUnpaddedData != NULL) {
		delete [] pbUnpaddedData;
	}		
	
	
	delete [] pbInputData;
	*pdwDataLen = dwDataOutLen;
	return TRUE;
}

BOOL CCSPEccPrk::Import(
	CONST BYTE *pbData,
	DWORD  dwDataLen,
	CCSPKey *pPubKey,
	DWORD dwFlags
	)
{
	SETLASTERROR(NTE_FAIL);
	return FALSE;
}

BOOL CCSPEccPrk::Export(
	CCSPKey *pPubKey,
	DWORD dwBlobType,
	DWORD dwFlags,
	BYTE *pbKeyBlob,
	DWORD *dwKeyBlobLen
	)
{
	SETLASTERROR(NTE_FAIL);
	return FALSE;
}

BOOL CCSPEccPrk::GetKeyOffsetInXdf(
		SHARE_XDF *pXdfRec,
		ULONG ulIndex,
		ULONG& ulOffset,
		ULONG& ulLen
		)
{
	ulOffset = 0;
	ulLen = 0;
	if (!GetCSPObject()->GetOffsetFormIndex(pXdfRec,ulIndex,ulOffset,ulLen))
		return FALSE;
	ULONG ulTagfieldLen,ulLenfieldLen;
	GetDERLen(pXdfRec->cContent+ulOffset,ulLen,ulTagfieldLen,ulLenfieldLen);
	ulOffset += (ulTagfieldLen+ulLenfieldLen);
	ulLen -= (ulTagfieldLen+ulLenfieldLen);
	//name
	ulOffset += GetDERTotalStrLen(pXdfRec->cContent+ulOffset,ulLen);
	
	ulLen = GetDERTotalStrLen(pXdfRec->cContent+ulOffset,ulLen);
	if (m_ulAlgId == g_dwEccKeyxAlgid)
		return TRUE;
	else if (m_ulAlgId == g_dwEccSignAlgid)
	{
		ulOffset += ulLen;
		ulLen = GetDERTotalStrLen(pXdfRec->cContent+ulOffset,ulLen);
		return TRUE;
	}
	else
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}
}

BOOL CCSPEccPrk::SetParam(
		DWORD dwParam,           // in
		BYTE *pbData,            // in
		DWORD dwFlags            // in
		)
{
	BOOL bRet;
	FILEHANDLE hFile = NULL;
	if (dwParam == KP_PERMISSIONS)
	{
		GetCSPObject()->BeginTransaction();

		FILEHANDLE hFile = NULL;
		if(!GetCSPObject()->OpenFile(g_cPathTable.prkdfPath, &hFile, NULL)){
			GetCSPObject()->EndTransaction();
			return FALSE;
		}

		SHARE_XDF XdfRec;
		GetCSPObject()->GetXdf(DFTYPE_PRK,&XdfRec);
		ULONG ulOffset,ulLen;
		GetKeyOffsetInXdf(&XdfRec,m_ulIndex,ulOffset,ulLen);
		
		//Խ��tag��len
		ulOffset += 2;
		ulOffset += 9;
		bRet = GetCSPObject()->WriteFile(hFile, pbData, sizeof(DWORD), ulOffset);
		GetCSPObject()->CloseFile(hFile);
		GetCSPObject()->EndTransaction();

		if(bRet == FALSE)
			return FALSE;
		GetCSPObject()->AddModify();
	}
	else if (dwParam == KP_CERTIFICATE)
	{
		DWORD dwLen = 0;
		BYTE path[2];
		if (pbData == NULL)
		{
			if ((m_CertPath[0] ==0)&&(m_CertPath[1] ==0))
			{
				return TRUE;
			}
			else
			{
				GetCSPObject()->BeginTransaction();
				GetCSPObject()->DeleteFile(m_CertPath);
				GetCSPObject()->EndTransaction();
				memset(path, 0, sizeof(path));
				memset(m_CertPath, 0, sizeof(m_CertPath));
			}
		}
		else{
			dwLen = GetDERTotalStrLen(pbData,5);
			GetCSPObject()->BeginTransaction();
			if (((m_CertPath[0]!=0)||(m_CertPath[1]!=0))&&(dwLen <= m_arbCert.GetSize()))
			{
				//��֤����ڣ��޸�֤�飩��֤��ĳ���С�ڵ�ǰ��֤��
				memcpy(path,m_CertPath,2);
			}
			else
			{
				GetCSPObject()->DeleteFile(m_CertPath);
				WORD flag = 0x0000|FILETYPE_CERT|FILE_UNUSED;
				bRet = GetCSPObject()->GetWorkableFile(flag,dwLen,path);
				if (bRet == FALSE){
					GetCSPObject()->EndTransaction();
					return FALSE;
				}
			}

			if(!GetCSPObject()->OpenFile(path, &hFile, NULL)){
				GetCSPObject()->EndTransaction();
				return FALSE;
			}

			bRet = GetCSPObject()->WriteFile(hFile, pbData, dwLen, 0);
			GetCSPObject()->CloseFile(hFile);
			if(!bRet){
				GetCSPObject()->EndTransaction();
				return FALSE;
			}
		}

		//���������ļ�
		if(!GetCSPObject()->OpenFile(g_cPathTable.prkdfPath, &hFile, NULL)){
			GetCSPObject()->EndTransaction();
			return FALSE;
		}

		SHARE_XDF XdfRec;
		GetCSPObject()->GetXdf(DFTYPE_PRK,&XdfRec);
		ULONG ulOffset,ulLen;
		GetKeyOffsetInXdf(&XdfRec,m_ulIndex,ulOffset,ulLen);
		
		//Խ��tag��len
		ulOffset += 2;
		ulOffset += 19;
		bRet = GetCSPObject()->WriteFile(hFile, path, 2, ulOffset);
		GetCSPObject()->CloseFile(hFile);
		if (bRet == FALSE)
		{
			GetCSPObject()->EndTransaction();
			return FALSE;
		}

		m_CertPath[0] = path[0];
		m_CertPath[1] = path[1];
		
		memcpy(XdfRec.cContent+ulOffset, m_CertPath, 2);
		GetCSPObject()->SetXdf(DFTYPE_PRK, &XdfRec);

		m_arbCert.RemoveAll();
		CopyByteToArray(m_arbCert,pbData,dwLen);
		GetCSPObject()->EndTransaction();
		GetCSPObject()->AddModify();
		return TRUE;
	}
	return CCSPEccPuk::SetParam(dwParam,pbData,dwFlags);
}

BOOL CCSPEccPrk::GetParam(
		DWORD dwParam,          // in
		BYTE *pbData,           // out
		DWORD *pdwDataLen,      // in, out
		DWORD dwFlags			// in
		)
{
	if (dwParam == KP_CERTIFICATE)
	{
		BOOL bRet;
		bRet = ReadCert();
		if (bRet == FALSE)
			return FALSE;
		
		return FillDataBuffer(pbData,pdwDataLen,m_arbCert.GetData(),m_arbCert.GetSize());
	}
	return CCSPEccPuk::GetParam(dwParam,pbData,pdwDataLen,dwFlags);
}

BOOL CCSPEccPrk::ReadCert()
{
	if (m_arbCert.GetSize()>0)
		return TRUE;
	if ((m_CertPath[0]!=0)|(m_CertPath[1]!=0))
	{
		GetCSPObject()->BeginTransaction();

		FILEHANDLE hFile = NULL;
		DWORD dwFileSize;
		if(!GetCSPObject()->OpenFile(m_CertPath, &hFile, &dwFileSize)){
			GetCSPObject()->EndTransaction();
			return FALSE;
		}
		BYTE *tmp = new BYTE[dwFileSize];
		if(!GetCSPObject()->ReadFile(hFile, dwFileSize, tmp, &dwFileSize, 0)){
			delete tmp;
			GetCSPObject()->EndTransaction();
			return FALSE;
		}

		dwFileSize = GetDERTotalStrLen(tmp,dwFileSize);
		CopyByteToArray(m_arbCert,tmp,dwFileSize);
		delete tmp;
		GetCSPObject()->EndTransaction();
		return TRUE;
	}
	else
	{
		SETLASTERROR(NTE_BAD_TYPE);
		return FALSE;
	}
}

BOOL CCSPEccPrk::IsNeedHWGenKey()
{
	return IsNeedHWCalc();
}