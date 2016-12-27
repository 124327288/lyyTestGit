//CSPRsaPrk.cpp
#include <stdAfx.h>
#include "cspkey.h"
#include "DERCoding.h"

#include "Integer.h"
#include "pkcspad.h"
#include "queue.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CCSPRsaPrk::CCSPRsaPrk(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken
		):CCSPRsaPuk(pKeyContainer, ulAlgId,bToken)
{
	m_ulExFilePath = 0;
	m_pInvertableRsa = NULL;
	m_CertPath[0] = 0;
	m_CertPath[1] = 0;
	m_pubID[0] =0;
	m_pubID[1] =0;
	hPubFile = NULL;
	m_ulAlgId = ulAlgId;
}

CCSPRsaPrk::CCSPRsaPrk(
		CCSPRsaPrk & src
		) : CCSPRsaPuk(src)
{
	if (!src.m_pInvertableRsa)
	{
		Integer n = src.m_pInvertableRsa->GetModulus();
		Integer e = src.m_pInvertableRsa->GetExponent();
		Integer d = src.m_pInvertableRsa->GetDecryptionExponent();
		Integer p = src.m_pInvertableRsa->GetPrime1();
		Integer q = src.m_pInvertableRsa->GetPrime2();
		Integer dp = src.m_pInvertableRsa->GetExponent1();
		Integer dq = src.m_pInvertableRsa->GetExponent2();
		Integer u = src.m_pInvertableRsa->GetCoefficient();
		if (m_pInvertableRsa)
		{
			delete m_pInvertableRsa;
			m_pInvertableRsa = NULL;
		}
		m_pInvertableRsa = new InvertableRSAFunction(n,e,d,p,q,dp,dq,u);
	}
	m_ulExFilePath = src.m_ulExFilePath;
	memcpy(m_CertPath,src.m_CertPath,2);
	m_arbCert.Copy(src.m_arbCert);
	m_ulAlgId = src.m_ulAlgId;
}

CCSPRsaPrk::~CCSPRsaPrk()
{
	if (m_pInvertableRsa)
	{
		delete m_pInvertableRsa;
		m_pInvertableRsa = NULL;
	}
	m_arbCert.RemoveAll();
	
	if (NULL != hPubFile)
	{
		GetCSPObject()->BeginTransaction();
		GetCSPObject()->DeleteFile(m_pubID);
		GetCSPObject()->EndTransaction();
		hPubFile = NULL;
	}
	CCSPRsaPuk::~CCSPRsaPuk();
}

BOOL CCSPRsaPrk::Create(
		DWORD bitlen,
		DWORD pubexp,
		CONST BYTE* modulus,
		CONST BYTE* prime1,
		CONST BYTE* prime2,
		CONST BYTE* exponent1,
		CONST BYTE* exponent2,
		CONST BYTE* coefficient,
		CONST BYTE* privateExponent
		)
{

	if (modulus == NULL)
		return SWGenKey(bitlen,pubexp);
	m_dwBitLen = bitlen; 
	CCSPRsaPuk::Create(bitlen,pubexp,modulus);

	BYTE * tmp = new BYTE[bitlen/8];

	memcpy(tmp,modulus,bitlen/8);
	SwapInt(tmp,bitlen/8);
	Integer n(tmp,bitlen/8);

	Integer e(pubexp);

	memcpy(tmp,privateExponent,bitlen/8);
	SwapInt(tmp,bitlen/8);
	Integer d(tmp,bitlen/8);

	memcpy(tmp,prime1,bitlen/16);
	SwapInt(tmp,bitlen/16);
	Integer p(tmp,bitlen/16);

	memcpy(tmp,prime2,bitlen/16);
	SwapInt(tmp,bitlen/16);
	Integer q(tmp,bitlen/16);

	memcpy(tmp,exponent1,bitlen/16);
	SwapInt(tmp,bitlen/16);
	Integer dp(tmp,bitlen/16);

	memcpy(tmp,exponent2,bitlen/16);
	SwapInt(tmp,bitlen/16);
	Integer dq(tmp,bitlen/16);

	memcpy(tmp,coefficient,bitlen/16);
	SwapInt(tmp,bitlen/16);
	Integer u(tmp,bitlen/16);

	delete tmp;

	if (m_pInvertableRsa)
	{
		delete m_pInvertableRsa;
		m_pInvertableRsa = NULL;
	}
	m_pInvertableRsa = new InvertableRSAFunction(n,e,d,p,q,dp,dq,u);
	

	
	return TRUE;
}

BOOL CCSPRsaPrk::Create(
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

BOOL CCSPRsaPrk::HWGenKey(
		DWORD bitlen,
		DWORD pubexp
		)
{
	ASSERT(pubexp == 65537);
	m_dwBlockLen = bitlen;
	m_dwBitLen = bitlen;
	m_ulKeyLen = bitlen;

	if (m_pInvertableRsa)
	{
		delete m_pInvertableRsa;
		m_pInvertableRsa = NULL;
	}

	if(m_pRsa)
	{
		delete m_pRsa;
		m_pRsa = NULL;
	}

	if (m_dwFlags & CRYPT_USER_PROTECTED)
		m_bAuthId = DEFAULT_AUTH_ID;

	GetCSPObject()->BeginTransaction();
	
	if (IsPrivate())
	{
		if(!GetCSPObject()->Login()){
			GetCSPObject()->EndTransaction();
			SETLASTERROR(NTE_PERM);
			return FALSE;
		}
	}
	
	BOOL bRet;
	if ((m_RealObjPath[0] ==0)&&(m_RealObjPath[1] ==0))
	{
		if(GetCSPObject()->GetCardType() == CPU_PKI){
			//创建私钥及其扩展文件
			WORD flag = 0x0000|FILETYPE_PRKEX | FILE_UNUSED | (m_bAuthId<<8);//WORD flag = 0x0000|FILETYPE_PRKEX | FILE_UNUSED | (m_bAuthId<<8);
			bRet = GetCSPObject()->GetWorkableFile(flag, g_cPathTable.rsaPrkExFileLen, m_RealObjPath);
			if (bRet == FALSE)
			{
				GetCSPObject()->EndTransaction();
				return FALSE;
			}
			//创建公钥文件
			BYTE pukFilePath[2] = {0, 0};
			flag = 0x0000|FILETYPE_PUK | FILE_UNUSED;//flag = 0x0000|FILETYPE_PUK | FILE_UNUSED| (m_bAuthId<<8);
			bRet = GetCSPObject()->GetWorkableFile(flag, g_cPathTable.rsaPukFileLen, pukFilePath);
			if (bRet == FALSE)
			{
				GetCSPObject()->EndTransaction();
				return FALSE;
			}


			if (bitlen ==1024)
			{
				//产生密钥对后直接写入公私钥文件中
				BYTE pbCmd[256];
				memcpy(pbCmd, "\x80\x46\x00\x00\x04", 5);
				//私钥文件标识符
				memcpy(pbCmd + 5, m_RealObjPath, 2);
				//公钥文件标符
				memcpy(pbCmd + 7, pukFilePath, 2);
				
				bRet = GetCSPObject()->SendCommand(pbCmd, pbCmd[4] + 5);
				if (bRet == FALSE)
				{
					GetCSPObject()->EndTransaction();
					return FALSE;
				}
				memcpy(m_pubID, pukFilePath, 2);
				//读取公钥(N, e)后,删除公钥文件
				BYTE *pbPubKeyData = new BYTE[1024 / 8 + 4];
				FILEHANDLE hPukFile = NULL;
				bRet = GetCSPObject()->OpenFile(pukFilePath, &hPukFile);
				if (bRet == FALSE)
				{
					GetCSPObject()->EndTransaction();
					return FALSE;
				}
				DWORD dwPubKeyDataLen;
				bRet = GetCSPObject()->ReadFile(hPukFile, 0x80 + 4, pbPubKeyData, &dwPubKeyDataLen);
				GetCSPObject()->CloseFile(hPukFile);
				if (bRet == FALSE)
				{
					GetCSPObject()->EndTransaction();
					return FALSE;
				}
				GetCSPObject()->DeleteFile(pukFilePath);
				
				m_pRsa = new RSAFunction(Integer(pbPubKeyData, 0x80),Integer(pbPubKeyData + 0x80, 4));
			}
			else if (bitlen == 2048)
			{
				
				//产生密钥对后直接写入公私钥文件中
				//80 36 01 00 04 
				BYTE pbCmd[256];
				memcpy(pbCmd, "\x80\x36\x01\x00\x04", 5);
				//私钥文件标识符
				memcpy(pbCmd + 7, m_RealObjPath, 2);
				//公钥文件标符
				memcpy(pbCmd + 5, pukFilePath, 2);
				bRet = GetCSPObject()->SendCommand(pbCmd, pbCmd[4] + 5);
				if (bRet == FALSE)
				{
					GetCSPObject()->EndTransaction();
					return FALSE;
				}
				memcpy(m_pubID, pukFilePath, 2);
				//读取公钥(N, e)后,删除公钥文件
				BYTE *pbPubKeyData = new BYTE[2048 / 8 + 4];
				FILEHANDLE hPukFile = NULL;
				bRet = GetCSPObject()->OpenFile(pukFilePath, &hPukFile);
				if (bRet == FALSE)
				{
					GetCSPObject()->EndTransaction();
					return FALSE;
				}
				DWORD dwPubKeyDataLen;
				bRet = GetCSPObject()->ReadFile(hPukFile, 0x100 + 4, pbPubKeyData, &dwPubKeyDataLen);
				GetCSPObject()->CloseFile(hPukFile);
				if (bRet == FALSE)
				{
					GetCSPObject()->EndTransaction();
					return FALSE;
				}
				GetCSPObject()->DeleteFile(pukFilePath);
				
				m_pRsa = new RSAFunction(Integer(pbPubKeyData, 0x100),Integer(pbPubKeyData + 0x100, 4));
			}
		}
		else
		{
			GetCSPObject()->EndTransaction();
			return FALSE;
		}
	}
	GetCSPObject()->EndTransaction();
	return TRUE;
}

BOOL CCSPRsaPrk::SWGenKey(
		DWORD bitlen,
		DWORD pubexp 
		)
{
	m_dwBlockLen = bitlen;
	m_dwBitLen = bitlen;
	m_ulKeyLen = bitlen;

	if (m_pInvertableRsa)
	{
		delete m_pInvertableRsa;
		m_pInvertableRsa = NULL;
	}
	m_pInvertableRsa = new InvertableRSAFunction(g_rng,bitlen,pubexp);
	if (m_pRsa)
	{
		delete m_pRsa;
		m_pRsa = NULL;
	}
	m_pRsa = new RSAFunction(m_pInvertableRsa->GetModulus(),
	m_pInvertableRsa->GetExponent());
	
	return TRUE;
}


BOOL CCSPRsaPrk::CreateOnToken(
		ULONG ulIndex
		)
{
	ASSERT(m_bToken == TRUE);
	GetCSPObject()->BeginTransaction();
	if (IsPrivate())
	{
		if(!GetCSPObject()->Login()){
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
		//以私钥文件的方式保存

		//查找可以用于保存私钥的路径
		WORD ulStaus = 0x9000;
		if ((m_RealObjPath[0] ==0)&&(m_RealObjPath[1] ==0))
		{
			if(GetCSPObject()->GetCardType() == CPU_PKI){
				//创建私钥及其扩展文件
				WORD flag = 0x0000|FILETYPE_PRKEX|FILE_UNUSED;
				flag |= (m_bAuthId<<8);
				bRet = GetCSPObject()->GetWorkableFile(flag, g_cPathTable.rsaPrkExFileLen, m_RealObjPath);
				if (bRet == FALSE)
					goto error_proc;
			
				//选择私钥文件并写入私钥
				FILEHANDLE hPriFile = NULL;
				bRet = GetCSPObject()->OpenFile(m_RealObjPath, &hPriFile);
				if (bRet == FALSE)
					goto error_proc;

				if (m_dwBitLen == 1024)
				{
					//P, Q, DP, DQ, QINV, E
					BYTE pbPriKeyData[0x40*5]; //BYTE pbPriKeyData[0x40*5 + 4];
					DWORD dwPriKeyDataLen = 0;
					m_pInvertableRsa->GetPrime1().Encode(pbPriKeyData + dwPriKeyDataLen, 0x40);
					dwPriKeyDataLen += 0x40;
					m_pInvertableRsa->GetPrime2().Encode(pbPriKeyData + dwPriKeyDataLen, 0x40);
					dwPriKeyDataLen += 0x40;
					m_pInvertableRsa->GetExponent1().Encode(pbPriKeyData + dwPriKeyDataLen, 0x40);
					dwPriKeyDataLen += 0x40;
					m_pInvertableRsa->GetExponent2().Encode(pbPriKeyData + dwPriKeyDataLen, 0x40);
					dwPriKeyDataLen += 0x40;
					m_pInvertableRsa->GetCoefficient().Encode(pbPriKeyData + dwPriKeyDataLen, 0x40);
					dwPriKeyDataLen += 0x40;
					//m_pInvertableRsa->GetExponent().Encode(pbPriKeyData + dwPriKeyDataLen, 0x04);
					//dwPriKeyDataLen += 0x04;

					bRet = GetCSPObject()->WriteFile(hPriFile, pbPriKeyData, dwPriKeyDataLen);
					GetCSPObject()->CloseFile(hPriFile);					
					if (bRet == FALSE)
						goto error_proc;
				}
				else if (m_dwBitLen == 2048)//add to support rsa 2048
				{
					//P, Q, DP, DQ, QINV, E
					BYTE pbPriKeyData[0x80*5];//不用添上E//BYTE pbPriKeyData[0x80*5 + 4];
					DWORD dwPriKeyDataLen = 0;
					m_pInvertableRsa->GetPrime1().Encode(pbPriKeyData + dwPriKeyDataLen, 0x80);
					dwPriKeyDataLen += 0x80;
					m_pInvertableRsa->GetPrime2().Encode(pbPriKeyData + dwPriKeyDataLen, 0x80);
					dwPriKeyDataLen += 0x80;
					m_pInvertableRsa->GetExponent1().Encode(pbPriKeyData + dwPriKeyDataLen, 0x80);
					dwPriKeyDataLen += 0x80;
					m_pInvertableRsa->GetExponent2().Encode(pbPriKeyData + dwPriKeyDataLen, 0x80);
					dwPriKeyDataLen += 0x80;
					m_pInvertableRsa->GetCoefficient().Encode(pbPriKeyData + dwPriKeyDataLen, 0x80);
					dwPriKeyDataLen += 0x80;
					//m_pInvertableRsa->GetExponent().Encode(pbPriKeyData + dwPriKeyDataLen, 0x04);
					//dwPriKeyDataLen += 0x04;

					bRet = GetCSPObject()->WriteFile(hPriFile, pbPriKeyData, dwPriKeyDataLen);
					GetCSPObject()->CloseFile(hPriFile);					
					if (bRet == FALSE)
						goto error_proc;
				}
				else goto error_proc;	
			}
			else goto error_proc;
			
		}
		//select the extension file that hold the puk
		m_ulExFilePath = (m_RealObjPath[0]<<8) + m_RealObjPath[1]
			- (g_cPathTable.prkStartPath[0]<<8) - g_cPathTable.prkStartPath[1]
			+ (g_cPathTable.prkexStarPath[0]<<8) + g_cPathTable.prkexStarPath[1];

		BYTE ExFilePath[2];
		ExFilePath[0] = BYTE(m_ulExFilePath >> 8);
		ExFilePath[1] = BYTE(m_ulExFilePath);
		FILEHANDLE hExFile = NULL;
		bRet = GetCSPObject()->OpenFile(ExFilePath, &hExFile, NULL);
		if (bRet == FALSE)
			goto error_proc;
		
		ByteQueue bt;
		m_pRsa->DEREncode(bt);
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
	}
	else
	{
			goto error_proc;
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
	//超出空间则强制整理碎片后再次尝试
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

BOOL CCSPRsaPrk::DestroyOnToken()
{
	GetCSPObject()->BeginTransaction();
	if(IsPrivate())
	{
		if(!GetCSPObject()->Login()){
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

	//直接置删除标记
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

BOOL CCSPRsaPrk::ReadRealObject(
		)
{
	GetCSPObject()->BeginTransaction();
	if (IsPrivate())
	{
		if(!GetCSPObject()->Login()){
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
		ULONG ulPathStart = (g_cPathTable.prkStartPath[0]<<8)
						+g_cPathTable.prkStartPath[1];
		ULONG ulPath = (m_RealObjPath[0]<<8) + m_RealObjPath[1];
		m_ulExFilePath = (g_cPathTable.prkexStarPath[0]<<8)
						+g_cPathTable.prkexStarPath[1];
		m_ulExFilePath += ulPath - ulPathStart;

		//selet the extersion file
		FILEHANDLE hFile = NULL;
		DWORD dwFileSize;
		BYTE FilePath[2];
		FilePath[0] = BYTE(m_ulExFilePath >> 8);
		FilePath[1] = BYTE(m_ulExFilePath);
		if(!GetCSPObject()->OpenFile(FilePath, &hFile, &dwFileSize))
			goto error_proc;

		//read n,e
		BYTE *tmp = new BYTE[dwFileSize];
		BOOL bRet = GetCSPObject()->ReadFile(hFile, dwFileSize, tmp, &dwFileSize, 0);
		GetCSPObject()->CloseFile(hFile);
		if(!bRet){
			delete tmp;
			goto error_proc;
		}
			
		ByteQueue bt;
		bt.Put(tmp,dwFileSize);
		delete tmp;
		if(m_pRsa != NULL)
			delete m_pRsa;
		m_pRsa = new RSAFunction(bt);
	}
	else
	{		
		goto error_proc;
	}

	GetCSPObject()->EndTransaction();
	m_RealObjReaded = TRUE;

	return TRUE;
error_proc:
	GetCSPObject()->EndTransaction();
	return FALSE;
}

BOOL CCSPRsaPrk::LoadFromToken(
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
	//越过tag和len
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
		- (g_cPathTable.prkStartPath[0]<<8) - g_cPathTable.prkStartPath[1]
		+ (g_cPathTable.prkexStarPath[0]<<8) + g_cPathTable.prkexStarPath[1];

	
	return TRUE;

}
//-----------------------------------------------------------
/*
功能：利用私钥解密数据(软件实现)
输入：pData---待解密的数据，长度取模长
输出：pData－－解密后的数据
说明：该函数不作任何填充
	  密钥的各项已经输入的数据都应该时big-endian
*/
//-----------------------------------------------------------
BOOL CCSPRsaPrk::SWRawRSADecryption(
	BYTE * pData
	)
{
	
	Integer x(pData,m_dwBitLen/8);

	if (m_pInvertableRsa)
		m_pInvertableRsa->CalculateInverse(x).Encode(pData,m_dwBitLen/8);
	else
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}
	return TRUE;
}

//-----------------------------------------------------------
/*
功能：利用私钥解密数据(硬件件实现)
输入：pData---待解密的数据，长度取模长
输出：pData－－解密后的数据
说明：该函数不作任何填充
	  密钥的各项已经输入的数据都应该时big-endian
*/
//-----------------------------------------------------------
BOOL CCSPRsaPrk::HWRawRSADecryption(
	BYTE * pData
	)
{
	if(GetCSPObject()->GetCardType() == CPU_PKI){
		//开始事务
		GetCSPObject()->BeginTransaction();
		
		if (m_dwBitLen == 1024)
		{
			BYTE pbCmd[256];
			pbCmd[0] = 0x80;
			pbCmd[1] = 0xC8;
			pbCmd[2] = m_RealObjPath[0];
			pbCmd[3] = m_RealObjPath[1];
			pbCmd[4] = 0x80;
			memcpy(pbCmd + 5, pData, 0x80);
			DWORD dwOutDataLen;
			BOOL bRetVal = GetCSPObject()->SendCommand(
				pbCmd, pbCmd[4]+5, pData, &dwOutDataLen
				);
		}
		else if (m_dwBitLen == 2048)
		{
			if (m_pInvertableRsa != NULL)//对应于Import方式的.
			{
				//写入公钥到公钥临时文件
				//创建公钥文件
				BYTE pukFilePath[2] = {0, 0};
				WORD flag = 0x0000|FILETYPE_PUK | FILE_UNUSED;
				BOOL bRet = GetCSPObject()->GetWorkableFile(flag, g_cPathTable.rsaPukFileLen, pukFilePath);
				if (bRet == FALSE)
				{
					goto error_proc;
				}
				
				//选择公钥文件并写入公钥				
				bRet = GetCSPObject()->OpenFile(pukFilePath, &hPubFile);
				if (bRet == FALSE)
					goto error_proc;
				
				BYTE pbPubKeyData[0x100+4];//
				DWORD dwPubKeyDataLen = 0;
				m_pInvertableRsa->GetModulus().Encode(pbPubKeyData + dwPubKeyDataLen, 0x100);
				dwPubKeyDataLen += 0x100;
				m_pInvertableRsa->GetExponent().Encode(pbPubKeyData + dwPubKeyDataLen, 0x04);
				dwPubKeyDataLen += 0x04;
				bRet = GetCSPObject()->WriteFile(hPubFile, pbPubKeyData, dwPubKeyDataLen);
				GetCSPObject()->CloseFile(hPubFile);					
				if (bRet == FALSE)
					goto error_proc;
				
				memcpy(m_pubID,pukFilePath,2);
			}			
			else if (m_pInvertableRsa == NULL)
			{
				if (m_pubID[0] == 0x00 && m_pubID[1] == 0x00)
				{
					//read n ,e. 产生m_pRsa;
					BOOL bRet = ReadRealObject();
					if (bRet == FALSE)
						goto error_proc;
					if (m_pRsa == NULL)
						goto error_proc;

					//写入公钥到公钥临时文件
					//创建公钥文件
					BYTE pukFilePath[2] = {0, 0};
					WORD flag = 0x0000|FILETYPE_PUK | FILE_UNUSED;
					bRet = GetCSPObject()->GetWorkableFile(flag, g_cPathTable.rsaPukFileLen, pukFilePath);
					if (bRet == FALSE)
					{
						goto error_proc;
					}
					
					//选择公钥文件并写入公钥				
					bRet = GetCSPObject()->OpenFile(pukFilePath, &hPubFile);
					if (bRet == FALSE)
						goto error_proc;
					
					BYTE pbPubKeyData[0x100+4];//
					DWORD dwPubKeyDataLen = 0;
					m_pRsa->GetModulus().Encode(pbPubKeyData + dwPubKeyDataLen, 0x100);
					dwPubKeyDataLen += 0x100;
					m_pRsa->GetExponent().Encode(pbPubKeyData + dwPubKeyDataLen, 0x04);
					dwPubKeyDataLen += 0x04;
					bRet = GetCSPObject()->WriteFile(hPubFile, pbPubKeyData, dwPubKeyDataLen);
					GetCSPObject()->CloseFile(hPubFile);					
					if (bRet == FALSE)
						goto error_proc;
					
					memcpy(m_pubID,pukFilePath,2);
				}
			}
			//RSA Encrypt & Decrypt Operation命令对载入的RSA操作数据执行解密			
			//;------------载入密钥	
			//80 38 01 F0 04 公钥ID 私钥ID 
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

			//;------------载入数据高128位
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
			//;------------载入数据低128位
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
			//执行解密
			//80 3A 01 01 00        4s Le= 0x100 响应数据+9000
			pbCmd[0] = 0x80;
			pbCmd[1] = 0x3A;
			pbCmd[2] = 0x01;
			pbCmd[3] = 0x01;
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
		//结束事务
		GetCSPObject()->EndTransaction();
	}
	else return FALSE;

	return TRUE;

error_proc:
	GetCSPObject()->EndTransaction();
	return FALSE;
}

BOOL CCSPRsaPrk::SignHash(
	CCSPHashObject* pHash,
	LPCWSTR sDescription,
	DWORD dwFlags,
	BYTE* pbSignature,
	DWORD* pdwSigLen
	)
{
	//参数检测
	if(pdwSigLen == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	//调用的目的只是为了判断输出的大小
	if(pbSignature == NULL){
		(*pdwSigLen) = (m_dwBitLen / 8);
		return TRUE;
	}

	//判断输出空间是否足够
	if((*pdwSigLen) < (m_dwBitLen /8)){
		SETLASTERROR(ERROR_MORE_DATA);
		return FALSE;
	}

	//读取私钥对象
	if (!ReadRealObject())
		return FALSE;

	//获取HASH值
	DWORD cbHash = 0;
	BOOL bRetVal = pHash->GetValue(NULL, &cbHash);
	if(bRetVal == FALSE)
		return FALSE;
	LPBYTE pbHash = new BYTE[cbHash];
	bRetVal = pHash->GetValue(pbHash, &cbHash);
	if(bRetVal == FALSE){
		delete pbHash;
		return FALSE;
	}
	
	//签名前进行填充
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
	
	LPBYTE pbPadedData = new BYTE[m_dwBitLen / 8];
	if(pbPadedData == NULL){
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}
	if(m_dwPadding == PKCS5_PADDING){
		PKCS_SignaturePaddingScheme pad;
		pad.Pad(g_rng, pbUnpadData, cbUnpadData, pbPadedData, m_dwBitLen-1);
	}
	delete pbUnpadData;
	
	//私钥签名
	if(IsNeedHWCalc())
		bRetVal = HWRawRSADecryption(pbPadedData);
	else
		bRetVal = SWRawRSADecryption(pbPadedData);
	if(!bRetVal){
		delete pbPadedData;
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}

	//输出
	*pdwSigLen = m_dwBitLen/8;
	memcpy(pbSignature, pbPadedData, m_dwBitLen/8);
	delete pbPadedData;
	SwapInt(pbSignature, *pdwSigLen);
	
	return TRUE;
}

BOOL CCSPRsaPrk::Decrypt(
	CCSPHashObject* pHash,
	BOOL Final,
	DWORD dwFlags,
	BYTE* pbData,
	DWORD* pdwDataLen
	)
{
	//参数检测
	if(pdwDataLen == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	//判断是否有数据需要解密
	if(pbData == NULL){
		(*pdwDataLen) = 0;
		return TRUE;
	}
	if((*pdwDataLen) == 0)
		return TRUE;

	//输入数据必需是模长的整数倍
	DWORD cbInputData = *pdwDataLen;
	if(cbInputData % (m_dwBitLen / 8) != 0){
		SETLASTERROR(NTE_BAD_DATA);
		return FALSE;
	}

	//复制输入数据
	LPBYTE pbInputData = new BYTE[cbInputData];
	if(pbInputData == NULL){
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}
	memcpy(pbInputData, pbData, cbInputData);

	//交换输入数据的顺序
	SwapInt(pbInputData, cbInputData);
	
	//读取私钥对象
	if(!ReadRealObject()){
		delete pbInputData;
		return FALSE;
	}
	
	BOOL bRetVal = TRUE;
	DWORD cbOutputData = 0;
	for(int i = 0; i < cbInputData; i += (m_dwBitLen / 8)){
		//私钥解密
		if(IsNeedHWCalc())
			bRetVal = HWRawRSADecryption(pbInputData + i);
		else
			bRetVal = SWRawRSADecryption(pbInputData + i);
		if(!bRetVal){
			delete pbInputData;
			SETLASTERROR(NTE_FAIL);
			return FALSE;
		}
		
		//去掉填充
		PKCS_EncryptionPaddingScheme pad;
		DWORD cbUnpaddedDataLen = pad.MaxUnpaddedLength(m_dwBitLen - 1);
		LPBYTE pbUnpaddedData = new BYTE[cbUnpaddedDataLen];
		if(pbUnpaddedData == NULL){
			delete pbInputData;
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
		cbUnpaddedDataLen = pad.Unpad(pbInputData + i, m_dwBitLen - 1, pbUnpaddedData);
		if(cbUnpaddedDataLen == 0){
			delete pbUnpaddedData;
			delete pbInputData;
			SETLASTERROR(NTE_BAD_DATA);
			return FALSE;
		}

		//输出
		memcpy(pbData + cbOutputData, pbUnpaddedData, cbUnpaddedDataLen);
		cbOutputData += cbUnpaddedDataLen;
		delete pbUnpaddedData;

		//对解密后的数据作HASH运算
		if(pHash != NULL){
			bRetVal = pHash->HashData(pbData + cbOutputData, cbUnpaddedDataLen, NULL);
			if(!bRetVal){
				delete pbInputData;
				return FALSE;
			}
		}
	}
	
	delete pbInputData;
	*pdwDataLen = cbOutputData;
	return TRUE;
}

BOOL CCSPRsaPrk::Import(
	CONST BYTE *pbData,
	DWORD  dwDataLen,
	CCSPKey *pPubKey,
	DWORD dwFlags
	)
{
	BLOBHEADER* bh = (BLOBHEADER* )pbData;
	if (bh->bType == PUBLICKEYBLOB)
	{
		return CCSPRsaPuk::Import(pbData,dwDataLen,pPubKey,dwFlags);
	}

	if (bh->bType != PRIVATEKEYBLOB)
	{
		SETLASTERROR(NTE_BAD_DATA);
		return FALSE;
	}
	m_dwFlags = dwFlags;

	pbData += sizeof(BLOBHEADER);

	DWORD dwPlaintextLen = dwDataLen - sizeof(BLOBHEADER);
	BYTE* pbPlaintext = new BYTE[dwPlaintextLen];
	if(pbPlaintext == NULL)
	{
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}
	memcpy(pbPlaintext, pbData, dwPlaintextLen);
	
	BOOL bRet;
	if (pPubKey != NULL)
	{
		bRet = pPubKey->Decrypt(NULL, TRUE , NULL,pbPlaintext, &dwPlaintextLen);
		if (bRet = FALSE)
		{
			delete pbPlaintext;
			SETLASTERROR(NTE_BAD_DATA);
			return FALSE;
		}
	}

	RSAPUBKEY* rsapuk = (RSAPUBKEY* )pbPlaintext;
	if (rsapuk->magic != 0x32415352)
	{
		delete pbPlaintext;
		SETLASTERROR(NTE_BAD_DATA);
		return FALSE;
	}

	int nLen = sizeof(RSAPUBKEY) + rsapuk->bitlen/16*9;
	if (dwPlaintextLen < nLen)
	{
		delete pbPlaintext;
		SETLASTERROR(NTE_BAD_DATA);
		return FALSE;
	}
	
	BOOL bRetVal = Create(
		rsapuk->bitlen,
		rsapuk->pubexp,
		pbPlaintext+sizeof(RSAPUBKEY),
		pbPlaintext+sizeof(RSAPUBKEY)+rsapuk->bitlen/8,
		pbPlaintext+sizeof(RSAPUBKEY)+rsapuk->bitlen/16*3,
		pbPlaintext+sizeof(RSAPUBKEY)+rsapuk->bitlen/16*4,
		pbPlaintext+sizeof(RSAPUBKEY)+rsapuk->bitlen/16*5,
		pbPlaintext+sizeof(RSAPUBKEY)+rsapuk->bitlen/16*6,
		pbPlaintext+sizeof(RSAPUBKEY)+rsapuk->bitlen/16*7
		);
	delete pbPlaintext;

	return bRetVal;
}

BOOL CCSPRsaPrk::Export(
	CCSPKey *pPubKey,
	DWORD dwBlobType,
	DWORD dwFlags,
	BYTE *pbKeyBlob,
	DWORD *dwKeyBlobLen
	)
{
	if(dwBlobType == PUBLICKEYBLOB)
		return CCSPRsaPuk::Export(pPubKey,dwBlobType,dwFlags,pbKeyBlob,dwKeyBlobLen);
	
	if(!ReadRealObject())
		return FALSE;	
	
	if(dwBlobType != PRIVATEKEYBLOB)
	{
		SETLASTERROR(NTE_BAD_TYPE);
		return FALSE;
	}

	if((m_dwPermissions & CRYPT_EXPORT) == 0)
	{
		SETLASTERROR(NTE_BAD_KEY_STATE);
		return FALSE;
	}

	DWORD dwEncryptLen = m_dwBitLen/16*9 + sizeof(RSAPUBKEY);
	DWORD dwTotalLen;
	if (pPubKey != NULL){
		DWORD dwBlockSize = pPubKey->GetBlockLen() / 8;
		if(dwEncryptLen % dwBlockSize)
			dwTotalLen = (dwEncryptLen / dwBlockSize + 1)*dwBlockSize;
		else
			dwTotalLen = dwEncryptLen;
	}
	else
		dwTotalLen = dwEncryptLen;
	dwTotalLen += sizeof(BLOBHEADER);

	if (pbKeyBlob == NULL)
	{
		*dwKeyBlobLen = dwTotalLen;
		return TRUE;
	}
	else{
		if (*dwKeyBlobLen < dwTotalLen)
		{
			*dwKeyBlobLen = dwTotalLen;
			SETLASTERROR(ERROR_MORE_DATA);
			return FALSE;
		}

		*dwKeyBlobLen = dwTotalLen;
	}

	DWORD dwOffset = 0;

	BLOBHEADER bh;
	bh.bType = dwBlobType;
	bh.bVersion = DEFAULT_BLOB_VERSION;
	bh.reserved = NULL;
	bh.aiKeyAlg = m_ulAlgId;
	memcpy(pbKeyBlob, LPBYTE(&bh), sizeof(BLOBHEADER));
	dwOffset += sizeof(BLOBHEADER);
	
	RSAPUBKEY rsapuk;
	rsapuk.bitlen = m_dwBitLen;
	rsapuk.pubexp = m_pInvertableRsa->GetExponent().ConvertToLong();
	rsapuk.magic = 0x32415352;
	memcpy(pbKeyBlob + dwOffset, (LPBYTE)&rsapuk, sizeof(RSAPUBKEY));
	dwOffset += sizeof(RSAPUBKEY);

	//n
	m_pInvertableRsa->GetModulus().Encode(pbKeyBlob+dwOffset,m_dwBitLen/8);
	SwapInt(pbKeyBlob+dwOffset,m_dwBitLen/8);
	dwOffset += m_dwBitLen/8;

	//p
	m_pInvertableRsa->GetPrime1().Encode(pbKeyBlob+dwOffset,m_dwBitLen/16);
	SwapInt(pbKeyBlob+dwOffset,m_dwBitLen/16);
	dwOffset += m_dwBitLen/16;
	
	//q
	m_pInvertableRsa->GetPrime2().Encode(pbKeyBlob+dwOffset,m_dwBitLen/16);
	SwapInt(pbKeyBlob+dwOffset,m_dwBitLen/16);
	dwOffset += m_dwBitLen/16;
	
	//dp
	m_pInvertableRsa->GetExponent1().Encode(pbKeyBlob+dwOffset,m_dwBitLen/16);
	SwapInt(pbKeyBlob+dwOffset,m_dwBitLen/16);
	dwOffset += m_dwBitLen/16;
	
	//dq
	m_pInvertableRsa->GetExponent2().Encode(pbKeyBlob+dwOffset,m_dwBitLen/16);
	SwapInt(pbKeyBlob+dwOffset,m_dwBitLen/16);
	dwOffset += m_dwBitLen/16;

	//u
	m_pInvertableRsa->GetCoefficient().Encode(pbKeyBlob+dwOffset,m_dwBitLen/16);
	SwapInt(pbKeyBlob+dwOffset,m_dwBitLen/16);
	dwOffset += m_dwBitLen/16;

	//d
	m_pInvertableRsa->GetDecryptionExponent().Encode(pbKeyBlob+dwOffset,m_dwBitLen/8);
	SwapInt(pbKeyBlob+dwOffset,m_dwBitLen/8);
	

	if (pPubKey != NULL)
	{
		BOOL bRet = pPubKey->Encrypt(
			NULL, TRUE, NULL, pbKeyBlob + sizeof(BLOBHEADER), &dwEncryptLen, dwEncryptLen
			);
		if (bRet == FALSE)
		{
			SETLASTERROR(NTE_FAIL);
			return FALSE;
		}
	}
	
	return TRUE;
}

BOOL CCSPRsaPrk::GetKeyOffsetInXdf(
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
	if (m_ulAlgId ==CALG_RSA_KEYX)
		return TRUE;
	else if (m_ulAlgId ==CALG_RSA_SIGN)
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

BOOL CCSPRsaPrk::SetParam(
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
		
		//越过tag和len
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
				//有证书存在（修改证书）且证书的长度小于当前的证书
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

		//更新索引文件
		if(!GetCSPObject()->OpenFile(g_cPathTable.prkdfPath, &hFile, NULL)){
			GetCSPObject()->EndTransaction();
			return FALSE;
		}

		SHARE_XDF XdfRec;
		GetCSPObject()->GetXdf(DFTYPE_PRK,&XdfRec);
		ULONG ulOffset,ulLen;
		GetKeyOffsetInXdf(&XdfRec,m_ulIndex,ulOffset,ulLen);
		
		//越过tag和len
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
	return CCSPRsaPuk::SetParam(dwParam,pbData,dwFlags);
}

BOOL CCSPRsaPrk::GetParam(
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
	return CCSPRsaPuk::GetParam(dwParam,pbData,pdwDataLen,dwFlags);
}

BOOL CCSPRsaPrk::ReadCert()
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

BOOL CCSPRsaPrk::IsNeedHWGenKey()
{
	return IsNeedHWCalc();
}