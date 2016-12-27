//ssf33.cpp
#include "stdAfx.h"
#include "sf33.h"

BOOL
SSF33SymmCipher(
	IN CTYCSP* pCSPObject,
	IN LPBYTE pbKey, 
	IN BOOL bEncrypt,
	IN LPBYTE pbInData,
	IN DWORD dwDataLen,
	OUT LPBYTE pbOutData
	)
{
	//通过密钥容器句柄获取CSP对象
	if(pCSPObject == NULL)
		return FALSE;

	//更新SSF33密钥
	BYTE cCommand[256];
	DWORD dwResLen;
	WORD wSW;
	
	//SSF33加解密
	#define SSF33_MAX_BLOCKSIZE 16*15
	DWORD dwOffset = 0;
	while(dwOffset < dwDataLen){
		DWORD dwBlockSize = dwDataLen - dwOffset;
		if(dwBlockSize > SSF33_MAX_BLOCKSIZE) 
			dwBlockSize = SSF33_MAX_BLOCKSIZE;
		cCommand[0] = 0x80;
		cCommand[1] = 0x32;
		cCommand[2] = 0x03;
		cCommand[3] = (bEncrypt ? 0x00 : 0x01);
		cCommand[4] = (BYTE)dwBlockSize;
		memcpy(cCommand + 5, pbInData + dwOffset , dwBlockSize);
		if(!pCSPObject->SendCommand(cCommand, 5 + dwBlockSize, pbOutData + dwOffset, &dwResLen, &wSW)){
			if(wSW == 0x6D00){
				cCommand[1] = 0x1B;
				if(!pCSPObject->SendCommand(cCommand, 5 + dwBlockSize, pbOutData + dwOffset, &dwResLen, &wSW))
					return FALSE;
			}
		}
		
		dwOffset += dwBlockSize;
	}
	
	return TRUE;
}
SF33_Encryption::SF33_Encryption(const byte * userKey,CTYCSP* pCSPObject)
{
	memcpy(m_userKey,userKey,16);
	m_pCSPObject = pCSPObject;
	bSuccess = new	BOOL;
	*bSuccess = TRUE;
}

SF33_Encryption::SF33_Encryption(const byte * userKey)
{
	memcpy(m_userKey,userKey,16);
	m_pCSPObject = NULL;
	bSuccess = new	BOOL;
	*bSuccess = TRUE;
}
SF33_Encryption::~SF33_Encryption()
{
	delete bSuccess;
}
void SF33_Encryption::ProcessBlock(const byte *inBlock, byte * outBlock) const
{
	BYTE inBlock1[16];
	memcpy(inBlock1,inBlock,16);
	if (*bSuccess) {
		*bSuccess = SSF33SymmCipher(
			m_pCSPObject,
			(BYTE*)m_userKey,
			TRUE,
			inBlock1,
			16,
			outBlock);
	}
}
void SF33_Encryption::ProcessBlock(byte * inoutBlock) const
{
	byte outBlock[16];
	ProcessBlock(inoutBlock,outBlock);
	memcpy(inoutBlock,outBlock,16);
}

void SF33_Encryption::Process(
							  const byte *inData, 
							  unsigned long inLen, 
							  byte * outData) const
{
	BYTE *inBlock1 = new BYTE[inLen];
	memcpy(inBlock1,inData,inLen);
	if (*bSuccess) {
		*bSuccess = SSF33SymmCipher(
			m_pCSPObject,
			(BYTE*)m_userKey,
			TRUE,
			inBlock1,
			inLen,
			outData);
	}
	delete inBlock1;
}

void SF33_Encryption::Process(
							  byte * inoutData, 
							  unsigned long inLen) const
{
	byte *outBlock = new byte[inLen];
	Process(inoutData,inLen,outBlock);
	memcpy(inoutData,outBlock,inLen);
	delete outBlock;
}

SF33_Decryption::SF33_Decryption(const byte * userKey,CTYCSP* pCSPObject)
{
	memcpy(m_userKey,userKey,16);
	m_pCSPObject = pCSPObject;
	bSuccess = new	BOOL;
	*bSuccess = TRUE;
}
SF33_Decryption::SF33_Decryption(const byte * userKey)
{
	memcpy(m_userKey,userKey,16);
	m_pCSPObject = NULL;
	bSuccess = new	BOOL;
	*bSuccess = TRUE;
}

SF33_Decryption::~SF33_Decryption()
{
	delete bSuccess;
}
void SF33_Decryption::ProcessBlock(const byte *inBlock, byte * outBlock) const
{
	BYTE inBlock1[16];
	memcpy(inBlock1,inBlock,16);
	if (*bSuccess) {
		*bSuccess = SSF33SymmCipher(
			m_pCSPObject,
			(BYTE*)m_userKey,
			FALSE,
			inBlock1,
			16,
			outBlock);
	}
}
void SF33_Decryption::ProcessBlock(byte * inoutBlock) const
{
	byte outBlock[16];
	ProcessBlock(inoutBlock,outBlock);
	memcpy(inoutBlock,outBlock,16);
}

void SF33_Decryption::Process(
							  const byte *inData, 
							  unsigned long inLen, 
							  byte * outData) const
{
	BYTE *inBlock1 = new BYTE[inLen];
	memcpy(inBlock1,inData,inLen);
	if (*bSuccess) {
		*bSuccess = SSF33SymmCipher(
			m_pCSPObject,
			(BYTE*)m_userKey,
			FALSE,
			inBlock1,
			inLen,
			outData);
	}
	delete inBlock1;
}

void SF33_Decryption::Process(
							  byte * inoutData, 
							  unsigned long inLen) const
{
	byte *outBlock = new byte[inLen];
	Process(inoutData,inLen,outBlock);
	memcpy(inoutData,outBlock,inLen);
	delete outBlock;
}
