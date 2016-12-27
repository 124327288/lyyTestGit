//SCB2.cpp
#include "stdAfx.h"
#include "scb2.h"

BOOL
SCB2SymmCipher(
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

	//更新SCB2密钥
	BYTE cCommand[256];
	DWORD dwResLen;
	WORD wSW;
	
	//SCB2加解密
	DWORD dwOffset = 0;
	while(dwOffset < dwDataLen){
		
		cCommand[0] = 0x80;
		cCommand[1] = 0x1A;		
		cCommand[2] = (bEncrypt ? 0x8C : 0x8D);
		cCommand[3] = 0x01;
		cCommand[4] = 0x10;
		memcpy(cCommand + 5, pbInData + dwOffset , 0x10);
		if(!pCSPObject->SendCommand(cCommand, 5 + 0x10, pbOutData + dwOffset, &dwResLen, &wSW))
		{		
			return FALSE;
		}
		
		dwOffset += 0x10;
	}
	
	return TRUE;
}
SCB2_Encryption::SCB2_Encryption(const byte * userKey,CTYCSP* pCSPObject)
{
	memcpy(m_userKey,userKey,32);
	m_pCSPObject = pCSPObject;
	bSuccess = new	BOOL;
	*bSuccess = TRUE;
}

SCB2_Encryption::SCB2_Encryption(const byte * userKey)
{
	memcpy(m_userKey,userKey,32);
	m_pCSPObject = NULL;
	bSuccess = new	BOOL;
	*bSuccess = TRUE;
}
SCB2_Encryption::~SCB2_Encryption()
{
	delete bSuccess;
}
void SCB2_Encryption::ProcessBlock(const byte *inBlock, byte * outBlock) const
{
	BYTE inBlock1[32];
	memcpy(inBlock1,inBlock,32);
	if (*bSuccess) {
		*bSuccess = SCB2SymmCipher(
			m_pCSPObject,
			(BYTE*)m_userKey,
			TRUE,
			inBlock1,
			32,
			outBlock);
	}
}
void SCB2_Encryption::ProcessBlock(byte * inoutBlock) const
{
	byte outBlock[32];
	ProcessBlock(inoutBlock,outBlock);
	memcpy(inoutBlock,outBlock,32);
}

void SCB2_Encryption::Process(
							  const byte *inData, 
							  unsigned long inLen, 
							  byte * outData) const
{
	BYTE *inBlock1 = new BYTE[inLen];
	memcpy(inBlock1,inData,inLen);
	if (*bSuccess) {
		*bSuccess = SCB2SymmCipher(
			m_pCSPObject,
			(BYTE*)m_userKey,
			TRUE,
			inBlock1,
			inLen,
			outData);
	}
	delete inBlock1;
}

void SCB2_Encryption::Process(
							  byte * inoutData, 
							  unsigned long inLen) const
{
	byte *outBlock = new byte[inLen];
	Process(inoutData,inLen,outBlock);
	memcpy(inoutData,outBlock,inLen);
	delete outBlock;
}

SCB2_Decryption::SCB2_Decryption(const byte * userKey,CTYCSP* pCSPObject)
{
	memcpy(m_userKey,userKey,32);
	m_pCSPObject = pCSPObject;
	bSuccess = new	BOOL;
	*bSuccess = TRUE;
}
SCB2_Decryption::SCB2_Decryption(const byte * userKey)
{
	memcpy(m_userKey,userKey,32);
	m_pCSPObject = NULL;
	bSuccess = new	BOOL;
	*bSuccess = TRUE;
}

SCB2_Decryption::~SCB2_Decryption()
{
	delete bSuccess;
}
void SCB2_Decryption::ProcessBlock(const byte *inBlock, byte * outBlock) const
{
	BYTE inBlock1[32];
	memcpy(inBlock1,inBlock,32);
	if (*bSuccess) {
		*bSuccess = SCB2SymmCipher(
			m_pCSPObject,
			(BYTE*)m_userKey,
			FALSE,
			inBlock1,
			32,
			outBlock);
	}
}
void SCB2_Decryption::ProcessBlock(byte * inoutBlock) const
{
	byte outBlock[32];
	ProcessBlock(inoutBlock,outBlock);
	memcpy(inoutBlock,outBlock,32);
}

void SCB2_Decryption::Process(
							  const byte *inData, 
							  unsigned long inLen, 
							  byte * outData) const
{
	BYTE *inBlock1 = new BYTE[inLen];
	memcpy(inBlock1,inData,inLen);
	if (*bSuccess) {
		*bSuccess = SCB2SymmCipher(
			m_pCSPObject,
			(BYTE*)m_userKey,
			FALSE,
			inBlock1,
			inLen,
			outData);
	}
	delete inBlock1;
}

void SCB2_Decryption::Process(
							  byte * inoutData, 
							  unsigned long inLen) const
{
	byte *outBlock = new byte[inLen];
	Process(inoutData,inLen,outBlock);
	memcpy(inoutData,outBlock,inLen);
	delete outBlock;
}
