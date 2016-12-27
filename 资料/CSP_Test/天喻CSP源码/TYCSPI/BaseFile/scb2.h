//scb2.h
#ifndef __SCB2_H__
#define __SCB2_H__
#include "CSPAfx.h"
class SCB2_Encryption : public BlockTransformation
{
public:
	SCB2_Encryption(const byte * userKey);
	SCB2_Encryption(const byte * userKey,CTYCSP* pCSPObject);
	~SCB2_Encryption();
	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const;

	void Process(const byte *inData, unsigned long inLen, byte * outData) const;
	void Process(byte * inoutData, unsigned long inLen) const;

	
	enum {KEYLENGTH=32, BLOCKSIZE=32};
	unsigned int BlockSize() const {return BLOCKSIZE;}

	BOOL * bSuccess;

private:
	BYTE m_userKey[32];
	CTYCSP* m_pCSPObject;
};

class SCB2_Decryption : public BlockTransformation
{
public:
	SCB2_Decryption(const byte * userKey);
	SCB2_Decryption(const byte * userKey,CTYCSP* pCSPObject);
	~SCB2_Decryption();
	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const;

	void Process(const byte *inData, unsigned long inLen, byte * outData) const;
	void Process(byte * inoutData, unsigned long inLen) const;

	enum {KEYLENGTH=32, BLOCKSIZE=32};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	BOOL *bSuccess;
private:
	BYTE m_userKey[32];
	CTYCSP* m_pCSPObject;
	
};
#endif