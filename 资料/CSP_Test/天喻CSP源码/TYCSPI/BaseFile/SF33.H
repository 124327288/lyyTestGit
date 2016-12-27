//sf33.h
#ifndef __SF33_H__
#define __SF33_H__
#include "CSPAfx.h"
class SF33_Encryption : public BlockTransformation
{
public:
	SF33_Encryption(const byte * userKey);
	SF33_Encryption(const byte * userKey,CTYCSP* pCSPObject);
	~SF33_Encryption();
	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const;

	void Process(const byte *inData, unsigned long inLen, byte * outData) const;
	void Process(byte * inoutData, unsigned long inLen) const;

	
	enum {KEYLENGTH=16, BLOCKSIZE=16};
	unsigned int BlockSize() const {return BLOCKSIZE;}

	BOOL * bSuccess;

private:
	BYTE m_userKey[16];
	CTYCSP* m_pCSPObject;
};

class SF33_Decryption : public BlockTransformation
{
public:
	SF33_Decryption(const byte * userKey);
	SF33_Decryption(const byte * userKey,CTYCSP* pCSPObject);
	~SF33_Decryption();
	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const;

	void Process(const byte *inData, unsigned long inLen, byte * outData) const;
	void Process(byte * inoutData, unsigned long inLen) const;

	enum {KEYLENGTH=16, BLOCKSIZE=16};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	BOOL *bSuccess;
private:
	BYTE m_userKey[16];
	CTYCSP* m_pCSPObject;
	
};
#endif