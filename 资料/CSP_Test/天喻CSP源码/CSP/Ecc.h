#ifndef ECC_H
#define ECC_H
#include "integer.h"
#include "cryptlib.h"
#include "asn.h"
NAMESPACE_BEGIN(CryptoPP)
class ECCFunction 
{
public:
	ECCFunction(const Integer &pubKey) : pubKey(pubKey){}
	ECCFunction(BufferedTransformation &bt)
	{
		BERSequenceDecoder seq(bt);
		pubKey.BERDecode(seq);
	}
	void DEREncode(BufferedTransformation &bt) const
	{
		DERSequenceEncoder seq(bt);
		pubKey.DEREncode(seq);
	}

	const Integer& GetPubKey() const {return pubKey;}

protected:
	ECCFunction() {}	
	Integer pubKey;	// these are only modified in constructors
};

class InvertableECCFunction : public ECCFunction
{
public:
	InvertableECCFunction(const Integer &pubKey, const Integer &priKey): ECCFunction(pubKey), priKey(priKey){}
	// generate a random private key
	//InvertableECCFunction(RandomNumberGenerator &rng, unsigned int keybits, const Integer &eStart=17);
	InvertableECCFunction(BufferedTransformation &bt)
	{
		BERSequenceDecoder seq(bt);
		
		Integer version(seq);
		if (!!version)  // make sure version is 0
			BERDecodeError();
		
		pubKey.BERDecode(seq);
		priKey.BERDecode(seq);	
	}
	void DEREncode(BufferedTransformation &bt) const
	{
		DERSequenceEncoder seq(bt);
		
		const byte version[] = {INTEGER, 1, 0};
		seq.Put(version, sizeof(version));
		pubKey.DEREncode(seq);
		priKey.DEREncode(seq);
	}
	const Integer& GetPriKey() const {return priKey;}

protected:
	Integer priKey; // these are only modified in constructors
};

class ECCPad
{
public:
	ECCPad(){};
	~ECCPad(){};
	//dwDataLen 原始数据长度, dwPadDataLen填充后数据长度 dwSize块长
	bool Pad(const BYTE *pbData,const DWORD dwDataLen, BYTE *pbPadData,DWORD &dwPadDataLen, const DWORD dwSize)
	{
		
		if (pbData == NULL || dwDataLen < 0 || dwSize <= 0) {
			return false;
		}
		DWORD nBlockNum = dwDataLen / dwSize + 1;
		DWORD nLeftNum = dwDataLen % dwSize;
		dwPadDataLen = nBlockNum * dwSize;	
		if (pbPadData == NULL)//为空时返回填充后数据长度
		{
			return true;
		}
		memcpy(pbPadData,pbData,dwDataLen);
		if (nLeftNum == 0) {
			memset(pbPadData+dwDataLen , 0xff , dwSize-1);
		}
		else{
			memset(pbPadData+dwDataLen , 0xff , dwSize-nLeftNum-1);
		}
		pbPadData[dwPadDataLen-1] = nLeftNum;
		return true;
	}
	bool UnPad(const BYTE *pbData,const DWORD dwDataLen,BYTE *pbDataout,DWORD &dwDataOutLen , const DWORD dwSize)
	{
		DWORD nLeftNum;
		if (pbData == NULL) {
			return false;
		}
		if ((pbData+dwDataLen-1) != NULL) {
			nLeftNum = *(pbData+dwDataLen-1);
		}
		else 
			return false;
		dwDataOutLen = dwDataLen-dwSize+nLeftNum;
		if (pbDataout == NULL) {
			return true;
		}
		memcpy(pbDataout,pbData,dwDataOutLen);
		return true;
	}
protected:
private:
};
NAMESPACE_END
#endif