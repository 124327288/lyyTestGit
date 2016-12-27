#ifndef CRYPTOPP_ITERHASH_H
#define CRYPTOPP_ITERHASH_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

/* The following classes are explicitly instantiated in iterhash.cpp

	IteratedHash<word32>
	IteratedHash<word64>	// #ifdef WORD64_AVAILABLE
*/

typedef struct _HashState{
	word32 countLo;
	word32 countHi;
	unsigned int blockSize;
	unsigned int digestSize;
	byte block[128];
	byte digest[32];
}HASHSTATE, *LPHASHSTATE;

template <class T> class IteratedHash : public virtual HashModule
{
public:
	IteratedHash(unsigned int blockSize, unsigned int digestSize);
	~IteratedHash();
	void Update(const byte *input, unsigned int length);

	typedef T HashWordType;

protected:
	void PadLastBlock(unsigned int lastBlockSize, byte padFirst=0x80);
	virtual void Init() =0;
	virtual void HashBlock(const T *input) =0;

	unsigned int blockSize;
	word32 countLo, countHi;	// 64-bit bit count
	SecBlock<T> data;			// Data buffer
	SecBlock<T> digest;			// Message digest

public:
	bool GetHashState(LPHASHSTATE lpHashState);
	void SetHashState(LPHASHSTATE lpHashState);
};

NAMESPACE_END

#endif
