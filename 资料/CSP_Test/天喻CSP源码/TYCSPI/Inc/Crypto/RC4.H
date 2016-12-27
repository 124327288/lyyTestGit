#ifndef CRYPTOPP_RC4_H
#define CRYPTOPP_RC4_H

NAMESPACE_BEGIN(CryptoPP)

typedef struct _RC4State{
	unsigned int mx, my;
	unsigned int data[256];
}RC4_STATE;

class RC4Crypt{
public:
	RC4Crypt(const byte* key, unsigned int keyLen);
	~RC4Crypt();

public:
	void Input(byte* indata, byte* outdata, unsigned int len);
	void InputFinished();

	void GetState(RC4_STATE* pState);
	void SetState(const RC4_STATE* pState);

private:
	void ResetKey();
	
	byte* m_pKey;
	unsigned int m_nKeyLen;
	unsigned int m_x, m_y;
	unsigned int m_pData[256];
};

NAMESPACE_END

#endif

