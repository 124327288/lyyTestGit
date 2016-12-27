//-------------------------------------------------------------------
//	���ļ�Ϊ TY Cryptographic Service Provider ����ɲ���
//
//
//	��Ȩ���� ������Ϣ��ҵ���޹�˾ (c) 1996 - 2005 ����һ��Ȩ��
//-------------------------------------------------------------------
#ifndef __TYCSP_HASHOBJECT_H__
#define __TYCSP_HASHOBJECT_H__

#include "iterhash.h"

class CCSPKey;

/////////////////////////////////////////////////////////////////////
//	class CCSPHashObject
//

//Hashֵ�����ߴ�
//SHAΪ20, MD5Ϊ16, SSL3SHAMD5Ϊ36(20 + 16)
#define HASH_MAX_SIZE		(20 + 16)

class CCSPHashObject : public CObject{
//��������������
public:
	CCSPHashObject(
		ALG_ID idAlg 
		);
	virtual ~CCSPHashObject();

//����
private:
	//������
	HCRYPTHASH	m_hHandle;

	//�㷨��ʶ
	ALG_ID		m_idAlg;

	//Hashֵ�����ֽ���
	DWORD		m_dwSize;
	BYTE		m_cValue[HASH_MAX_SIZE];

	//HASH���������־
	BOOL		m_bFinished;

	//�Ƿ��ǿյ�HASH����
	BOOL		m_bEmpty;

	//HASHģ��, ����SSL3SHAMDEΪNULL
	IteratedHash<word32>* m_pHashModule;

public:
	//��ȡHASH����ľ��
	HCRYPTHASH GetHandle() const { return m_hHandle; }
	//HASH�����Ƿ��ѽ���
	BOOL IsFinished() const { return m_bFinished; }
	//�Ƿ�Ϊ�յ�HASH����
	BOOL IsEmpty() const { return m_bEmpty; }
	//��ȡ�㷨��ʶ
	ALG_ID GetAlgId() const { return m_idAlg;}
	//��ȡHASHֵ�ĳߴ�
	DWORD GetSize() const { return m_dwSize; }

	//��ȡHASHֵ
	BOOL GetValue(BYTE* pbData, DWORD* pdwDataLen);
	//����HASHֵ
	void SetValue(BYTE* pbData);

protected:
	//����HASH����
	void Finish();
	//��ȡHASH״̬
	BOOL GetHashState(LPHASHSTATE lpHashState);
	//����HASH״̬
	void SetHashState(LPHASHSTATE lpHashState);

public:
	//makes an exact copy of a hash and its state
	virtual BOOL Duplicate(
		DWORD *pdwReserved,
		DWORD dwFlags,
		CCSPHashObject* pSourceHash
		);

	//The call to CPGetHashParam function completes the hash. 
	//After this call, no more data can be added to the hash. 
	//Additional calls to CPHashData or CPHashSessionKey must 
	//fail. 
	virtual BOOL GetParam(
		DWORD dwParam,
		BYTE *pbData,
		DWORD *pdwDataLen,
		DWORD dwFlags
		);
 
	//customizes the operations of a hash object. Typically, the 
	//hash object will be empty. If this is not the case, an 
	//error returned. 
	virtual BOOL SetParam(
		DWORD dwParam,
		BYTE *pbData,
		DWORD dwFlags
		);
 
	//feeds data into a specified hash object
	virtual BOOL HashData(
		CONST BYTE *pbData,
		DWORD dwDataLen,
		DWORD dwFlags
		);

	//feeds a cryptographic key to a specified hash object. This 
	//allows a key to be hashed without the application having 
	//access to the key material.The only data this function adds 
	//to the hash object is the session key material, itself.
	virtual BOOL HashSessionKey(
		CCSPKey* pKey,
		DWORD dwFlags
		);
};
#endif