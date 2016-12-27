//-------------------------------------------------------------------
//	本文件为 TY Cryptographic Service Provider 的组成部分
//
//
//	版权所有 天喻信息产业有限公司 (c) 1996 - 2005 保留一切权利
//-------------------------------------------------------------------
#ifndef __TYCSP_HASHOBJECT_H__
#define __TYCSP_HASHOBJECT_H__

#include "iterhash.h"

class CCSPKey;

/////////////////////////////////////////////////////////////////////
//	class CCSPHashObject
//

//Hash值的最大尺寸
//SHA为20, MD5为16, SSL3SHAMD5为36(20 + 16)
#define HASH_MAX_SIZE		(20 + 16)

class CCSPHashObject : public CObject{
//构造与析构函数
public:
	CCSPHashObject(
		ALG_ID idAlg 
		);
	virtual ~CCSPHashObject();

//属性
private:
	//对象句柄
	HCRYPTHASH	m_hHandle;

	//算法标识
	ALG_ID		m_idAlg;

	//Hash值及其字节数
	DWORD		m_dwSize;
	BYTE		m_cValue[HASH_MAX_SIZE];

	//HASH计算结束标志
	BOOL		m_bFinished;

	//是否是空的HASH对象
	BOOL		m_bEmpty;

	//HASH模块, 对于SSL3SHAMDE为NULL
	IteratedHash<word32>* m_pHashModule;

public:
	//获取HASH对象的句柄
	HCRYPTHASH GetHandle() const { return m_hHandle; }
	//HASH计算是否已结束
	BOOL IsFinished() const { return m_bFinished; }
	//是否为空的HASH对象
	BOOL IsEmpty() const { return m_bEmpty; }
	//获取算法标识
	ALG_ID GetAlgId() const { return m_idAlg;}
	//获取HASH值的尺寸
	DWORD GetSize() const { return m_dwSize; }

	//获取HASH值
	BOOL GetValue(BYTE* pbData, DWORD* pdwDataLen);
	//设置HASH值
	void SetValue(BYTE* pbData);

protected:
	//结束HASH运算
	void Finish();
	//获取HASH状态
	BOOL GetHashState(LPHASHSTATE lpHashState);
	//设置HASH状态
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