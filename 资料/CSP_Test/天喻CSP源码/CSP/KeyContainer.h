//-------------------------------------------------------------------
//	本文件为 TY Cryptographic Service Provider 的组成部分
//
//
//	版权所有 天喻信息产业有限公司 (c) 1996 - 2005 保留一切权利
//-------------------------------------------------------------------

#ifndef __TYCSP_KEYCONTAINER_H__
#define __TYCSP_KEYCONTAINER_H__

class CCSPHashObject;
class CCSPKey;
typedef CArray<CCSPHashObject*, CCSPHashObject*> CCSPHashObjectPtrArray;
typedef CArray<CCSPKey*, CCSPKey*> CCSPKeyPtrArray;

/////////////////////////////////////////////////////////////////////
//	class CCSPKeyContainer
//
class CCSPKeyContainer : public CObject{
//构造与析构函数
public:
	CCSPKeyContainer(
		CTYCSP* pCSPObject,
		LPCTSTR lpszName, 
		BOOL bInitOpen = TRUE
		);
	~CCSPKeyContainer();

//属性
private:
	//CSP对象
	CTYCSP*						m_pCSPObject;
	
	//过程密钥
	CCSPKeyPtrArray				m_arSessionKeys;

	//密钥对
	CCSPKeyPtrArray				m_arKeyPair;

	//Hash对象
	CCSPHashObjectPtrArray		m_arHashObjects;

	//名字
	CString						m_szName;

	//是否被打开
	BOOL						m_bOpened;

	//是否被释放
	BOOL						m_bReleased;

	//句柄
	HCRYPTPROV					m_hHandle;

	//在卡中的索引
	int							m_nIndexOnToken;

	//引用计数
	DWORD						m_dwRefCount;

public:
	//获取CSP对象
	CTYCSP* GetCSPObject() const { return m_pCSPObject; }
	//获取Key Container对象的句柄
	HCRYPTPROV GetHandle() const { return m_hHandle; }
	//获取Key Container的名字
	CString GetName() const {return m_szName;}
	//判断Key Container是否被打开
	BOOL IsOpened() const { return m_bOpened;}
	//判断Key Container是否已被释放
	BOOL IsReleased() const { return m_bReleased; }
	//打开Key Container
	void Open();
	//增加引用计数
	DWORD AddRef();
	//释放Key Container
	DWORD Release();
	//判断是否有受保护的密钥对
	BOOL HaveProtectedKeyPairs();
	//判断是否创建在Token上
	BOOL IsToken() { return (m_nIndexOnToken >= 0); }

//对象的维护
public:
	//通过句柄获取密钥对象
	CCSPKey* GetKeyObjectByHandle(HCRYPTKEY hKey);
	//通过句柄获取HASH对象
	CCSPHashObject* GetHashObjectByHandle(HCRYPTHASH hHash);
	//通过句柄获取过程密钥对象
	CCSPKey* GetSessionKeyObjectByHandle(HCRYPTKEY hKey);
	//通过句柄获取密钥对
	CCSPKey* GetKeyPairObjectByHandle(HCRYPTKEY hKey);
	//获取指定算法标识的密钥对
	CCSPKey* GetKeyPairObjectByAlgId(ALG_ID algId);
	//判断是否已存在指定算法标识的密钥对
	BOOL IsKeyPairExist(ALG_ID algId);

protected:
	//删除HASH对象
	void DeleteHashObjects(BOOL bDestroyOnToken = FALSE);
	//删除过程密钥对象
	void DeleteSessionKeyObjects(BOOL bDestroyOnToken = FALSE);
	//删除密钥对对象
	void DeleteKeyPairObjects(BOOL bDestroyOnToken = FALSE);
	//删除KeyContainer中的所有对象
	void DeleteAllObjects(BOOL bDestroyOnToken = FALSE);
	//销毁指定算法标识的密钥对
	void DestroyKeyPair(ALG_ID algId);
	//根据算法标识产生密钥对象
	CCSPKey* CreateKeyObjectByAlgId(ALG_ID algId, BOOL bIsPublicKey = FALSE);
	//复制并产生一个密钥对象
	BOOL DuplicateSessionKeyObject(CCSPKey* pSource, CCSPKey*& pDuplicate);

//与卡有关的操作
public:
	//在卡上创建该Key Container
	BOOL CreateOnToken(int nIndex);
	//在卡上删除该Key Container
	BOOL DestroyOnToken();
	//获取该Key Container在卡上的索引
	int GetTokenIndex() const{ return m_nIndexOnToken; }
	//设置该Key Container在卡上的索引
	void SetTokenIndex(int nIndex);
	//载入密钥对
	void LoadKeyPairs(BYTE* pDERStr, ULONG dwDERLen);
	//获取密钥对的创建索引
	int GetKeyPairCreateIndex() const { return GetTokenIndex(); }

protected:

//以下对应CryptSPI接口(21)
public:
	/*CPGenKey*/
	BOOL GenKey(
		ALG_ID Algid,
		DWORD dwFlags,
		HCRYPTKEY *phKey
		);

	/*CPDeriveKey*/
	BOOL DeriveKey(
		ALG_ID Algid,
		HCRYPTHASH hBaseData,
		DWORD dwFlags,
		HCRYPTKEY *phKey
		);

	/*CPDuplicateKey*/
	BOOL DuplicateKey(
		HCRYPTKEY hKey,
		DWORD *pdwReserved,
		DWORD dwFlags,
		HCRYPTKEY* phKey
		);

	/*CPDestroyKey*/
	BOOL DestroyKey(
		HCRYPTKEY hKey
		);

	/*CPGetKeyParam*/
	BOOL GetKeyParam(
		HCRYPTKEY hKey,
		DWORD dwParam,
		BYTE *pbData,
		DWORD *pdwDataLen,
		DWORD dwFlags
		);
 
	/*CPSetKeyParam*/
	BOOL SetKeyParam(
		HCRYPTKEY hKey,
		DWORD dwParam,
		BYTE *pbData,
		DWORD dwFlags
		);
  
	/*CPImportKey*/
	BOOL ImportKey(
		CONST BYTE *pbData,
		DWORD dwDataLen,
		HCRYPTKEY hImpKey,
		DWORD dwFlags,
		HCRYPTKEY *phKey
		);

	/*CPExportKey*/
	BOOL ExportKey(
		HCRYPTKEY hKey,
		HCRYPTKEY hExpKey,
		DWORD dwBlobType,
		DWORD dwFlags,
		BYTE *pbData,
		DWORD *pdwDataLen
		);
 
	/*CPGenRandom*/
	BOOL GenRandom(
		DWORD dwLen,
		BYTE *pbBuffer
		);
 
	/*CPGetUserKey*/
	BOOL GetUserKey(
		DWORD dwKeySpec,
		HCRYPTKEY *phUserKey
		);

	/*CPEncrypt*/
	BOOL Encrypt(
		HCRYPTKEY hKey,
		HCRYPTHASH hHash,
		BOOL Final,
		DWORD dwFlags,
		BYTE *pbData,
		DWORD *pdwDataLen,
		DWORD dwBufLen
		);
 
	/*CPDecrypt*/
	BOOL Decrypt(
		HCRYPTKEY hKey,
		HCRYPTHASH hHash,
		BOOL Final,
		DWORD dwFlags,
		BYTE *pbData,
		DWORD *pdwDataLen
		);
 
	/*CPCreateHash*/
	BOOL CreateHash(
		ALG_ID Algid,
		HCRYPTKEY hKey,
		DWORD dwFlags,
		HCRYPTHASH *phHash
		);
 
	/*CPDestroyHash*/
	BOOL DestroyHash(
		HCRYPTHASH hHash
		);

	/*CPDuplicateHash*/
	BOOL DuplicateHash(
		HCRYPTHASH hHash,
		DWORD *pdwReserved,
		DWORD dwFlags,
		HCRYPTHASH *phHash
		);
 
	/*CPGetHashParam*/
	BOOL GetHashParam(
		HCRYPTHASH hHash,
		DWORD dwParam,
		BYTE *pbData,
		DWORD *pdwDataLen,
		DWORD dwFlags
		);
 
	/*CPSetHashParam*/
	BOOL SetHashParam(
		HCRYPTHASH hHash,
		DWORD dwParam,
		BYTE *pbData,
		DWORD dwFlags
		);
 
	/*CPHashData*/
	BOOL HashData(
		HCRYPTHASH hHash,
		CONST BYTE *pbData,
		DWORD dwDataLen,
		DWORD dwFlags
		);
 
	/*CPHashSessionKey*/
	BOOL HashSessionKey(
		HCRYPTHASH hHash,
		HCRYPTKEY hKey,
		DWORD dwFlags
		);
 
	/*CPSignHash*/
	BOOL SignHash(
		HCRYPTHASH hHash,
		DWORD dwKeySpec,
		LPCWSTR sDescription,
		DWORD dwFlags,
		BYTE *pbSignature,
		DWORD *pdwSigLen
		);
 	
	/*CPVerifySignature*/
	BOOL VerifySignature(
		HCRYPTHASH hHash,
		CONST BYTE *pbSignature,
		DWORD dwSigLen,
		HCRYPTKEY hPubKey,
		LPCWSTR sDescription,
		DWORD dwFlags
		);
};


#endif