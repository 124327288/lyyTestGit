//-------------------------------------------------------------------
//	���ļ�Ϊ TY Cryptographic Service Provider ����ɲ���
//
//
//	��Ȩ���� ������Ϣ��ҵ���޹�˾ (c) 1996 - 2005 ����һ��Ȩ��
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
//��������������
public:
	CCSPKeyContainer(
		CTYCSP* pCSPObject,
		LPCTSTR lpszName, 
		BOOL bInitOpen = TRUE
		);
	~CCSPKeyContainer();

//����
private:
	//CSP����
	CTYCSP*						m_pCSPObject;
	
	//������Կ
	CCSPKeyPtrArray				m_arSessionKeys;

	//��Կ��
	CCSPKeyPtrArray				m_arKeyPair;

	//Hash����
	CCSPHashObjectPtrArray		m_arHashObjects;

	//����
	CString						m_szName;

	//�Ƿ񱻴�
	BOOL						m_bOpened;

	//�Ƿ��ͷ�
	BOOL						m_bReleased;

	//���
	HCRYPTPROV					m_hHandle;

	//�ڿ��е�����
	int							m_nIndexOnToken;

	//���ü���
	DWORD						m_dwRefCount;

public:
	//��ȡCSP����
	CTYCSP* GetCSPObject() const { return m_pCSPObject; }
	//��ȡKey Container����ľ��
	HCRYPTPROV GetHandle() const { return m_hHandle; }
	//��ȡKey Container������
	CString GetName() const {return m_szName;}
	//�ж�Key Container�Ƿ񱻴�
	BOOL IsOpened() const { return m_bOpened;}
	//�ж�Key Container�Ƿ��ѱ��ͷ�
	BOOL IsReleased() const { return m_bReleased; }
	//��Key Container
	void Open();
	//�������ü���
	DWORD AddRef();
	//�ͷ�Key Container
	DWORD Release();
	//�ж��Ƿ����ܱ�������Կ��
	BOOL HaveProtectedKeyPairs();
	//�ж��Ƿ񴴽���Token��
	BOOL IsToken() { return (m_nIndexOnToken >= 0); }

//�����ά��
public:
	//ͨ�������ȡ��Կ����
	CCSPKey* GetKeyObjectByHandle(HCRYPTKEY hKey);
	//ͨ�������ȡHASH����
	CCSPHashObject* GetHashObjectByHandle(HCRYPTHASH hHash);
	//ͨ�������ȡ������Կ����
	CCSPKey* GetSessionKeyObjectByHandle(HCRYPTKEY hKey);
	//ͨ�������ȡ��Կ��
	CCSPKey* GetKeyPairObjectByHandle(HCRYPTKEY hKey);
	//��ȡָ���㷨��ʶ����Կ��
	CCSPKey* GetKeyPairObjectByAlgId(ALG_ID algId);
	//�ж��Ƿ��Ѵ���ָ���㷨��ʶ����Կ��
	BOOL IsKeyPairExist(ALG_ID algId);

protected:
	//ɾ��HASH����
	void DeleteHashObjects(BOOL bDestroyOnToken = FALSE);
	//ɾ��������Կ����
	void DeleteSessionKeyObjects(BOOL bDestroyOnToken = FALSE);
	//ɾ����Կ�Զ���
	void DeleteKeyPairObjects(BOOL bDestroyOnToken = FALSE);
	//ɾ��KeyContainer�е����ж���
	void DeleteAllObjects(BOOL bDestroyOnToken = FALSE);
	//����ָ���㷨��ʶ����Կ��
	void DestroyKeyPair(ALG_ID algId);
	//�����㷨��ʶ������Կ����
	CCSPKey* CreateKeyObjectByAlgId(ALG_ID algId, BOOL bIsPublicKey = FALSE);
	//���Ʋ�����һ����Կ����
	BOOL DuplicateSessionKeyObject(CCSPKey* pSource, CCSPKey*& pDuplicate);

//�뿨�йصĲ���
public:
	//�ڿ��ϴ�����Key Container
	BOOL CreateOnToken(int nIndex);
	//�ڿ���ɾ����Key Container
	BOOL DestroyOnToken();
	//��ȡ��Key Container�ڿ��ϵ�����
	int GetTokenIndex() const{ return m_nIndexOnToken; }
	//���ø�Key Container�ڿ��ϵ�����
	void SetTokenIndex(int nIndex);
	//������Կ��
	void LoadKeyPairs(BYTE* pDERStr, ULONG dwDERLen);
	//��ȡ��Կ�ԵĴ�������
	int GetKeyPairCreateIndex() const { return GetTokenIndex(); }

protected:

//���¶�ӦCryptSPI�ӿ�(21)
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