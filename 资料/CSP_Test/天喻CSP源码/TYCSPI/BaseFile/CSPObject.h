#ifndef __TYCSP_OBJECT_H__
#define __TYCSP_OBJECT_H__

/////////////////////////////////////////////////////////////////////
//
#include "Reader.h"
#include "DERTool.h"

class CCSPKeyContainer;
class CUserFile;
typedef CArrayTemplate<CCSPKeyContainer*, CCSPKeyContainer*> CCSPKeyContainerPtrArray;
typedef CArrayTemplate<CUserFile*, CUserFile*> CUserFilePtrArray;
typedef CArrayTemplate<ALG_ID, ALG_ID> AlgIdArray;

typedef WORD HCRYPTCSP;
typedef WORD HCRYPTKC;
#define MAKE_HCRYPTPROV(csp_handle, kc_handle) 	((HCRYPTPROV)(((HCRYPTPROV)((HCRYPTCSP)(csp_handle))) << 16 | (HCRYPTPROV)((HCRYPTKC)(kc_handle))))
#define GET_HCRYPTCSP(prov_handle) ((HCRYPTCSP)(((HCRYPTPROV)(prov_handle)) >> 16))

/////////////////////////////////////////////////////////////////////
//	���������㷨ģʽ
enum CryptMode{SOFTWARE = 0, HARDWARE = 1};

/////////////////////////////////////////////////////////////////////
//	ODF�ļ�ӳ��
//
#define MAX_XDF_LEN		2048
struct SHARE_XDF{
	BYTE  cContent[MAX_XDF_LEN];					//ODF�ļ�������
	ULONG ulTotalLen;								//ODF�ļ��ĳ���
	ULONG ulDataLen;								//ODF�ļ��а������ݵĳ���
	BOOL bHasFragment;								//ODF�ļ����Ƿ������Ƭ
};

//�������ODF�ļ����͵���������
typedef ULONG XDF_TYPE;
#define DFTYPE_PUK					0x00000001		//��Կ��ODF
#define DFTYPE_TRUSTEDPUK			0x00000002		//�����ι�Կ��ODF
#define DFTYPE_PRK					0x00000003		//˽Կ��ODF
#define DFTYPE_SK					0x00000004		//������Կ��ODF
#define DFTYPE_CERT					0x00000005		//֤���ODF
#define DFTYPE_TRUSTEDCERT			0x00000006		//������֤���ODF
#define DFTYPE_DATA					0x00000007		//���ݵ�ODF
#define DFTYPE_PUK_ECC				0x00000008		//ECC��Կ��ODF
#define DFTYPE_PRK_ECC				0x00000009		//ECC˽Կ��ODF

//�����ȡ���
#define READED_KEYCONTAINER			0x00000001
#define READED_FILEINDEX			0x00000002

/////////////////////////////////////////////////////////////////////
//
//
//typedef struct _PROV_ENUMALGS_EX 
//{
//    ALG_ID    aiAlgid;
//    DWORD     dwDefaultLen;
//    DWORD     dwMinLen;
//    DWORD     dwMaxLen;
//    DWORD     dwProtocols;
//    DWORD     dwNameLen;
//    CHAR      szName[20];
//    DWORD     dwLongNameLen;
//    CHAR      szLongName[40];
//} PROV_ENUMALGS_EX;
//
#define	RC2_NAME				_T("RC2")
#define RC2_LONG_NAME			_T("RSA Data Security's RC2")
#define RC2_DEFAULT_LEN			128
#define RC2_MIN_LEN				40
#define RC2_MAX_LEN				128
#define RC2_PROTOCOLS			0

#define RC2_DEF_EFF_LEN			0x28

#define RC4_NAME				_T("RC4")
#define RC4_LONG_NAME			_T("RSA Data Security's RC4")
#define RC4_DEFAULT_LEN			128
#define RC4_MIN_LEN				40
#define RC4_MAX_LEN				128
#define RC4_PROTOCOLS			0

#define DES_NAME				_T("DES")
#define DES_LONG_NAME			_T("Data Encryption Standard (DES)")
#define DES_DEFAULT_LEN			64
#define DES_MIN_LEN				56
#define DES_MAX_LEN				64
#define DES_PROTOCOLS			0

#define DES2_NAME				_T("2DES")
#define DES2_LONG_NAME			_T("DES-EDE")
#define DES2_DEFAULT_LEN		128
#define DES2_MIN_LEN			56
#define DES2_MAX_LEN			128
#define DES2_PROTOCOLS			0

#define DES3_NAME				_T("3DES")
#define DES3_LONG_NAME			_T("Triple-DES")
#define DES3_DEFAULT_LEN		192
#define DES3_MIN_LEN			56
#define DES3_MAX_LEN			192
#define DES3_PROTOCOLS			0

#define CALG_SSF33				(ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_EXAMPLE+1)
#define SSF33_NAME				_T("SSF33")
#define SSF33_LONG_NAME			_T("SSF33")
#define SSF33_DEFAULT_LEN		128
#define SSF33_MIN_LEN			128
#define SSF33_MAX_LEN			128
#define SSF33_PROTOCOLS			0

#define MD5_NAME				_T("MD5")
#define MD5_LONG_NAME			_T("Message Digest 5 (MD5)")
#define MD5_DEFAULT_LEN			128
#define MD5_MIN_LEN				128
#define MD5_MAX_LEN				128
#define MD5_PROTOCOLS			32

#define SHA_NAME				_T("SHA-1")	
#define SHA_LONG_NAME			_T("Secure Hash Algorithm (SHA-1)")
#define SHA_DEFAULT_LEN			160
#define SHA_MIN_LEN				160
#define SHA_MAX_LEN				160
#define SHA_PROTOCOLS			32

#define SSL3SHAMD5_NAME			_T("SSL3 SHAMD5")	
#define SSL3SHAMD5_LONG_NAME	_T("SSL3 SHAMD5")
#define SSL3SHAMD5_DEFAULT_LEN	288
#define SSL3SHAMD5_MIN_LEN		288
#define SSL3SHAMD5_MAX_LEN		288
#define SSL3SHAMD5_PROTOCOLS	0

#define RSA_SIGN_NAME			_T("RSA_SIGN")
#define RSA_SIGN_LONG_NAME		_T("RSA Signature")
#define RSA_SIGN_DEFAULT_LEN	1024
#define RSA_SIGN_MIN_LEN		1024
#define RSA_SIGN_MAX_LEN		2048
#define RSA_SIGN_PROTOCOLS		48	

#define RSA_KEYX_NAME			_T("RSA_KEYX")
#define RSA_KEYX_LONG_NAME		_T("RSA Key Exchange")
#define RSA_KEYX_DEFAULT_LEN	1024
#define RSA_KEYX_MIN_LEN		1024
#define RSA_KEYX_MAX_LEN		2048
#define RSA_KEYX_PROTOCOLS		48	

#define CALG_ECC_SIGN           (ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | ALG_SID_EXAMPLE+10)
#define ECC_SIGN_NAME			_T("ECC_SIGN")
#define ECC_SIGN_LONG_NAME		_T("ECC Signature")
#define ECC_SIGN_DEFAULT_LEN	192
#define ECC_SIGN_MIN_LEN		192
#define ECC_SIGN_MAX_LEN		192
#define ECC_SIGN_PROTOCOLS		48	

#define CALG_ECC_KEYX           (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | ALG_SID_EXAMPLE+11)
#define ECC_KEYX_NAME			_T("ECC_KEYX")
#define ECC_KEYX_LONG_NAME		_T("ECC Key Exchange")
#define ECC_KEYX_DEFAULT_LEN	192
#define ECC_KEYX_MIN_LEN		192
#define ECC_KEYX_MAX_LEN		192
#define ECC_KEYX_PROTOCOLS		48	


#define CALG_SCB2 (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|(ALG_SID_EXAMPLE+2))
#define SCB2_NAME				_T("SCB2")
#define SCB2_LONG_NAME			_T("SCB2")
#define SCB2_DEFAULT_LEN		256
#define SCB2_MIN_LEN			256
#define SCB2_MAX_LEN			256
#define SCB2_PROTOCOLS			0
/////////////////////////////////////////////////////////////////////
//	class CTYCSP
//
//CSP������
#define TYCSP_NAME ("Tianyu Cryptographic Service Provider")

class CTYCSP{
//��������������
public:
	CTYCSP(LPCTSTR lpszName = TYCSP_NAME);
	virtual ~CTYCSP();

private:
	//�û��Զ����ļ������б�
	CUserFilePtrArray			m_arUserFiles;
	//������Key Container�����б�
	CCSPKeyContainerPtrArray	m_arKeyContainers;
	//�о�Key Containerʱ����ǰKey Container�б������ֵ
	int							m_nEnumKeyContainerIndex;
	//�Ѷ���־
	int							m_nReadFlag;
	
	//֧�ֵ��㷨��ʶ
	//��ϣ��CALG_MD5��CALG_SHA
	//�Գ���Կ��CALG_RC2��CALG_RC4
	//��Կ�ԣ�CALG_RSA_SIGN��CALG_RSA_KEYX
	AlgIdArray					m_arAlgIds;
	//�о���֧�ֵ��㷨��ʶʱ����ǰ�㷨��ʶ�б������ֵ
	int							m_nEnumAlgIdIndex;
	
	//����
	LPTSTR						m_szName;
	
	//����
	DWORD						m_dwType;

	//�汾��	
	DWORD						m_dwVersion;	
	
	//ʵ������
	DWORD						m_dwImpType;
	
	//CSP���
	HCRYPTCSP					m_hHandle;
	//��һ��KC�ľ��
	HCRYPTKC					m_hNextKCHandle;

	//�����㷨ģʽ
	CryptMode					m_cryptMode;

public:
	//CSP��ʼ��
	BOOL Initialize();
	//ˢ���ڴ�ӳ�������CSP��������ɾ���������ٶ�����Ƭ�е�FAT��
	void RefreshCard();
	//CSP�˳�
	BOOL Finalize(BOOL bWrite = TRUE);

	//��ȡCSP�汾��
	DWORD GetVersion() const { return m_dwVersion;}
	//��ȡCSP����
	DWORD GetType() const { return m_dwType; }
	//��ȡCSP����
	LPCTSTR GetName() const { return m_szName; }
	//��ȡʵ������
	DWORD GetImpType() const { return m_dwImpType; }
	//��ȡCSP�ľ��
	HCRYPTCSP GetHandle() const { return m_hHandle; }
	//����CSP�ľ��
	void SetHandle(HCRYPTCSP hHandle) { m_hHandle = hHandle; }
	//��ȡ��һ��KC�ľ��
	HCRYPTKC GetNextKCHandle() { return ++m_hNextKCHandle; }

	//��ȡ�����㷨ģʽ
	CryptMode GetCryptMode() const { return m_cryptMode; }

public:

	//ͨ�������ȡһ��Key Container����
	CCSPKeyContainer* GetKeyContainerByHandle(
		HCRYPTPROV hKeyContainer
		);
	//ͨ�����ֻ�ȡһ��Key Container����
	CCSPKeyContainer* GetKeyContainerByName(
		LPCTSTR lpszName
		);
	//����һ��Key Container����
	void CreateKeyContainer(
		LPCTSTR lpszName,							//����
		BOOL bInitOpen,								//������ͬʱ�Ƿ��
		CCSPKeyContainer*& pCreatedKeyContainer,	//�����Ķ���
		BOOL bCreateOnToken = FALSE					//�Ƿ񴴽��ڿ���
		);
	//����һ��Key Container����
	void DestroyKeyContainer(
		CCSPKeyContainer* pDestroyKeyContainer,		//���ٵĶ���
		BOOL bDestroyOnToken = FALSE				//�Ƿ�ӿ�������
		);
	//��ȡ��ǰ�û�ȱʡ��Key Container����
	BOOL GetDefaultKeyContainerName(
		TCHAR szDefaultName[UNLEN + 1]
		);
	//��ȡKey Container�������Ŀ
	int GetKeyContainerCount() const { return m_arKeyContainers.GetSize(); }
	//��ȡ��ǰKey Container�Ĵ�������
	int GetKeyContainerCreateIndex();

public:
	//ͨ�������ȡһ��UserFile����
	CUserFile* GetUserFileByHandle(
		HCRYPTPROV hKeyContainer
		);
	//ͨ�����ֻ�ȡһ��UserFile����
	CUserFile* GetUserFileByName(
		LPCTSTR lpszName
		);
	//����һ��UserFile����
	void DestroyUserFile(
		CUserFile* pDestroyUserFile,				//���ٵĶ���
		BOOL bDestroyOnToken = FALSE				//�Ƿ�ӿ�������
		);

	BOOL GetUserFileNameList(
		CHAR* szFileNameList,
		LPDWORD pcchSize
		);

private:
	//����˽ԿODF�ļ���Ӱ��
	SHARE_XDF	m_xdfPrk;
	//��������ODF�ļ���Ӱ��
	SHARE_XDF	m_xdfData;

	//�ӿ��ж���Key Container
	BOOL ReadKeyContainer();
	//�ӿ��ж����ļ�����
	BOOL ReadFileIndex();
	//���������DER����
	BOOL ReadObjectDERs(
		BYTE path[2],						//ODF�ļ�·��
		SHARE_XDF* pXdfRec,					//�洢����ODF�ļ���Ӱ��
		CDERTool& tool						//�洢�����DER����
		);
	//��ȡODF�ļ��еļ�¼
	BOOL ReadODF(
		FILEHANDLE hFile,					//ODF�ļ����
		BYTE* pBuffer,						//����������
		DWORD dwBufferLen					//���ݿռ�Ĵ�С
		);

	//������Դ����ʼ������
	void DestroyResourceAndInitData();
	
public:
	//��ȡODF�ļ���Ӱ��
	BOOL GetXdf(
		XDF_TYPE dfType,					//ODF�ļ�����
		SHARE_XDF* pXdfRec					//ָ��ODF�ļ�Ӱ���ָ��
		);
	//����ODF�ļ���Ӱ��
	BOOL SetXdf(
		XDF_TYPE dfType,					//ODF�ļ�����
		SHARE_XDF* pXdfRec					//ָ��ODF�ļ�Ӱ���ָ��
		);
	//ɾ��XDF�е���Ƭ
	void RemoveXdfFragment(
		SHARE_XDF* pXdfRec					//ָ��ODF�ļ�Ӱ���ָ��
		);

	BOOL GetOffsetFormIndex(
		SHARE_XDF *pXdfRec,
		ULONG ulIndex,
		ULONG& ulOffset,
		ULONG& ulLen
		);

protected:
	//��װ�Ķ�д����
	CCSPReader		m_reader;

public:
	//��ʼһ������
	BOOL BeginTransaction();
	//����һ������
	BOOL EndTransaction(
		DWORD dwDisposition = SCARD_LEAVE_CARD
		);
	//��������
	BOOL SendCommand(
		BYTE* pbCommand, 
		DWORD dwCommandLen, 
		BYTE* pbRespond = NULL, 
		DWORD* pdwRespondLen = NULL, 
		WORD* pwStatus = NULL
		);
	//����
	BOOL Connect(BOOL bCheckCardValid = TRUE);

	//��λ��Ƭ
	BOOL ResetCard(BYTE* pbATR,	DWORD* pdwATR,	ResetMode mode =WARM);
	
	//�Ͽ�
	BOOL DisConnect();

	BOOL GetATR(BYTE* pbATR, DWORD* pdwATRLen)
	{
		return m_reader.GetATR(pbATR, pdwATRLen);
	}

	//���ö�д��������
	void SetReaderName(LPCTSTR lpszReaderName)
	{
		m_reader.SetName(lpszReaderName);
	}
	//��ȡ��д��������
	LPCTSTR GetReaderName()
	{
		return m_reader.GetName();
	}
	//���ö�д��������(for TYKEY)
	void SetReaderIndex(int nIndex)
	{
		m_reader.SetIndex(nIndex);
	}
	//��ȡ��д��������(for TYKEY)
	int GetReaderIndex()
	{
		return m_reader.GetIndex();
	}
	int GetRealIndex()
	{
		return m_reader.GetRealIndex();
	}
	//���ö�д��������
	void SetReaderType(ReaderType type)
	{
		m_reader.SetType(type);
	}
	//��ȡ��д��������
	ReaderType GetReaderType()
	{
		return m_reader.GetType();
	}
	
	//��ȡ��Ƭ������
	CardType GetCardType() const 
	{ 
		return m_reader.GetCardType(); 
	}
	//��ȡ��Ƭ���
	CARDHANDLE GetCardHandle() const 
	{
		return m_reader.GetCardHandle(); 
	}

//����Ϊ�Կ���һЩ����
private:
	int		m_nUserType;

public:
	//��⿨Ƭ�Ƿ����
	BOOL CheckCardIsExist()
	{
		return m_reader.CheckCardIsExist();
	}

	//��ȡ��ǰ�û�����
	int GetUserType() const { return m_nUserType; }
	//��¼
	BOOL Login(
		int nUserType,						//��¼�û�����
		LPBYTE pPIN,						//PIN��
		DWORD dwPINLen,						//PIN��ĳ���
		DWORD& nRetryCount					//ʣ������ԵĴ���
		);
	//ע��
	BOOL Logout();
	//����PIN��
	BOOL ChangePIN(
		LPBYTE pOldPIN,						//��PIN
		DWORD dwOldPINLen,					//��PIN�ĳ���
		LPBYTE pNewPIN,						//��PIN
		DWORD dwNewPINLen					//��PIN�ĳ���
		);
	//PIN����
	BOOL UnlockPIN(
		LPBYTE pUserDefaultPIN,				//�������û���ȱʡPIN
		DWORD dwUserDefaultPINLen			//�������û���ȱʡPIN�ĳ���
		);
	//�ж��Ƿ��ѵ�¼Ϊ�û�
	BOOL IsLogin() const { return (m_nUserType != UT_PUBLIC); }

	//��ȡ���õ��ļ��򴴽�
	BOOL GetWorkableFile(
		BYTE flag,
		DWORD dwSize,
		BYTE path[2]
		);
	//�����ļ�(���޸�FAT��)
	BOOL CreateFile(
		BYTE path[2],
		DWORD dwSize,
		FILEHANDLE* phFile,
		BYTE type,
		BYTE readAuth,
		BYTE writeAuth
		);
	//ɾ���ļ�
	BOOL DeleteFile(
		BYTE path[2]
		);

	//���ļ�
	BOOL OpenFile(
		BYTE path[2],
		FILEHANDLE* phFile,
		LPDWORD pdwFileSize = NULL
		);
	//���ļ�
	BOOL ReadFile(
		FILEHANDLE hFile,
		DWORD dwReadLen,
		LPBYTE pReadBuffer,
		LPDWORD pdwRealReadLen,
		DWORD dwOffset = 0
		);
	//д�ļ�
	BOOL WriteFile(
		FILEHANDLE hFile,
		LPBYTE pWriteBuffer,
		DWORD dwWriteBufferLen,
		DWORD dwOffset = 0
		);
	//�ر��ļ�
	BOOL CloseFile(
		FILEHANDLE hFile
		);

	//���������
	BOOL GenRandom(
		DWORD dwLen,
		BYTE *pbBuffer
		);

	void AddModify();

//���¶�Ӧ��CryptSPI�е� Service Provider Functions(4)
public:
	/*CPAcquireContext*/
	BOOL AcquireContext(
		HCRYPTPROV *phProv,
		CHAR *pszContainer,
		DWORD dwFlags,
		PVTableProvStruc pVTable
		);

	/*CPReleaseContext*/
	BOOL ReleaseContext(
		HCRYPTPROV hProv,
		DWORD dwFlags
		);

	/*CPGetProvParam*/
	BOOL GetProvParam(
		HCRYPTPROV hProv,
		DWORD dwParam,
		BYTE *pbData,
		DWORD *pdwDataLen,
		DWORD dwFlags
		);
 
	/*CPSetProvParam*/
	BOOL SetProvParam(
		HCRYPTPROV hProv,
		DWORD dwParam,
		BYTE *pbData,
		DWORD dwFlags
		);

//���¶�Ӧ��CryptSPI�е� UserFile Functions
public:
	BOOL AcquireUserFile(
		HCRYPTPROV *phProv,
		CHAR* szFileName,
		DWORD dwFileSize,
		DWORD dwFlags
		);
	BOOL ReleaseUserFile(
		HCRYPTPROV hProv
		);

//���¶�Ӧ��CryptSPI�е� TokenInfo Functions
public:
	BOOL GetTokenInfo(
		LPTOKENINFO pTokenInfo,
		BOOL bReload = FALSE
		);
	BOOL SetTokenInfo(
		LPTOKENINFO pTokenInfo
		);

	//��ȡEEPROM�Ĵ�С
	BOOL GetE2Size(
		DWORD& dwTotalSize,					//�ܿռ�
		DWORD& dwTotoalSize2,				//������ϵͳռ�õ��ܿռ�
		DWORD& dwUnusedSize					//���ÿռ�
		);
	//��ѯCOS�汾
	BOOL GetCosVer(
		DWORD& dwVersion					//COS�汾
		);

	//��ѯ�Ƿ�������SSF33�㷨
	BOOL IsSSF33Support();

	//��ȡPIN�����Դ�����Ϣ
	BOOL GetPinRetryInfo(
		int nUserType,						//�û�����
		int& nMaxRetry,						//������Դ���
		int& nLeftRetry						//ʣ�����Դ���
		);

//���¶�Ӧ��CryptSPI�е� Format Functions
public:
	BOOL Format(
		LPFORMATINFO pFormatInfo
		);

	BOOL EraseE2();
};

/////////////////////////////////////////////////////////////////////
//	class CTYCSPManager
//
typedef CArrayTemplate<CTYCSP*, CTYCSP*> CTYCSPPtrArray;

class CTYCSPManager{
//��������������
public:
	CTYCSPManager();
	~CTYCSPManager();

//����
public:
	//����CSP����
	void CreateCSPs();
	//�ͷ�CSP����
	void ReleaseCSPs();
	void CreatePCSCCSPs();
	void CreateUSBPortCSPs();
	void CreateCOMPortCSPs();

	BOOL IsFilterReader() const{ return m_bFilterReader; }
	void SetFilterReader(BOOL b) { m_bFilterReader = b; }
	void SetEnumReaderFlag(DWORD dwFlag) { m_dwEnumReaderFlag = dwFlag; }

public:
	//��ʼ��
	BOOL Initialize();
	//�ͷ���Դ
	BOOL Finalize();

	//ͨ�������ȡCSP����
	CTYCSP* GetCSPByHandle(HCRYPTCSP hCSP);
	//ͨ����д�������ֻ�ȡCSP����
	CTYCSP* GetCSPByReaderName(LPCTSTR lpszName);
	//ͨ����д��������ȡCSP����
	CTYCSP* GetCSPByReaderIndex(int nIndex);
	CTYCSP* GetCPSByRealIndex(int nIndex);
	//��ȡCSP�������Ŀ
	DWORD GetCSPCount();
	//ͨ�������Ż�ȡCSP����
	CTYCSP* GetCSPAt(int nIndex);

	//Connect
	BOOL Connect(
		HCRYPTPROV *phProv,
		DWORD dwIndex
		);
	BOOL Connect(
		HCRYPTPROV *phProv,
		CHAR* szReaderName
		);

	//AcquireContext
	BOOL AcquireContext(
		HCRYPTPROV *phProv,
		CHAR *pszContainer,
		DWORD dwFlags,
		DWORD dwIndex
		);
	BOOL AcquireContext(
		HCRYPTPROV *phProv,
		CHAR *pszContainer,
		DWORD dwFlags,
		CHAR* szReaderName
		);

	//AcquireUserfile
	BOOL AcquireUserFile(
		HCRYPTPROV *phProv,
		CHAR* szFileName,
		DWORD dwFileSize,
		DWORD dwFlags,
		DWORD dwIndex
		);
	BOOL AcquireUserFile(
		HCRYPTPROV *phProv,
		CHAR* szFileName,
		DWORD dwFileSize,
		DWORD dwFlags,
		CHAR* szReaderName
		);

private:
	//CSP��������
	CTYCSPPtrArray	m_arCSPs;
	//��һ��CSP����ľ��
	HCRYPTCSP		m_hNextCSPHandle;
	//�Ƿ���˶�д��
	BOOL m_bFilterReader;
	//ö�ٶ�д���ı�־
	DWORD m_dwEnumReaderFlag;
};

/////////////////////////////////////////////////////////////////////
//	����Ψһ��TYCSPManagerʵ��
//
extern CTYCSPManager g_theTYCSPManager;

/////////////////////////////////////////////////////////////////////
//	class CCSPRandomNumberGenerator
//
class CCSPRandomNumberGenerator : public RandomNumberGenerator{
public:
	void init();
	virtual byte GetByte();
};

/////////////////////////////////////////////////////////////////////
//	Helper Functions

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡָ���㷨����Ϣ
//
//	���أ�
//		TRUE:�ɹ�		FALSE:��֧�ָ��㷨
//
//  ������
//		PROV_ENUMALGS_EX& info	�㷨��Ϣ
//
//  ˵����
//-------------------------------------------------------------------
BOOL GetAlgInfo(PROV_ENUMALGS_EX& info);

//-------------------------------------------------------------------
//	���ܣ�
//		�ж��Ƿ�Ϊ֧�ֵ�HASH���㷨��ʶ
//
//	���أ�
//		TRUE:��		FALSE:����
//
//  ������
//		ALG_ID algId	�㷨��ʶ
//
//  ˵����
//-------------------------------------------------------------------
BOOL IsSupportHashAlgId(ALG_ID algId);

//-------------------------------------------------------------------
//	���ܣ�
//		�ж��Ƿ�Ϊ֧�ֵ���Կ�Ե��㷨��ʶ
//
//	���أ�
//		TRUE:��		FALSE:����
//
//  ������
//		ALG_ID algId	�㷨��ʶ
//
//  ˵����
//-------------------------------------------------------------------
BOOL IsSupportKeyPairAlgId(ALG_ID algId);

//-------------------------------------------------------------------
//	���ܣ�
//		�ж��Ƿ�Ϊ֧�ֵĶԳ���Կ��ķ���ʶ
//
//	���أ�
//		TRUE:��		FALSE:����
//
//  ������
//		ALG_ID algId	�㷨��ʶ
//
//  ˵����
//-------------------------------------------------------------------
BOOL IsSupportSymmetricKeyAlgId(ALG_ID algId);


#endif