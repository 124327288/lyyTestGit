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
//	声明密码算法模式
enum CryptMode{SOFTWARE = 0, HARDWARE = 1};

/////////////////////////////////////////////////////////////////////
//	ODF文件映像
//
#define MAX_XDF_LEN		2048
struct SHARE_XDF{
	BYTE  cContent[MAX_XDF_LEN];					//ODF文件的内容
	ULONG ulTotalLen;								//ODF文件的长度
	ULONG ulDataLen;								//ODF文件中包含数据的长度
	BOOL bHasFragment;								//ODF文件中是否存在碎片
};

//定义代表ODF文件类型的数据类型
typedef ULONG XDF_TYPE;
#define DFTYPE_PUK					0x00000001		//公钥的ODF
#define DFTYPE_TRUSTEDPUK			0x00000002		//可信任公钥的ODF
#define DFTYPE_PRK					0x00000003		//私钥的ODF
#define DFTYPE_SK					0x00000004		//秘密密钥的ODF
#define DFTYPE_CERT					0x00000005		//证书的ODF
#define DFTYPE_TRUSTEDCERT			0x00000006		//可信任证书的ODF
#define DFTYPE_DATA					0x00000007		//数据的ODF
#define DFTYPE_PUK_ECC				0x00000008		//ECC公钥的ODF
#define DFTYPE_PRK_ECC				0x00000009		//ECC私钥的ODF

//定义读取标记
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
//CSP的名字
#define TYCSP_NAME ("Tianyu Cryptographic Service Provider")

class CTYCSP{
//构造与析构函数
public:
	CTYCSP(LPCTSTR lpszName = TYCSP_NAME);
	virtual ~CTYCSP();

private:
	//用户自定义文件对象列表
	CUserFilePtrArray			m_arUserFiles;
	//包含的Key Container对象列表
	CCSPKeyContainerPtrArray	m_arKeyContainers;
	//列举Key Container时，当前Key Container列表的索引值
	int							m_nEnumKeyContainerIndex;
	//已读标志
	int							m_nReadFlag;
	
	//支持的算法标识
	//哈希：CALG_MD5、CALG_SHA
	//对称密钥：CALG_RC2、CALG_RC4
	//密钥对：CALG_RSA_SIGN、CALG_RSA_KEYX
	AlgIdArray					m_arAlgIds;
	//列举所支持的算法标识时，当前算法标识列表的索引值
	int							m_nEnumAlgIdIndex;
	
	//名字
	LPTSTR						m_szName;
	
	//类型
	DWORD						m_dwType;

	//版本号	
	DWORD						m_dwVersion;	
	
	//实现类型
	DWORD						m_dwImpType;
	
	//CSP句柄
	HCRYPTCSP					m_hHandle;
	//下一个KC的句柄
	HCRYPTKC					m_hNextKCHandle;

	//密码算法模式
	CryptMode					m_cryptMode;

public:
	//CSP初始化
	BOOL Initialize();
	//刷新内存映象，如对于CSP对象则是删除，另外再读出卡片中的FAT表
	void RefreshCard();
	//CSP退出
	BOOL Finalize(BOOL bWrite = TRUE);

	//获取CSP版本号
	DWORD GetVersion() const { return m_dwVersion;}
	//获取CSP类型
	DWORD GetType() const { return m_dwType; }
	//获取CSP名字
	LPCTSTR GetName() const { return m_szName; }
	//获取实现类型
	DWORD GetImpType() const { return m_dwImpType; }
	//获取CSP的句柄
	HCRYPTCSP GetHandle() const { return m_hHandle; }
	//设置CSP的句柄
	void SetHandle(HCRYPTCSP hHandle) { m_hHandle = hHandle; }
	//获取下一个KC的句柄
	HCRYPTKC GetNextKCHandle() { return ++m_hNextKCHandle; }

	//获取密码算法模式
	CryptMode GetCryptMode() const { return m_cryptMode; }

public:

	//通过句柄获取一个Key Container对象
	CCSPKeyContainer* GetKeyContainerByHandle(
		HCRYPTPROV hKeyContainer
		);
	//通过名字获取一个Key Container对象
	CCSPKeyContainer* GetKeyContainerByName(
		LPCTSTR lpszName
		);
	//创建一个Key Container对象
	void CreateKeyContainer(
		LPCTSTR lpszName,							//名字
		BOOL bInitOpen,								//创建的同时是否打开
		CCSPKeyContainer*& pCreatedKeyContainer,	//创建的对象
		BOOL bCreateOnToken = FALSE					//是否创建在卡中
		);
	//销毁一个Key Container对象
	void DestroyKeyContainer(
		CCSPKeyContainer* pDestroyKeyContainer,		//销毁的对象
		BOOL bDestroyOnToken = FALSE				//是否从卡中销毁
		);
	//获取当前用户缺省的Key Container名字
	BOOL GetDefaultKeyContainerName(
		TCHAR szDefaultName[UNLEN + 1]
		);
	//获取Key Container对象的数目
	int GetKeyContainerCount() const { return m_arKeyContainers.GetSize(); }
	//获取当前Key Container的创建索引
	int GetKeyContainerCreateIndex();

public:
	//通过句柄获取一个UserFile对象
	CUserFile* GetUserFileByHandle(
		HCRYPTPROV hKeyContainer
		);
	//通过名字获取一个UserFile对象
	CUserFile* GetUserFileByName(
		LPCTSTR lpszName
		);
	//销毁一个UserFile对象
	void DestroyUserFile(
		CUserFile* pDestroyUserFile,				//销毁的对象
		BOOL bDestroyOnToken = FALSE				//是否从卡中销毁
		);

	BOOL GetUserFileNameList(
		CHAR* szFileNameList,
		LPDWORD pcchSize
		);

private:
	//卡中私钥ODF文件的影像
	SHARE_XDF	m_xdfPrk;
	//卡中数据ODF文件的影像
	SHARE_XDF	m_xdfData;

	//从卡中读出Key Container
	BOOL ReadKeyContainer();
	//从卡中读出文件索引
	BOOL ReadFileIndex();
	//读出对象的DER编码
	BOOL ReadObjectDERs(
		BYTE path[2],						//ODF文件路径
		SHARE_XDF* pXdfRec,					//存储卡中ODF文件的影像
		CDERTool& tool						//存储对象的DER编码
		);
	//读取ODF文件中的记录
	BOOL ReadODF(
		FILEHANDLE hFile,					//ODF文件句柄
		BYTE* pBuffer,						//读出的数据
		DWORD dwBufferLen					//数据空间的大小
		);

	//销毁资源并初始化数据
	void DestroyResourceAndInitData();
	
public:
	//获取ODF文件的影像
	BOOL GetXdf(
		XDF_TYPE dfType,					//ODF文件类型
		SHARE_XDF* pXdfRec					//指向ODF文件影像的指针
		);
	//设置ODF文件的影像
	BOOL SetXdf(
		XDF_TYPE dfType,					//ODF文件类型
		SHARE_XDF* pXdfRec					//指向ODF文件影像的指针
		);
	//删除XDF中的碎片
	void RemoveXdfFragment(
		SHARE_XDF* pXdfRec					//指向ODF文件影像的指针
		);

	BOOL GetOffsetFormIndex(
		SHARE_XDF *pXdfRec,
		ULONG ulIndex,
		ULONG& ulOffset,
		ULONG& ulLen
		);

protected:
	//封装的读写器类
	CCSPReader		m_reader;

public:
	//开始一个事务
	BOOL BeginTransaction();
	//结束一个事务
	BOOL EndTransaction(
		DWORD dwDisposition = SCARD_LEAVE_CARD
		);
	//发送命令
	BOOL SendCommand(
		BYTE* pbCommand, 
		DWORD dwCommandLen, 
		BYTE* pbRespond = NULL, 
		DWORD* pdwRespondLen = NULL, 
		WORD* pwStatus = NULL
		);
	//连接
	BOOL Connect(BOOL bCheckCardValid = TRUE);

	//复位卡片
	BOOL ResetCard(BYTE* pbATR,	DWORD* pdwATR,	ResetMode mode =WARM);
	
	//断开
	BOOL DisConnect();

	BOOL GetATR(BYTE* pbATR, DWORD* pdwATRLen)
	{
		return m_reader.GetATR(pbATR, pdwATRLen);
	}

	//设置读写器的名字
	void SetReaderName(LPCTSTR lpszReaderName)
	{
		m_reader.SetName(lpszReaderName);
	}
	//获取读写器的名字
	LPCTSTR GetReaderName()
	{
		return m_reader.GetName();
	}
	//设置读写器的索引(for TYKEY)
	void SetReaderIndex(int nIndex)
	{
		m_reader.SetIndex(nIndex);
	}
	//获取读写器的索引(for TYKEY)
	int GetReaderIndex()
	{
		return m_reader.GetIndex();
	}
	int GetRealIndex()
	{
		return m_reader.GetRealIndex();
	}
	//设置读写器的类型
	void SetReaderType(ReaderType type)
	{
		m_reader.SetType(type);
	}
	//获取读写器的类型
	ReaderType GetReaderType()
	{
		return m_reader.GetType();
	}
	
	//获取卡片的类型
	CardType GetCardType() const 
	{ 
		return m_reader.GetCardType(); 
	}
	//获取卡片句柄
	CARDHANDLE GetCardHandle() const 
	{
		return m_reader.GetCardHandle(); 
	}

//以下为对卡的一些操作
private:
	int		m_nUserType;

public:
	//检测卡片是否存在
	BOOL CheckCardIsExist()
	{
		return m_reader.CheckCardIsExist();
	}

	//获取当前用户类型
	int GetUserType() const { return m_nUserType; }
	//登录
	BOOL Login(
		int nUserType,						//登录用户类型
		LPBYTE pPIN,						//PIN码
		DWORD dwPINLen,						//PIN码的长度
		DWORD& nRetryCount					//剩余可重试的次数
		);
	//注销
	BOOL Logout();
	//更改PIN码
	BOOL ChangePIN(
		LPBYTE pOldPIN,						//旧PIN
		DWORD dwOldPINLen,					//旧PIN的长度
		LPBYTE pNewPIN,						//新PIN
		DWORD dwNewPINLen					//新PIN的长度
		);
	//PIN解锁
	BOOL UnlockPIN(
		LPBYTE pUserDefaultPIN,				//解锁后用户的缺省PIN
		DWORD dwUserDefaultPINLen			//解锁后用户的缺省PIN的长度
		);
	//判断是否已登录为用户
	BOOL IsLogin() const { return (m_nUserType != UT_PUBLIC); }

	//获取可用的文件或创建
	BOOL GetWorkableFile(
		BYTE flag,
		DWORD dwSize,
		BYTE path[2]
		);
	//创建文件(不修改FAT表)
	BOOL CreateFile(
		BYTE path[2],
		DWORD dwSize,
		FILEHANDLE* phFile,
		BYTE type,
		BYTE readAuth,
		BYTE writeAuth
		);
	//删除文件
	BOOL DeleteFile(
		BYTE path[2]
		);

	//打开文件
	BOOL OpenFile(
		BYTE path[2],
		FILEHANDLE* phFile,
		LPDWORD pdwFileSize = NULL
		);
	//读文件
	BOOL ReadFile(
		FILEHANDLE hFile,
		DWORD dwReadLen,
		LPBYTE pReadBuffer,
		LPDWORD pdwRealReadLen,
		DWORD dwOffset = 0
		);
	//写文件
	BOOL WriteFile(
		FILEHANDLE hFile,
		LPBYTE pWriteBuffer,
		DWORD dwWriteBufferLen,
		DWORD dwOffset = 0
		);
	//关闭文件
	BOOL CloseFile(
		FILEHANDLE hFile
		);

	//产生随机数
	BOOL GenRandom(
		DWORD dwLen,
		BYTE *pbBuffer
		);

	void AddModify();

//以下对应于CryptSPI中的 Service Provider Functions(4)
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

//以下对应于CryptSPI中的 UserFile Functions
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

//以下对应于CryptSPI中的 TokenInfo Functions
public:
	BOOL GetTokenInfo(
		LPTOKENINFO pTokenInfo,
		BOOL bReload = FALSE
		);
	BOOL SetTokenInfo(
		LPTOKENINFO pTokenInfo
		);

	//获取EEPROM的大小
	BOOL GetE2Size(
		DWORD& dwTotalSize,					//总空间
		DWORD& dwTotoalSize2,				//不包含系统占用的总空间
		DWORD& dwUnusedSize					//可用空间
		);
	//查询COS版本
	BOOL GetCosVer(
		DWORD& dwVersion					//COS版本
		);

	//查询是否已下载SSF33算法
	BOOL IsSSF33Support();

	//获取PIN的重试次数信息
	BOOL GetPinRetryInfo(
		int nUserType,						//用户类型
		int& nMaxRetry,						//最大重试次数
		int& nLeftRetry						//剩余重试次数
		);

//以下对应于CryptSPI中的 Format Functions
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
//构造与析构函数
public:
	CTYCSPManager();
	~CTYCSPManager();

//方法
public:
	//构造CSP对象
	void CreateCSPs();
	//释放CSP对象
	void ReleaseCSPs();
	void CreatePCSCCSPs();
	void CreateUSBPortCSPs();
	void CreateCOMPortCSPs();

	BOOL IsFilterReader() const{ return m_bFilterReader; }
	void SetFilterReader(BOOL b) { m_bFilterReader = b; }
	void SetEnumReaderFlag(DWORD dwFlag) { m_dwEnumReaderFlag = dwFlag; }

public:
	//初始化
	BOOL Initialize();
	//释放资源
	BOOL Finalize();

	//通过句柄获取CSP对象
	CTYCSP* GetCSPByHandle(HCRYPTCSP hCSP);
	//通过读写器的名字获取CSP对象
	CTYCSP* GetCSPByReaderName(LPCTSTR lpszName);
	//通过读写器索引获取CSP对象
	CTYCSP* GetCSPByReaderIndex(int nIndex);
	CTYCSP* GetCPSByRealIndex(int nIndex);
	//获取CSP对象的数目
	DWORD GetCSPCount();
	//通过索引号获取CSP对象
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
	//CSP对象链表
	CTYCSPPtrArray	m_arCSPs;
	//下一个CSP对象的句柄
	HCRYPTCSP		m_hNextCSPHandle;
	//是否过滤读写器
	BOOL m_bFilterReader;
	//枚举读写器的标志
	DWORD m_dwEnumReaderFlag;
};

/////////////////////////////////////////////////////////////////////
//	声明唯一的TYCSPManager实例
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
//	功能：
//		获取指定算法的信息
//
//	返回：
//		TRUE:成功		FALSE:不支持该算法
//
//  参数：
//		PROV_ENUMALGS_EX& info	算法信息
//
//  说明：
//-------------------------------------------------------------------
BOOL GetAlgInfo(PROV_ENUMALGS_EX& info);

//-------------------------------------------------------------------
//	功能：
//		判断是否为支持的HASH的算法标识
//
//	返回：
//		TRUE:是		FALSE:不是
//
//  参数：
//		ALG_ID algId	算法标识
//
//  说明：
//-------------------------------------------------------------------
BOOL IsSupportHashAlgId(ALG_ID algId);

//-------------------------------------------------------------------
//	功能：
//		判断是否为支持的密钥对的算法标识
//
//	返回：
//		TRUE:是		FALSE:不是
//
//  参数：
//		ALG_ID algId	算法标识
//
//  说明：
//-------------------------------------------------------------------
BOOL IsSupportKeyPairAlgId(ALG_ID algId);

//-------------------------------------------------------------------
//	功能：
//		判断是否为支持的对称密钥算的法标识
//
//	返回：
//		TRUE:是		FALSE:不是
//
//  参数：
//		ALG_ID algId	算法标识
//
//  说明：
//-------------------------------------------------------------------
BOOL IsSupportSymmetricKeyAlgId(ALG_ID algId);


#endif