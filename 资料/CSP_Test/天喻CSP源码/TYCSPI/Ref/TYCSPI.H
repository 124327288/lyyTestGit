//
//	DEVELOP INTERFACE COMPATIBLE WITH TYCSP
//

#ifndef __TY_CRYPTSPI_H__
#define __TY_CRYPTSPI_H__

#define _WIN32_WINNT				0x0400
#include "wincrypt.h"

/////////////////////////////////////////////////////////////////////
//
//	STRUCTURE DEFINITION

//智能卡信息
typedef struct TOKENINFO{
	CHAR manufacturerID[32];		//制造商的名称
	CHAR label[32];					//Token的名字
	CHAR model[16];					//Token的模式
	CHAR serialNumber[16];			//Token的序列号
	BYTE pinMaxRetry;				//管理员和用户PIN的最大重试次数
}TOKENINFO, *LPTOKENINFO;

//格式化信息
typedef struct FORMATINFO{
	TOKENINFO tokenInfo;			//智能卡信息
	LPBYTE userPIN;					//用户初始PIN
	DWORD userPINLen;				//用户初始PIN的长度,如果为0,则初始PIN为"1234"
	BYTE userPINMaxRetry;			//用户PIN重试次数			
	LPBYTE soPIN;					//管理员初始PIN
	DWORD soPINLen;					//管理员初始PIN的长度,如果为0,则初始PIN为"1234"
	BYTE soPINMaxRetry;				//管理员PIN重试次数			
}FORMATINFO, *LPFORMATINFO;

/////////////////////////////////////////////////////////////////////
//
//	MACRO DEFINITION

//用户文件的操作模式(LOWORD)
#define USERFILE_NEW				0x0000			//新建一个用户文件
#define USERFILE_OPEN				0x0001			//打开一个用户文件
#define USERFILE_DELETE				0x0002			//删除一个用户文件

//新建文件时,读写权限设定(HIWORD)
#define USERFILE_AUTH_READ			0x0001			//读文件需要权限
#define USERFILE_AUTH_WRITE			0x0002			//写文件需要权限

//用户类型或状态
#define UT_PUBLIC					0				//未登录
#define UT_USER						1				//登录为用户
#define UT_SO						2				//登录为管理员

//枚举读写器标志
#define ENUM_PCSC_READER			0x00000001
#define ENUM_USBPORT_READER			0x00000002
#define ENUM_SERIALPORT_READER		0x00000004

//字节顺序模式
enum ByteOrderMode{ BOM_LITTLE_ENDIAN = 1, BOM_BIG_ENDIAN = 2};

//定义SSF33算法标识
#define ALG_SID_SSF33			100
#define CALG_SSF33				(ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_SSF33)

//复位模式
enum ResetMode{COLD, WARM};

/////////////////////////////////////////////////////////////////////
//
//	STATIC LIB FUNCTIONS
#ifdef USE_TYCSPI_STATIC_LIB
BOOL WINAPI CPStaticLibInitialize();
BOOL WINAPI CPStaticLibFinalize();
#endif

/////////////////////////////////////////////////////////////////////
//
//	INTERFACE DEFINITION

//-------------------------------------------------------------------
//
//	Service Provider Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	功能：
//		打开、新建或删除指定TOKEN中的一个容器
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV* phProv		对于打开或新建返回的容器句柄
//		CHAR* pszContainer		容器名称
//		DWORD dwFlags			支持以下值，意义见MSDN描述
//			0
//			CRYPT_VERIFYCONTEXT
//			CRYPT_NEWKEYSET
//			CRYPT_DELETEKEYSET
//		DWORD dwIndex			TOKEN的索引号(读卡器索引或列表索引)
//
//  说明：
//		缺省为列表索引
//-------------------------------------------------------------------
BOOL WINAPI CPAcquireContext(
	OUT HCRYPTPROV *phProv,
	IN CHAR *pszContainer,
	IN DWORD dwFlags,
	IN DWORD dwIndex
	);

//-------------------------------------------------------------------
//	功能：
//		打开、新建或删除指定TOKEN中的一个容器
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV* phProv		对于打开或新建返回的容器句柄
//		CHAR* pszContainer		容器名称
//		DWORD dwFlags			支持以下值，意义见MSDN描述
//			0
//			CRYPT_VERIFYCONTEXT
//			CRYPT_NEWKEYSET
//			CRYPT_DELETEKEYSET
//		CHAR* szReaderName		TOKEN的名称
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPAcquireContext2(
	OUT HCRYPTPROV *phProv,
	IN CHAR *pszContainer,
	IN DWORD dwFlags,
	IN CHAR* szReaderName
	);

//-------------------------------------------------------------------
//	功能：
//		关闭打开的容器
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv	容器句柄
//		DWORD dwFlags		总是为0
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPReleaseContext(
	IN HCRYPTPROV hProv,
	IN DWORD dwFlags
	);

//-------------------------------------------------------------------
//	功能：
//		获取容器参数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv	容器句柄
//		DWORD dwParam		参数类型，支持以下取值,意义见MSDN描述
//			PP_CONTAINER
//			PP_ENUMALGS
//			PP_ENUMALGS_EX
//			PP_ENUMCONTAINERS
//			PP_NAME
//			PP_VERSION
//			PP_IMPTYPE
//			PP_PROVTYPE
//		BYTE* pbData		返回的数据
//		DWORD* pdwDataLen	返回数据的长度
//		DWORD dwFlags		标识，支持以下取值,意义见MSDN描述
//			CRYPT_FIRST
//			CRYPT_NEXT
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetProvParam(
	IN HCRYPTPROV hProv,  
	IN DWORD dwParam,     
	OUT BYTE *pbData,      
	IN OUT DWORD *pdwDataLen, 
	IN DWORD dwFlags      
	);

//-------------------------------------------------------------------
//	功能：
//		设置容器参数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv	容器句柄
//		DWORD dwParam		参数类型，支持以下取值,意义见MSDN描述
//		BYTE* pbData		设置的数据
//		DWORD dwFlags		标识，支持以下取值,意义见MSDN描述
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPSetProvParam(
	IN HCRYPTPROV hProv,  
	IN DWORD dwParam,     
	IN BYTE *pbData,      
	IN DWORD dwFlags      
	);
 
//-------------------------------------------------------------------
//
//	Key Generation and Exchange Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	功能：
//		产生密钥(对称密钥或非对称密钥)
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		ALG_ID AlgId			密钥标识，支持以下取值,意义见MSDN描述
//			CALG_RC2
//			CALG_RC4
//			CALG_3DES
//			CALG_3DES_112
//			CALG_SSF33
//			CALG_RSA_SIGN,AT_SIGNATURE
//			CALG_RSA_KEYX,AT_KEYEXCHANGE
//		DWORD dwFlags			密钥属性设置，支持以下取值,意义见MSDN描述
//			CRYPT_EXPORTABLE
//			CRYPT_CREATE_SALT
//			CRYPT_NO_SALT
//			CRYPT_USER_PROTECTED
//		HCRYPTKEY* phKey		产生的密钥句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGenKey(
	IN HCRYPTPROV hProv, 
	IN ALG_ID Algid,     
	IN DWORD dwFlags,    
	OUT HCRYPTKEY *phKey  
	);

//-------------------------------------------------------------------
//	功能：
//		复制密钥
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			待复制的密钥句柄
//		DWORD* pdwReserved		总为NULL
//		DWORD dwFlags			总为0
//		HCRYPTKEY* phKey		复制的密钥句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPDuplicateKey(
	IN HCRYPTPROV hProv,    
	IN HCRYPTKEY hKey,      
	IN DWORD *pdwReserved,  
	IN DWORD dwFlags,       
	OUT HCRYPTKEY* phKey     
	);

//-------------------------------------------------------------------
//	功能：
//		派生出对称密钥
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		ALG_ID Algid			算法标识
//		HCRYPTHASH hBaseData	基础数据	
//		DWORD dwFlags			密钥属性设置，支持以下取值,意义见MSDN描述
//			CRYPT_EXPORTABLE
//			CRYPT_CREATE_SALT
//			CRYPT_NO_SALT
//			CRYPT_USER_PROTECTED
//		HCRYPTKEY* phKey		派生出的密钥句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPDeriveKey(
	IN HCRYPTPROV hProv,      
	IN ALG_ID Algid,          
	IN HCRYPTHASH hBaseData,  
	IN DWORD dwFlags,         
	OUT HCRYPTKEY *phKey       
	);

//-------------------------------------------------------------------
//	功能：
//		销毁对称密钥
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY pKey			密钥句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPDestroyKey(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey     
	);

//-------------------------------------------------------------------
//	功能：
//		销毁密钥对
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		DWORD dwKeySpec			密钥对类型
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPDestroyKeyPair(
	IN HCRYPTPROV hProv,  
	IN DWORD dwKeySpec      
	);

//-------------------------------------------------------------------
//	功能：
//		获取密钥参数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			密钥句柄
//		DWORD dwParam			参数类型，支持以下取值,意义见MSDN描述
//			KP_ALGID 
//			KP_BLOCKLEN 
//			KP_SALT 
//			KP_PERMISSIONS 
//			KP_IV 
//			KP_PADDING 
//			KP_MODE 
//			KP_MODE_BITS
//			KP_EFFECTIVE_KEYLEN 
//			KP_CERTIFICATE
//		BYTE* pbData			返回的数据
//		DWORD* pdwDataLen		返回数据的长度
//		DWORD dwFlags			总是为0			
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetKeyParam(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey,    
	IN DWORD dwParam,     
	OUT BYTE *pbData,      
	IN OUT DWORD *pdwDataLen, 
	IN DWORD dwFlags      
	);

//-------------------------------------------------------------------
//	功能：
//		设置密钥参数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			密钥句柄
//		DWORD dwParam			参数类型，支持以下取值,意义见MSDN描述
//			KP_ALGID 
//			KP_BLOCKLEN 
//			KP_SALT 
//			KP_PERMISSIONS 
//			KP_IV 
//			KP_PADDING 
//			KP_MODE 
//			KP_MODE_BITS
//			KP_EFFECTIVE_KEYLEN 
//			KP_CERTIFICATE
//		BYTE* pbData			设置的数据
//		DWORD dwFlags			总是为0			
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPSetKeyParam(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey,    
	IN DWORD dwParam,     
	IN BYTE *pbData,      
	IN DWORD dwFlags      
	);

//-------------------------------------------------------------------
//	功能：
//		导出密钥
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			待导出密钥句柄
//		HCRYPTKEY hExpKey		导出密钥用的加密密钥
//		DWORD dwBlobType		密钥BLOB的类型		
//		DWORD dwFlags			总是为0
//		BYTE* pbData			导出的数据
//		DWORD* pdwDataLen		导出数据的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPExportKey(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey,    
	IN HCRYPTKEY hExpKey, 
	IN DWORD dwBlobType,  
	IN DWORD dwFlags,     
	OUT BYTE *pbData,      
	IN OUT DWORD *pdwDataLen  
	);

//-------------------------------------------------------------------
//	功能：
//		导入密钥
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		CONST BYTE *pbData		导入的数据
//		DWORD dwDataLen			导入数据的长度
//		HCRYPTKEY hImpKey		导入时解密用的密钥句柄		
//		DWORD dwFlags			标识，支持以下取值,意义见MSDN描述
//			CRYPT_EXPORTABLE 
//		HCRYPTKEY *phKey		导入产生的密钥句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPImportKey(
	IN HCRYPTPROV hProv,   
	IN CONST BYTE *pbData, 
	IN DWORD dwDataLen,    
	IN HCRYPTKEY hImpKey,  
	IN DWORD dwFlags,      
	OUT HCRYPTKEY *phKey    
	);

//-------------------------------------------------------------------
//	功能：
//		导出公钥的DER编码
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKeyPair		密钥对句柄
//		LPBYTE pbDERCode		导出的编码
//		LPDWORD pdwDERCodeLen	导出的编码长度		
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPExportPublicKeyDERCode(
	IN HCRYPTPROV hProv,
	IN HCRYPTKEY hKeyPair,
	OUT LPBYTE pbDERCode,
	IN OUT LPDWORD pdwDERCodeLen
	);

//-------------------------------------------------------------------
//	功能：
//		查询密钥对
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		DWORD dwKeySpec			密钥对类型
//		HCRYPTKEY hKeyPair		密钥对句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserKey(
	IN HCRYPTPROV hProv,     
	IN DWORD dwKeySpec,      
	OUT HCRYPTKEY *phUserKey  
	);

//-------------------------------------------------------------------
//	功能：
//		产生随机数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		DWORD dwLen				产生随机数的长度
//		BYTE pbBuffer			产生的随机数
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGenRandom(
	IN HCRYPTPROV hProv,  
	IN DWORD dwLen,       
	OUT BYTE *pbBuffer     
	);
 
//-------------------------------------------------------------------
//
//	Data Encryption Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	功能：
//		解密
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			解密密钥的句柄
//		HCRYPTHASH hHash		解密同时计算HASH
//		BOOL Final				最后一块
//		DWORD dwFlags			总是为0
//		BYTE* pbData			[IN]密文/[OUT]明文
//		DWORD* pdwDataLen		[IN]密文长度/[OUT]明文长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPDecrypt(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey,    
	IN HCRYPTHASH hHash,  
	IN BOOL Final,        
	IN DWORD dwFlags,     
	IN OUT BYTE *pbData,      
	IN OUT DWORD *pdwDataLen  
	);
 
//-------------------------------------------------------------------
//	功能：
//		加密
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			加密密钥的句柄
//		HCRYPTHASH hHash		加密同时计算HASH
//		BOOL Final				最后一块
//		DWORD dwFlags			总是为0
//		BYTE* pbData			[IN]明文/[OUT]密文
//		DWORD* pdwDataLen		[IN]明文长度/[OUT]密文长度
//		DWORD dwBufLen			pbData的空间大小
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPEncrypt(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey,    
	IN HCRYPTHASH hHash,  
	IN BOOL Final,        
	IN DWORD dwFlags,     
	IN OUT BYTE *pbData,      
	IN OUT DWORD *pdwDataLen, 
	IN DWORD dwBufLen     
	);

//-------------------------------------------------------------------
//	功能：
//		RSA原始解密
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			密钥对句柄
//		LPBYTE pbInData			输入数据
//		DWORD dwInDataLen		输入数据的长度
//		LPBYTE pbOutData		输出数据
//		LPDWORD pdwOutDataLen	输出数据的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPRSARawDecrypt(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey,    
	IN LPBYTE pbInData,
	IN DWORD dwInDataLen,
	OUT LPBYTE pbOutData,
	IN OUT LPDWORD pdwOutDataLen
	);

//-------------------------------------------------------------------
//	功能：
//		RSA原始加密
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTKEY hKey			密钥对句柄
//		LPBYTE pbInData			输入数据
//		DWORD dwInDataLen		输入数据的长度
//		LPBYTE pbOutData		输出数据
//		LPDWORD pdwOutDataLen	输出数据的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPRSARawEncrypt(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey,    
	IN LPBYTE pbInData,
	IN DWORD dwInDataLen,
	OUT LPBYTE pbOutData,
	IN OUT LPDWORD pdwOutDataLen
	);

//-------------------------------------------------------------------
//
//	Hashing and Digital Signature Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	功能：
//		创建HASH
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		ALG_ID AlgId			算法标识，可取以下值
//			CALG_MD5
//			CALG_SHA
//			CALG_SSL3_SHAMD5
//		HCRYPTKEY hKey			MAC中用到的密钥句柄
//		DWORD dwFlags			总是为0
//		HCRYPTHASH* phHash		创建的HASH句柄	
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPCreateHash(
	IN HCRYPTPROV hProv,  
	IN ALG_ID Algid,      
	IN HCRYPTKEY hKey,    
	IN DWORD dwFlags,     
	OUT HCRYPTHASH *phHash 
	);

//-------------------------------------------------------------------
//	功能：
//		复制HASH
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		待复制的HASH句柄
//		DWORD* pdwReserved		总为NULL
//		DWORD dwFlags			总为0
//		HCRYPTHASH* phHash		复制的HASH句柄	
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPDuplicateHash(
	IN HCRYPTPROV hProv,    
	IN HCRYPTHASH hHash,    
	IN DWORD *pdwReserved,  
	IN DWORD dwFlags,       
	OUT HCRYPTHASH* phHash    
	);

//-------------------------------------------------------------------
//	功能：
//		销毁HASH
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		HASH句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPDestroyHash(
	IN HCRYPTPROV hProv, 
	IN HCRYPTHASH hHash  
	);

//-------------------------------------------------------------------
//	功能：
//		获取HASH参数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		HASH句柄
//		DWORD dwParam			参数类型，支持以下取值,意义见MSDN描述
//			HP_ALGID 
//			HP_HASHSIZE 
//			HP_HASHVAL
//		BYTE* pbData			返回的数据
//		DWORD* pdwDataLen		返回数据的长度
//		DWORD dwFlags			总是为0			
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetHashParam(
	IN HCRYPTPROV hProv,  
	IN HCRYPTHASH hHash,  
	IN DWORD dwParam,     
	OUT BYTE *pbData,      
	IN OUT DWORD *pdwDataLen, 
	IN DWORD dwFlags      
	);

//-------------------------------------------------------------------
//	功能：
//		设置HASH参数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		HASH句柄
//		DWORD dwParam			参数类型，支持以下取值,意义见MSDN描述
//			HP_HASHVAL 
//		BYTE* pbData			设置的数据
//		DWORD dwFlags			总是为0			
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPSetHashParam(
	IN HCRYPTPROV hProv,  
	IN HCRYPTHASH hHash,  
	IN DWORD dwParam,     
	IN BYTE *pbData,      
	IN DWORD dwFlags      
	);

//-------------------------------------------------------------------
//	功能：
//		HASH数据
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		HASH句柄
//		CONST BYTE* pbData		数据
//		DWORD dwDataLen			数据长度
//		DWORD dwFlags			总是为0
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPHashData(
	IN HCRYPTPROV hProv,    
	IN HCRYPTHASH hHash,    
	IN CONST BYTE *pbData,  
	IN DWORD dwDataLen,     
	IN DWORD dwFlags        
	);

//-------------------------------------------------------------------
//	功能：
//		HASH密钥
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		HASH句柄
//		HCRYPTKEY hKey			密钥句柄
//		DWORD dwFlags			总是为0
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPHashSessionKey(
	IN HCRYPTPROV hProv,  
	IN HCRYPTHASH hHash,  
	IN HCRYPTKEY hKey,    
	IN DWORD dwFlags      
	);

//-------------------------------------------------------------------
//	功能：
//		签名HASH
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		HASH句柄
//		DWORD dwKeySpec			签名密钥对类型
//		LPCWSTR sDescription	签名描述
//		DWORD dwFlags			总是为0
//		BYTE* pbSignature		签名值
//		DWORD* pdwSigLen		签名值的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPSignHash(
	IN HCRYPTPROV hProv,      
	IN HCRYPTHASH hHash,      
	IN DWORD dwKeySpec,       
	IN LPCWSTR sDescription,  
	IN DWORD dwFlags,         
	OUT BYTE *pbSignature,     
	IN OUT DWORD *pdwSigLen       
	);

//-------------------------------------------------------------------
//	功能：
//		验证签名
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		HCRYPTHASH hHash		HASH句柄
//		CONST BYTE* pbSignature	签名值
//		DWORD dwSigLen			签名值的长度
//		HCRYPTKEY hPubKey		验证公钥的句柄
//		LPCWSTR sDescription	签名描述
//		DWORD dwFlags			总是为0
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPVerifySignature(
	IN HCRYPTPROV hProv,      
	IN HCRYPTHASH hHash,      
	IN CONST BYTE *pbSignature,  
	IN DWORD dwSigLen,        
	IN HCRYPTKEY hPubKey,     
	IN LPCWSTR sDescription,  
	IN DWORD dwFlags          
	);

//-------------------------------------------------------------------
//	功能：
//		可复原签名
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		DWORD dwKeySpec			签名密钥对类型
//		LPBYTE pbData			待签名数据
//		DWORD dwDataLen			待签名数据的长度
//		DWORD dwFlags			总是为0
//		LPBYTE pbSignature		签名值
//		LPDWORD pdwSigLen		签名值的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPSignRecover(
	IN HCRYPTPROV hProv,
	IN DWORD dwKeySpec, 
	IN LPBYTE pbData,
	IN DWORD dwDataLen,
	IN DWORD dwFlags,
	OUT LPBYTE pbSignature,     
	IN OUT LPDWORD pdwSigLen       
	);

//-------------------------------------------------------------------
//	功能：
//		验证还原
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		CONST LPBYTE pbSignature签名值
//		DWORD dwSigLen			签名值的长度
//		HCRYPTKEY hPubKey		验证公钥的句柄
//		DWORD dwFlags			总是为0
//		LPBYTE pbData			复原数据
//		LPDWORD pdwDataLen		复原数据的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPVerifyRecover(
	IN HCRYPTPROV hProv,
	IN CONST LPBYTE pbSignature,  
	IN DWORD dwSigLen,        
	IN HCRYPTKEY hPubKey,
	IN DWORD dwFlags,
	OUT LPBYTE pbData,
	IN OUT LPDWORD pdwDataLen
	);

//-------------------------------------------------------------------
//
//	PIN Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	功能：
//		校验PIN
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		int nUserType			用户类型
//		LPBYTE pPIN				PIN
//		DWORD dwPINLen			PIN的长度
//		DWORD& nRetryCount		错误后，可重试次数。若正确，则无意义。
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPLogin(
	IN HCRYPTPROV hProv,
	IN int nUserType,
	IN LPBYTE pPIN,
	IN DWORD dwPINLen,
	OUT DWORD& nRetryCount
	);

//-------------------------------------------------------------------
//	功能：
//		注销
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPLogout(
	IN HCRYPTPROV hProv
	);

//-------------------------------------------------------------------
//	功能：
//		更改当前登录用户的PIN
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		LPBYTE pOldPIN			旧PIN
//		DWORD dwOldPINLen		旧PIN的长度
//		LPBYTE pNewPIN			新PIN
//		DWORD dwNewPINLen		新PIN的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPChangePIN(
	IN HCRYPTPROV hProv,
	IN LPBYTE pOldPIN,
	IN DWORD dwOldPINLen,
	IN LPBYTE pNewPIN,
	IN DWORD dwNewPINLen
	);

//-------------------------------------------------------------------
//	功能：
//		解锁用户PIN
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv				容器句柄
//		LPBYTE pUserDefaultPIN			解锁后的缺省用户PIN
//		DWORD dwUserDefaultPINLen		解锁后的缺省用户PIN长度
//
//  说明：
//		必须已登录为管理员
//-------------------------------------------------------------------
BOOL WINAPI CPUnlockPIN(
	IN HCRYPTPROV hProv,
	IN LPBYTE pUserDefaultPIN,
	IN DWORD dwUserDefaultPINLen
	);

//-------------------------------------------------------------------
//	功能：
//		获取当前用户类型
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		int& nUserType			用户类型
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserType(
	IN HCRYPTPROV hProv,
	OUT int& nUserType
	);

//-------------------------------------------------------------------
//
//	UserFile Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	功能：
//		打开、新建或删除指定TOKEN中的一个用户文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV* phProv		文件句柄
//		CHAR* szFileName		文件名称
//		DWORD dwFileSize		文件大小(只对新建文件有意义)
//		DWORD dwFlags			标志
//		DWORD dwIndex			TOKEN索引
//
//  说明：
//		dwFlags的LOWORD为操作模式,HIWORD为创建文件时的权限设定
//-------------------------------------------------------------------
BOOL WINAPI CPAcquireUserFile(
	OUT HCRYPTPROV *phProv,
	IN CHAR* szFileName,
	IN DWORD dwFileSize,
	IN DWORD dwFlags,
	IN DWORD dwIndex
	);

//-------------------------------------------------------------------
//	功能：
//		打开、新建或删除指定TOKEN中的一个用户文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV* phProv		文件句柄
//		CHAR* szFileName		文件名称
//		DWORD dwFileSize		文件大小(只对新建文件有意义)
//		DWORD dwFlags			标志
//		CHAR* szReaderName		TOKEN名称
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPAcquireUserFile2(
	OUT HCRYPTPROV *phProv,
	IN CHAR* szFileName,
	IN DWORD dwFileSize,
	IN DWORD dwFlags,
	IN CHAR* szReaderName
	);

//-------------------------------------------------------------------
//	功能：
//		关闭打开的用户文件句柄
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		文件句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPReleaseUserFile(
	IN HCRYPTPROV hProv
	);

//-------------------------------------------------------------------
//	功能：
//		读取用户文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		文件句柄
//		DWORD dwReadLen			欲读取的长度
//		LPBYTE pbReadBuffer		读取的数据
//		LPDWORD pdwRealReadLen	实际读取的长度
//		DWORD dwOffset			读取偏移量
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPReadUserFile(
	IN HCRYPTPROV hProv,
	IN DWORD dwReadLen,
	OUT LPBYTE pbReadBuffer,
	OUT LPDWORD pdwRealReadLen,
	IN DWORD dwOffset
	);

//-------------------------------------------------------------------
//	功能：
//		更新用户文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		文件句柄
//		LPBYTE pbWriteBuffer	写入的数据
//		DWORD dwWriteLen		写入数据的长度
//		DWORD dwOffset			读取偏移量
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPWriteUserFile(
	IN HCRYPTPROV hProv,
	IN LPBYTE pbWriteBuffer,
	IN DWORD dwWriteLen,
	IN DWORD dwOffset
	);

//-------------------------------------------------------------------
//	功能：
//		获取用户文件的大小
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		文件句柄
//		LPDWORD pdwSize			文件大小
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserFileSize(
	IN HCRYPTPROV hProv,
	OUT LPDWORD pdwSize
	);

//-------------------------------------------------------------------
//	功能：
//		获取用户文件的名称
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		文件句柄
//		CHAR* szFileName		文件名称
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserFileName(
	IN HCRYPTPROV hProv,
	OUT CHAR* szFileName
	);

//-------------------------------------------------------------------
//	功能：
//		获取所有用户文件名的列表
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		TOKEN句柄
//		CHAR* szFileNameList	所有用户文件名字的列表,以0分隔,双0结束
//		LPDWORD pcchSize		[IN]接收区大小/[OUT]实际大小				
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserFileNameList(
	IN HCRYPTPROV hProv,
	OUT CHAR* szFileNameList,
	IN OUT LPDWORD pcchSize
	);

//-------------------------------------------------------------------
//
//	TokenInfo Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	功能：
//		获取TOKEN信息
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv			容器句柄
//		LPTOKENINFO pTokenInfo		TOKEN信息
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetTokenInfo(
	IN HCRYPTPROV hProv,
	OUT LPTOKENINFO pTokenInfo
	);

//-------------------------------------------------------------------
//	功能：
//		设置TOKEN信息
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv			容器句柄
//		LPTOKENINFO pTokenInfo		TOKEN信息
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPSetTokenInfo(
	IN HCRYPTPROV hProv,
	IN LPTOKENINFO pTokenInfo
	);


//-------------------------------------------------------------------
//	功能：
//		查询容量
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		HCRYPTPROV hProv			容器句柄
//		DWORD& dwTotalSize			总空间(含系统占用)
//		DWORD& dwTotalSize2			总空间(不含系统占用)
//		DWORD& dwUnusedSize			可用空间
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetE2Size(
	IN HCRYPTPROV hProv,
	OUT DWORD& dwTotalSize,
	OUT DWORD& dwTotalSize2,
	OUT DWORD& dwUnusedSize
	);

//-------------------------------------------------------------------
//	功能：
//		查询容量
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		DWORD dwIndex				索引
//		DWORD& dwTotalSize			总空间(含系统占用)
//		DWORD& dwTotalSize2			总空间(不含系统占用)
//		DWORD& dwUnusedSize			可用空间
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetE2Size2(
	IN DWORD dwIndex,
	OUT DWORD& dwTotalSize,
	OUT DWORD& dwTotalSize2,
	OUT DWORD& dwUnusedSize
	);

//-------------------------------------------------------------------
//	功能：
//		查询容量
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		CHAR* szReaderName			读卡器的名字
//		DWORD& dwTotalSize			总空间(含系统占用)
//		DWORD& dwTotalSize2			总空间(不含系统占用)
//		DWORD& dwUnusedSize			可用空间
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetE2Size3(
	IN CHAR* szReaderName,
	OUT DWORD& dwTotalSize,
	OUT DWORD& dwTotalSize2,
	OUT DWORD& dwUnusedSize
	);


BOOL WINAPI CPGetCosVer(
	CHAR* szReaderName,
	DWORD& dwVersion
	);
BOOL WINAPI CPIsSSF33Support(
	CHAR* szReaderName
	);


//-------------------------------------------------------------------
//	功能：
//		获取PIN的重试信息
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		HCRYPTPROV hProv			容器句柄
//		int nUserType				用户类型
//		int nMaxRetry				最大重试次数
//		int nLeftRetry				剩余重试次数
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetPinRetryInfo(
	IN HCRYPTPROV hProv,
	IN int nUserType,
	OUT int& nMaxRetry,
	OUT int& nLeftRetry
	);

//-------------------------------------------------------------------
//
//	Misc Functions
//
//-------------------------------------------------------------------

#ifndef USE_TYCSPI_STATIC_LIB

//-------------------------------------------------------------------
//	功能：
//		选择包含智能卡的读卡器
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		int& nReaderIndex		读卡器索引
//		CHAR* szReaderName		读卡器名称
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPSelectReader(
	OUT int& nReaderIndex,
	OUT CHAR* szReaderName
	);

#endif

//-------------------------------------------------------------------
//	功能：
//		格式化TOKEN
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv			容器句柄
//		LPFORMATINFO pFormatInfo	格式化信息
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPFormat(
	IN HCRYPTPROV hProv,
	IN LPFORMATINFO pFormatInfo
	);

//-------------------------------------------------------------------
//	功能：
//		格式化TOKEN
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		DWORD dwIndex				索引
//		LPFORMATINFO pFormatInfo	格式化信息
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPFormat2(
	IN DWORD dwIndex,
	IN LPFORMATINFO pFormatInfo
	);

//-------------------------------------------------------------------
//	功能：
//		格式化TOKEN
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		CHAR* szReaderName			读卡器的名字
//		LPFORMATINFO pFormatInfo	格式化信息
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPFormat3(
	IN CHAR* szReaderName,
	IN LPFORMATINFO pFormatInfo
	);

//-------------------------------------------------------------------
//	功能：
//		擦除EEPROM
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		DWORD dwIndex				索引
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPEraseEE(
	DWORD dwIndex
	);

//-------------------------------------------------------------------
//	功能：
//		擦除EEPROM
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		CHAR* szReaderName			读卡器的名字
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPEraseEE2(
	CHAR* szReaderName
	);

//-------------------------------------------------------------------
//	功能：
//		擦除EEPROM
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		CHAR* szReaderName			读卡器的名字
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPEraseEE3(
	IN CHAR* szReaderName
	);

//-------------------------------------------------------------------
//	功能：
//		向卡发送命令
//
//	返回：
//		TRUE:成功(SW1SW2 = 0x9000或0x61XX)	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv		容器句柄
//		BYTE* pbCommand			命令体
//		DWORD dwCommandLen		命令体的长度
//		BYTE* pbRespond			响应体
//		DWORD* pdwRespondLen	响应体的长度
//		WORD* pwStatus			状态字节
//
//  说明：
//		如果不需要响应体或状态字节,只需赋予NULL
//-------------------------------------------------------------------
BOOL WINAPI CPSendCommand(
	HCRYPTPROV hProv,
	BYTE* pbCommand, 
	DWORD dwCommandLen, 
	BYTE* pbRespond = NULL, 
	DWORD* pdwRespondLen = NULL, 
	WORD* pwStatus = NULL
	);

//-------------------------------------------------------------------
//	功能：
//		向卡发送命令
//
//	返回：
//		TRUE:成功(SW1SW2 = 0x9000或0x61XX)	FALSE:失败
//
//  参数：
//		DWORD dwIndex			索引
//		BYTE* pbCommand			命令体
//		DWORD dwCommandLen		命令体的长度
//		BYTE* pbRespond			响应体
//		DWORD* pdwRespondLen	响应体的长度
//		WORD* pwStatus			状态字节
//
//  说明：
//		如果不需要响应体或状态字节,只需赋予NULL
//-------------------------------------------------------------------
BOOL WINAPI CPSendCommand2(
	DWORD dwIndex,
	BYTE* pbCommand, 
	DWORD dwCommandLen, 
	BYTE* pbRespond = NULL, 
	DWORD* pdwRespondLen = NULL, 
	WORD* pwStatus = NULL
	);

//-------------------------------------------------------------------
//	功能：
//		向卡发送命令
//
//	返回：
//		TRUE:成功(SW1SW2 = 0x9000或0x61XX)	FALSE:失败
//
//  参数：
//		CHAR* szReaderName		读卡器的名字
//		BYTE* pbCommand			命令体
//		DWORD dwCommandLen		命令体的长度
//		BYTE* pbRespond			响应体
//		DWORD* pdwRespondLen	响应体的长度
//		WORD* pwStatus			状态字节
//
//  说明：
//		如果不需要响应体或状态字节,只需赋予NULL
//-------------------------------------------------------------------
BOOL WINAPI CPSendCommand3(
	CHAR* szReaderName,
	BYTE* pbCommand, 
	DWORD dwCommandLen, 
	BYTE* pbRespond = NULL, 
	DWORD* pdwRespondLen = NULL, 
	WORD* pwStatus = NULL
	);
//-------------------------------------------------------------------
//	功能：
//		连接Token
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		OUT HCRYPTPROV hProv	返回连接后的容器句柄
//		DWORD dwIndex			TOKEN的索引号(读卡器索引或列表索引)
//
//  说明：
//		如果TOKEN已格式化成了CSP文件系统，则返回VERIFYCONTEXT的容器句柄。
//	否则返回TOKEN的连接句柄。
//		可调用CPIsFormatted来断是否已格式化成了CSP的文件系统。
//-------------------------------------------------------------------
BOOL WINAPI CPConnect(
	OUT HCRYPTPROV *phProv,
	IN DWORD dwIndex
	);
//-------------------------------------------------------------------
//	功能：
//		连接卡片
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		CHAR* szReaderName		读卡器的名字
//
//  说明：
//	
//-------------------------------------------------------------------
BOOL WINAPI CPConnect1(
	CHAR* szReaderName
	);
//-------------------------------------------------------------------
//	功能：
//		连接Token
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		OUT HCRYPTPROV hProv	返回连接后的容器句柄
//		CHAR* szReaderName		TOKEN的名称
//
//  说明：
//		如果TOKEN已格式化成了CSP文件系统，则返回VERIFYCONTEXT的容器句柄。
//	否则返回TOKEN的连接句柄。
//		可调用CPIsFormatted来断是否已格式化成了CSP的文件系统。
//-------------------------------------------------------------------
BOOL WINAPI CPConnect2(
	OUT HCRYPTPROV *phProv,
	IN CHAR* szReaderName
	);
//-------------------------------------------------------------------
//	功能：
//		断开TOKEN的连接
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv	容器句柄
//		BOOL bWrite
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPFinalize(
	IN HCRYPTPROV hProv,
	IN BOOL bWrite = TRUE
	);

//-------------------------------------------------------------------
//	功能：
//		断开TOKEN的连接
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		DWORD dwIndex		索引
//		BOOL bWrite
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPFinalize2(
	IN DWORD dwIndex,
	IN BOOL bWrite = TRUE
	);

//-------------------------------------------------------------------
//	功能：
//		断开TOKEN的连接
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		CHAR* szReaderName	读卡器的名字
//		BOOL bWrite
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPFinalize3(
	IN CHAR* szReaderName,
	IN BOOL bWrite = TRUE
	);

//-------------------------------------------------------------------
//	功能：
//		设置读写器枚举标志位
//
//	返回：
//		无
//
//  参数：
//		DWORD dwFlag		枚举读卡器的种类
//		BOOL bFilter		是否过滤非天喻读卡器(针对PCSC)
//
//  说明：
//-------------------------------------------------------------------
void WINAPI CPSetReaderEnumFlag(
	IN DWORD dwFlag, 
	IN BOOL bFilter = TRUE
	);

//-------------------------------------------------------------------
//	功能：
//		查询CSP(Token)的数目
//
//	返回：
//		数目
//
//  参数：
//
//  说明：
//-------------------------------------------------------------------
DWORD WINAPI CPGetCSPCount();

//-------------------------------------------------------------------
//	功能：
//		获取CSP对应读卡器的名字
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		DWORD dwIndex		索引
//		CHAR* szReaderName	读卡器的名定
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPGetReaderName(
	IN DWORD dwIndex,
	OUT CHAR* szReaderName
	);



//-------------------------------------------------------------------
//
//	Helper(Wraper) Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	功能：
//		打开指定名字的密钥容器,如果没有则创建
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		DWORD dwCardIndex			卡索引(从0开始)
//		char* szName				密钥容器名称
//		HCRYPTPROV* phProv 			打开或创建的密钥容器句柄
//		BOOL bCreateIfNoneExist		如果不存在是否创建
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI
OpenKeyContainer(
	IN DWORD dwCardIndex,
	IN LPSTR szName, 
	OUT HCRYPTPROV* phProv, 
	IN BOOL bCreateIfNoneExist = TRUE
	);

//-------------------------------------------------------------------
//	功能：
//		以DER编码的形式导出指定密钥对的公钥
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv			密钥容器的句柄
//		HCRYPTKEY hKeyPair			密钥对(私钥)的句柄
//		LPBYTE lpPubKey				导出公钥的DER编码
//		LPDWORD lpPubKeyLen			输入的长度/输出的长度
//
//  说明：
//		公钥的ASN.1表示
//		RSAPublicKey ::= SEQUENCE{
//			modulus INTEGER, -- n
//			publicExponent INTEGER -- e 
//			}
//-------------------------------------------------------------------
BOOL WINAPI
ExportPublicKey(
	IN HCRYPTPROV hProv,
	IN HCRYPTKEY hKeyPair,
	OUT LPBYTE lpPubKey,
	IN OUT LPDWORD lpPubKeyLen
	);

//-------------------------------------------------------------------
//	功能：
//		以DER编码的形式导出指定密钥对的私钥
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv			密钥容器的句柄
//		HCRYPTKEY hKeyPair			密钥对(私钥)的句柄
//		LPBYTE lpPriKey				导出私钥的DER编码
//		LPDWORD lpPriKeyLen			输入的长度/输出的长度
//
//  说明：
//		密钥对必须是可被导出的
//		私钥的ASN.1表示
//			RSAPrivateKey ::= SEQUENCE {
//				version Version,
//				modulus INTEGER, -- n
//				publicExponent INTEGER, -- e
//				privateExponent INTEGER, -- d
//				prime1 INTEGER, -- p
//				prime2 INTEGER, -- q
//				exponent1 INTEGER, -- d mod (p-1)
//				exponent2 INTEGER, -- d mod (q-1)
//				coefficient INTEGER -- (inverse of q) mod p 
//				}
//
//			Version ::= INTEGER
//-------------------------------------------------------------------
BOOL WINAPI
ExportPrivateKey(
	IN HCRYPTPROV hProv,
	IN HCRYPTKEY hKeyPair,
	OUT LPBYTE lpPriKey,
	IN OUT LPDWORD lpPriKeyLen
	);

//-------------------------------------------------------------------
//	功能：
//		解公钥的DER编码并创建公钥对象
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv					导入的密钥容器句柄
//		ALG_ID algId						公钥类型
//		LPBYTE pbPublicKeyDERCode			公钥的DER编码
//		DWORD dwPublicKeyDERCodeLen			公钥DER编码的长度
//		HCRYPTKEY* phPublicKey				创建的公钥句柄
//
//  说明：
//		公钥的ASN.1表示
//		RSAPublicKey ::= SEQUENCE{
//			modulus INTEGER, -- n
//			publicExponent INTEGER -- e 
//			}
//-------------------------------------------------------------------
BOOL WINAPI
DecodeAndCreatePublicKey(
	IN HCRYPTPROV hProv,
	IN ALG_ID algId,
	IN LPBYTE pbPublicKeyDERCode,
	IN DWORD dwPublicKeyDERCodeLen,
	OUT HCRYPTKEY* phPublicKey
	);

//-------------------------------------------------------------------
//	功能：
//		解私钥的DER编码并创建私钥对象
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv					导入的密钥容器句柄
//		ALG_ID algId						私钥类型
//		LPBYTE pbPrivateKeyDERCode			私钥的DER编码
//		DWORD dwPrivateKeyDERCodeLen		私钥DER编码的长度
//		HCRYPTKEY* phPrivateKey				创建的私钥句柄
//
//  说明：
//		私钥的ASN.1表示
//			RSAPrivateKey ::= SEQUENCE {
//				version Version,
//				modulus INTEGER, -- n
//				publicExponent INTEGER, -- e
//				privateExponent INTEGER, -- d
//				prime1 INTEGER, -- p
//				prime2 INTEGER, -- q
//				exponent1 INTEGER, -- d mod (p-1)
//				exponent2 INTEGER, -- d mod (q-1)
//				coefficient INTEGER -- (inverse of q) mod p 
//				}
//
//			Version ::= INTEGER
//-------------------------------------------------------------------
BOOL WINAPI
DecodeAndCreatePrivateKey(
	IN HCRYPTPROV hProv,
	IN ALG_ID algId,
	IN LPBYTE pbPrivateKeyDERCode,
	IN DWORD dwPrivateKeyDERCodeLen,
	OUT HCRYPTKEY* phPrivateKey
	);


//-------------------------------------------------------------------
//	功能：
//		解私钥的DER编码并创建私钥对象
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv					导入的密钥容器句柄
//		ALG_ID algId						私钥类型
//		LPBYTE pbPrivateKeyDERCode			私钥的DER编码
//		DWORD dwPrivateKeyDERCodeLen		私钥DER编码的长度
//		BOOL bExportAble					是否可导出
//		HCRYPTKEY* phPrivateKey				创建的私钥句柄
//
//  说明：
//		私钥的ASN.1表示
//			RSAPrivateKey ::= SEQUENCE {
//				version Version,
//				modulus INTEGER, -- n
//				publicExponent INTEGER, -- e
//				privateExponent INTEGER, -- d
//				prime1 INTEGER, -- p
//				prime2 INTEGER, -- q
//				exponent1 INTEGER, -- d mod (p-1)
//				exponent2 INTEGER, -- d mod (q-1)
//				coefficient INTEGER -- (inverse of q) mod p 
//				}
//
//			Version ::= INTEGER
//-------------------------------------------------------------------
BOOL WINAPI
DecodeAndCreatePrivateKey2(
	IN HCRYPTPROV hProv,
	IN ALG_ID algId,
	IN LPBYTE pbPrivateKeyDERCode,
	IN DWORD dwPrivateKeyDERCodeLen,
	IN BOOL bExportAble,
	OUT HCRYPTKEY* phPrivateKey
	);

//-------------------------------------------------------------------
//	功能：
//		使用对称密钥对数据进行加/解密
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv			密钥容器句柄
//		ALG_ID algId				算法标识
//		LPBYTE pbKey				要做加/解密的密钥值
//		DWORD dwKeyLen				做加/解密的密钥长度
//		BOOL bEncrypt				加密(TRUE)/解密(FALSE)
//		LPBYTE pbInData				原始数据
//		DWORD dwInDataLen			原始数据长度
//		LPBYTE pbOutData			加解密后的数据
//		LPDWORD pdwOutDataLen		加解密后的数据长度
//		BOOL bPadding				是否填充数据
//
//  说明：
//		目前仅用ECB的模式
//-------------------------------------------------------------------
BOOL WINAPI
SymmCipher(
	IN HCRYPTPROV hProv,
	IN ALG_ID algId,
	IN LPBYTE pbKey,
	IN DWORD dwKeyLen,
	IN BOOL bEncrypt,
	IN LPBYTE pbInData,
	IN DWORD dwInDataLen,
	OUT LPBYTE pbOutData,
	OUT LPDWORD pdwOutDataLen,
	IN BOOL bPadding
	);

//-------------------------------------------------------------------
//	功能：
//		公钥加密
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		 HCRYPTPROV hProv			密钥容器句柄
//		 HCRYPTKEY hPubKey			公钥句柄
//		 LPBYTE pbInData			输入数据
//		 DWORD dwInDataLen			输入数据的长度
//		 LPBYTE pbOutData			输出数据
//		 LPDWORD pdwOutDataLen		输出数据的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI
PublicKeyEncrypt(
	IN HCRYPTPROV hProv,
	IN HCRYPTKEY hPubKey,
	IN LPBYTE pbInData,
	IN DWORD dwInDataLen,
	OUT LPBYTE pbOutData,
	OUT LPDWORD pdwOutDataLen
	);

//-------------------------------------------------------------------
//	功能：
//		私钥解密
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		 HCRYPTPROV hProv			密钥容器句柄
//		 HCRYPTKEY hPrivateKey		私钥句柄
//		 LPBYTE pbInData			输入数据
//		 DWORD dwInDataLen			输入数据的长度
//		 LPBYTE pbOutData			输出数据
//		 LPDWORD pdwOutDataLen		输出数据的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI
PrivateKeyDecrypt(
	IN HCRYPTPROV hProv,
	IN HCRYPTKEY hPrivateKey,
	IN LPBYTE pbInData,
	IN DWORD dwInDataLen,
	OUT LPBYTE pbOutData,
	OUT LPDWORD pdwOutDataLen
	);

//-------------------------------------------------------------------
//	功能：
//		设置字节顺序模式
//
//	返回：
//		无
//
//  参数：
//		ByteOrderMode nMode		字节顺序模式
//
//  说明：
//-------------------------------------------------------------------
void WINAPI 
CPSetByteOrderMode(
	IN ByteOrderMode nMode
	);

//-------------------------------------------------------------------
//	功能：
//		判断是否以读卡器索引作为查询读卡器的索引
//
//	返回：
//		TRUE:是		FALSE:不是
//
//  参数：
//		无
//
//  说明：
//		缺省为用读卡器列表索引
//-------------------------------------------------------------------
BOOL WINAPI CPIsUseReaderIndex();

//-------------------------------------------------------------------
//	功能：
//		设置是否以读卡器索引作为查询读卡器的索引
//
//	返回：
//		无
//
//  参数：
//		BOOL bFlag	标志
//
//  说明：
//		缺省为用读卡器列表索引
//-------------------------------------------------------------------
void WINAPI CPSetUseReaderIndex(
	BOOL bFlag
	);

//-------------------------------------------------------------------
//	功能：
//		检测智能卡是否存在
//
//	返回：
//		TRUE:存在	FALSE:不存在
//
//  参数：
//		HCRYPTPROV hProv	容器句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPCheckCardIsExist(
	HCRYPTPROV hProv
	);

//-------------------------------------------------------------------
//	功能：
//		检测智能卡是否存在
//
//	返回：
//		TRUE:存在	FALSE:不存在
//
//  参数：
//		DWORD dwIndex		索引
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPCheckCardIsExist2(
	DWORD dwIndex
	);
//-------------------------------------------------------------------
//	功能：
//		检测智能卡是否存在
//
//	返回：
//		TRUE:存在	FALSE:不存在
//
//  参数：
//		CHAR* szReaderName	读卡器的名定
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPCheckCardIsExist3(
	CHAR* szReaderName
	);

//-------------------------------------------------------------------
//	功能：
//		Base64编码
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		LPBYTE pbInData			输入数据
//		DWORD dwInDataLen		输入数据的长度
//		LPBYTE pbOutData		输出的Base64编码
//		LPDWORD pdwOutDataLen	Base64编码后的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI
CPBase64Encode(
	IN LPBYTE pbInData, 
	IN DWORD dwInDataLen, 
	OUT LPBYTE pbOutData,
	IN OUT LPDWORD pdwOutDataLen
	);

//-------------------------------------------------------------------
//	功能：
//		Base64解码
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		LPBYTE pbInData			Base64编码
//		DWORD dwInDataLen		Base64编码的长度
//		LPBYTE pbOutData		输出的数据
//		LPDWORD pdwOutDataLen	输出数据的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI
CPBase64Decode(
	IN LPBYTE pbInData, 
	IN DWORD dwInDataLen, 
	OUT LPBYTE pbOutData,
	IN OUT LPDWORD pdwOutDataLen
	);

//-------------------------------------------------------------------
//	功能：
//		计算HASH
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		IN ALG_ID algId			HASH算法标识
//		IN LPBYTE pbInData		数据
//		IN DWORD dwInDataLen	数据的长度 
//		OUT LPBYTE pbDigest		摘要
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI
CPSoftHash(
	IN ALG_ID algId,
	IN LPBYTE pbInData, 
	IN DWORD dwInDataLen, 
	OUT LPBYTE pbDigest
	);


//-------------------------------------------------------------------
//	功能：
//		复位卡片
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		BYTE* pbATR			ATR命令
//		DWORD* pdwATR		ATR的长度
//		ResetMode mode		复位模式
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI CPResetCard(
	CHAR* szReaderName,
	BYTE* pbATR,
	DWORD* pdwATR,
	ResetMode mode /*=WARM*/
);

#endif	// #ifndef __TY_CRYPTSPI_H__