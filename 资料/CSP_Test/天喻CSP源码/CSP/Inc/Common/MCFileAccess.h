//-------------------------------------------------------------------
//	本文件为 MemCard 的组成部分
//
//
//	版权所有 天喻信息产业有限公司 (c) 1996 - 2002 保留一切权利
//-------------------------------------------------------------------
//	用户接口:函数接口
//

#ifndef __MCARD_FILE_ACCESS_H__
#define __MCARD_FILE_ACCESS_H__

//数据类型定义
#include "MCTypeDef.h"

#define MCARD_API __stdcall

#ifdef __cplusplus
extern "C" {
#endif

//-------------------------------------------------------------------
//	功能：
//		与卡连接
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_TYPE cardType		卡片类型
//		IN LPVOID pParameter			连接参数
//		OUT MC_CARD_HANDLE* phCard		返回的卡片句柄
//
//  说明：
//		如果cardType为MC_CARDTYPE_DISKFILE，则pParameter可转换为一char类型的指针，
//	该字符串为磁盘文件的路径。
//		如果cardType为MC_CARDTYPE_PCSCCARD，则pParameter可转换为一DWORD类型的指针，
//	该DWORD表明了要连接的卡的索引号
//		如果cardType为MC_CARDTYPE_TYKEY，则pParameter可转换为一DWORD类型的指针，
//	该DWORD表明了要连接的卡的索引号
//		如果cardType为MC_CARDTYPE_CYPRESSSB，则pParameter可转换为一DWORD类型的指针，
//	该DWORD表明了要连接的卡的索引号
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardConnect(
	IN MC_CARD_TYPE cardType,
	IN LPVOID pParameter,
	OUT MC_CARD_HANDLE* phCard
	);

//-------------------------------------------------------------------
//	功能：
//		根据传入的卡片通讯句柄创建MemCard对象并返回对象的句柄
//
//	返回：
//		错误号
//
//  参数：
//		IN MC_CARD_TYPE cardType		卡片类型
//		IN HANDLE hCardComm				卡片通讯句柄
//		OUT MC_CARD_HANDLE* phCard		卡片句柄
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardAttachCard(
	IN MC_CARD_TYPE cardType,
	IN HANDLE hCardComm,
	OUT MC_CARD_HANDLE* phCard
	);

//-------------------------------------------------------------------
//	功能：
//		断开与卡片的连接
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardDisconnect(
	IN MC_CARD_HANDLE hCard
	);

//-------------------------------------------------------------------
//	功能：
//		判断卡片是否还存在
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardIsCardExist(
	IN MC_CARD_HANDLE hCard
	);

//-------------------------------------------------------------------
//	功能：
//		创建卡片的文件系统
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard					卡片句柄
//		IN MC_SYSTEM_CREATE_INFO* pCreateInfo	创建信息
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardCreateFileSystem(
	IN MC_CARD_HANDLE hCard,
	IN MC_SYSTEM_CREATE_INFO* pCreateInfo
	);

//-------------------------------------------------------------------
//	功能：
//		获取卡片系统信息
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		OUT DWORD& dwVersion			版本号
//		OUT DWORD& dwCardSize			卡片尺寸
//		OUT BYTE& Align					文件字节对齐数
//		OUT DWORD& dwFatItemCount		FAT表项的数目
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardGetSystemInfo(
	IN MC_CARD_HANDLE hCard,
	OUT DWORD& dwVersion,
	OUT DWORD& dwCardSize,
	OUT BYTE& Align,
	OUT DWORD& dwFatItemCount
	);

//-------------------------------------------------------------------
//	功能：
//		创建目录
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard					卡片句柄
//		IN MC_FILE_ID fileID					目录标识
//		IN MC_DIR_CREATE_INFO* pCreateInfo		建立目录的信息
//		IN DWORD dwFlags						标志位(保留)
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardMakeDir(
	IN MC_CARD_HANDLE hCard,
	IN MC_FILE_ID fileID,
	IN MC_DIR_CREATE_INFO* pCreateInfo,
	IN DWORD dwFlags
	);

//-------------------------------------------------------------------
//	功能：
//		删除目录
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_FILE_ID fileID			目录标识
//		IN DWORD dwFlags				标志位(保留)
//
//  说明：
//		目录必须为空
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardDeleteDir(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_ID fileID,
	IN DWORD dwFlags
	);

//-------------------------------------------------------------------
//	功能：
//		改变目录
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_FILE_ID* pPath			由文件标识组成的路径
//		IN DWORD dwCount				文件标识的数目
//		IN MC_CD_TYPE cdType			改变目录的方式
//
//  说明：
//		函数执行错误不会改变当前目录
//		如果pPath = NULL且cdType = MC_CD_FROM_ROOT,则回到根目录
//		如果路径标识为0xFFFF则表示回退到上一级目录
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardChangeDir(
	IN MC_CARD_HANDLE hCard,
	IN MC_FILE_ID* pPath,	
	IN DWORD dwCount,	
	IN MC_CD_TYPE cdType	
	);

//-------------------------------------------------------------------
//	功能：
//		列出当前目录下所有文件和子目录的属性
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN OUT MC_FILE_PROP* pFiles		文件属性
//		IN OUT DWORD& dwCount			文件的数目
//
//  说明：
//		一般要调用两次。第一次时pFiles = NULL,函数将在dwCount
//	中返回文件的数目；此时再分配空间然后进行第二次调用。
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardDirectory(
	IN MC_CARD_HANDLE hCard,
	IN OUT MC_FILE_PROP* pFiles,
	IN OUT DWORD& dwCount
	);

//-------------------------------------------------------------------
//	功能：
//		获取一个可用的文件标识符
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN DWORD dwFlags				标志位(保留)
//		OUT MC_FILE_ID* pFileId			返回的文件标识符
//		IN MC_FILE_ID startFileId		起始文件标识
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardGetWorkableFileId(
	IN MC_CARD_HANDLE hCard,
	IN DWORD dwFlags,
	OUT MC_FILE_ID* pFileId,
	IN MC_FILE_ID startFileId = MC_MIN_FILE_ID
	);

//-------------------------------------------------------------------
//	功能：
//		创建文件
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard				卡片句柄
//		IN MC_FILE_ID fileID				文件标识
//		IN MC_FILE_CREATE_INFO* pCreateInfo	建立文件的信息
//		IN DWORD dwFlags					标志位(保留)
//		OUT MC_FILE_HANDLE phFile			返回的文件句柄
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardCreateFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_ID fileID,
	IN MC_FILE_CREATE_INFO* pCreateInfo,
	IN DWORD dwFlags,
	OUT MC_FILE_HANDLE* phFile
	);

//-------------------------------------------------------------------
//	功能：
//		删除文件
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_FILE_ID fileID			文件标识
//		IN DWORD dwFlags				标志位(保留)
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardDeleteFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_ID fileID,
	IN DWORD dwFlags
	);

//-------------------------------------------------------------------
//	功能：
//		打开文件
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_FILE_ID fileID			文件标识
//		IN DWORD dwFlags				标志位(保留)
//		OUT MC_FILE_HANDLE* phFile		返回的文件句柄
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardOpenFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_ID fileID,
	IN DWORD dwFlags,
	OUT MC_FILE_HANDLE* phFile
	);

//-------------------------------------------------------------------
//	功能：
//		关闭文件
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_FILE_HANDLE hFile			文件句柄
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardCloseFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_HANDLE hFile
	);

//-------------------------------------------------------------------
//	功能：
//		获取文件的大小
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_FILE_HANDLE hFile			文件句柄
//		OUT LPDWORD pdwSize				返回的文件大小
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardGetFileSize(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_HANDLE hFile,
	OUT LPDWORD pdwSize
	);

//-------------------------------------------------------------------
//	功能：
//		读取文件的内容
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_FILE_HANDLE hFile			文件句柄
//		IN DWORD dwFlags				标志位(保留)
//		IN DWORD dwReadLen				读取的长度
//		IN LPBYTE pbReadBuffer			存放读取内容的空间
//		OUT LPDWORD pdwRealReadLen		实际读取的长度
//
//  说明：
//		读文件不会影响文件指针的位置
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardReadFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_HANDLE hFile,
	IN DWORD dwFlags,
	IN DWORD dwReadLen,
	IN LPBYTE pbReadBuffer,
	OUT LPDWORD pdwRealReadLen
	);

//-------------------------------------------------------------------
//	功能：
//		写入数据到文件中
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_FILE_HANDLE hFile			文件句柄
//		IN DWORD dwFlags				标志位(保留)
//		IN LPBYTE pbWriteBuffer			存放写入数据的空间
//		IN DWORD dwWriteLen				写入数据的长度
//
//  说明：
//		写文件不会影响文件指针的位置
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardWriteFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_HANDLE hFile,
	IN DWORD dwFlags,
	IN LPBYTE pbWriteBuffer,
	IN DWORD dwWriteLen
	);

//-------------------------------------------------------------------
//	功能：
//		移动文件指针
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_FILE_HANDLE hFile			文件句柄
//		IN MC_SEEK_TYPE seekType		移动方向
//		IN LONG offset					移动距离
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardSeekFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_HANDLE hFile,
	IN MC_SEEK_TYPE seekType,
	IN LONG offset
	); 

//-------------------------------------------------------------------
//	功能：
//		使文件无效
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_FILE_ID fileID			文件标识
//		IN DWORD dwFlags				标志位(保留)
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardInvalidateFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_ID fileID,
	IN DWORD dwFlags
	);

//-------------------------------------------------------------------
//	功能：
//		恢复文件的有效性
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_FILE_ID fileID			文件标识
//		IN DWORD dwFlags				标志位(保留)
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardRehabilitateFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_ID fileID,
	IN DWORD dwFlags
	);

//-------------------------------------------------------------------
//	功能：
//		增加或修改密钥
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_FILE_HANDLE hFile			文件句柄
//		IN MC_KEY_INFO* pKeyInfo		密钥信息
//		IN BOOL bInstall				增加(TRUE)或修改(FALSE)
//		IN DWORD dwFlags				标志位(保留)
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardWriteKey(
	IN MC_CARD_HANDLE hCard,			
	IN MC_KEY_INFO* pKeyInfo,
	IN BOOL bInstall,
	IN DWORD dwFlags
	);

//-------------------------------------------------------------------
//	功能：
//		获取随机数
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		OUT LPBYTE pbRandom				获取的随机数
//		IN DWORD dwRandomNum			随机数的数目
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardGetChallenge(
	IN MC_CARD_HANDLE hCard,			
	OUT LPBYTE pbRandom,
	IN DWORD dwRandomNum
	);

//-------------------------------------------------------------------
//	功能：
//		外部认证
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_KEY_ID keyId				密钥标识
//		IN LPBYTE pbEncryptedData		加密的数据(8字节)
//		OUT DWORD& dwRetryNum			以后可重试的次数
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardExternalAuthentication(
	IN MC_CARD_HANDLE hCard,			
	IN MC_KEY_ID keyId,
	IN LPBYTE pbEncryptedData,
	OUT DWORD& dwRetryNum
	);

//-------------------------------------------------------------------
//	功能：
//		校验个人密码
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_KEY_ID pinId				PIN标识
//		IN LPBYTE pbPin					个人密码(1-16字节)
//		IN DWORD dwPinLen				个人密码的长度
//		OUT DWORD& dwRetryNum			以后可重试的次数
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardVerifyPin(
	IN MC_CARD_HANDLE hCard,
	IN MC_KEY_ID pinId,
	IN LPBYTE pbPin,
	IN DWORD dwPinLen,
	OUT DWORD& dwRetryNum
	);

//-------------------------------------------------------------------
//	功能：
//		验证并更换个人密码
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//		IN MC_KEY_ID pinId				PIN标识
//		IN LPBYTE pbOldPin				个人旧密码(1-16字节)
//		IN DWORD dwOldPinLen			个人旧密码的长度
//		IN LPBYTE pbNewPin				个人新密码(1-16字节)
//		IN DWORD dwNewPinLen			个人新密码的长度
//		OUT DWORD& dwRetryNum			以后可重试的次数
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardVerifyAndChangePin(
	IN MC_CARD_HANDLE hCard,
	IN MC_KEY_ID pinId,
	IN LPBYTE pbOldPin,
	IN DWORD dwOldPinLen,
	IN LPBYTE pbNewPin,
	IN DWORD dwNewPinLen,
	OUT DWORD& dwRetryNum
	);

//-------------------------------------------------------------------
//	功能：
//		开始一个事务
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//
//  说明：
//		如果已有事务在运行那么调用该函数的线程将被阻塞直到其它事务结束
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardBeginTransaction(
	IN MC_CARD_HANDLE hCard
	);

//-------------------------------------------------------------------
//	功能：
//		结束一个事务
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_CARD_HANDLE hCard			卡片句柄
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardEndTransaction(
	IN MC_CARD_HANDLE hCard
	);

//-------------------------------------------------------------------
//	功能：
//		获取错误描述
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN MC_RV errCode					错误码
//		OUT TCHAR errMsg[MC_ERRMSG_MAX_LEN]	错误描述符
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardGetErrorMsg(
	IN MC_RV errCode,
	OUT char errMsg[MC_ERRMSG_MAX_LEN]
	);



/////////////////////////////////////////////////////////////////////
//
//	辅助函数

//	算法标识
#define ALG_HASH_MD5						1		//哈希值为16 Byte
#define ALG_HASH_SHA						2		//哈希值为20 Byte
#define ALG_SYMM_DES						3		//密钥长度为8 Byte，分块长度为8 Byte
#define ALG_SYMM_DES_EDE					4		//密钥长度为16 Byte，分块长度为8 Byte
#define ALG_SYMM_3DES						5		//密钥长度为24 Byte，分块长度为8 Byte

//	PKCS1 V1.5填充类型
#define PKCS_SIGNATURE_PADDING				1		//block	type 01		
#define PKCS_ENCRYPTION_PADDING				2		//block type 02

/*
	DigestInfo的ASN1表示

	DigestInfo ::= SEQUENCE{
 		digestAlgorithm DigestAlgorithmIdentifier, 
		digest Digest 
		} 
	DigestAlgorithmIdentifier ::= AlgorithmIdentifier 
	Digest ::= OCTET STRING

	将计算出的HASH值连接在下面定义的常量后面即构成了SHA或MD5的DigestInfo
	然后按PKCS1-V1.5规定进行block type 01填充再用RSA私钥进行解密运算得到签名

*/
const BYTE g_SHA_DigestInfo[] = {
	0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14
	};
const BYTE g_MD5_DigestInfo[] = {
	0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x04,0x10
	};

//-------------------------------------------------------------------
//	功能：
//		计算一组数据的哈希值
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN int nAlgId						HASH算法标识
//		IN LPBYTE pbData					待计算HASH的数据
//		IN DWORD dwDataLen					数据的长度
//		OUT unsigned char* pbHashValue		返回的HASH值
//
//  说明：
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardAuxHash(
	IN int nAlgId,
	IN LPBYTE pbData,
	IN DWORD dwDataLen,
	OUT LPBYTE pbHashValue
	);

//-------------------------------------------------------------------
//	功能：
//		对称加解密
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN int nAlgId				对称算法标识
//		IN BOOL bEncrypt			1为加密，0为解密
//		IN LPBYTE pbKey				密钥值
//		IN LPBYTE pbInData			输入数据
//		IN DWORD dwInDataLen		输入数据的长度
//		OUT LPBYTE pbOutData		输出数据
//		OUT LPDWORD pdwOutDataLen	输出数据的长度
//		IN BOOL bPadding			1填充，0不填充
//
//  说明：
//		目前只支持ECB模式
//		如果bPadding为 1 则自动填充(加密)或去掉填充(解密)
//		当bEncrypt为 1 (加密)时，如果bPadding为 1 则输入数据的长度可
//	为任意值，输出数据的长度不会超过输入数据的长度加块长；如果bPadding
//	为 0 则输入数据的长度必须为块长的整数倍，输出数据的长度与输入数据
//	的长度相同	
//		当bEncrypt为 0 (解密)时，输入数据的长度必须为块长的整数倍；输
//	出数据的长度当bPadding为 0 时与输入数据的长度相同，当bPadding为 1
//	时不会超过输入数据的长度
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardAuxSymmCipher(
	IN int nAlgId,
	IN BOOL bEncrypt,
	IN LPBYTE pbKey,
	IN LPBYTE pbInData,
	IN DWORD dwInDataLen,
	OUT LPBYTE pbOutData,
	OUT LPDWORD pdwOutDataLen,
	IN BOOL bPadding
	);

//-------------------------------------------------------------------
//	功能：
//		为RSA加/解密或签名/验证按PKCS1-V1.5进行数据填充
//
//	返回：
//		MC_S_SUCCESS: 成功            其它:失败
//
//  参数：
//		IN int nPaddingType			填充类型
//		IN BOOL bPadding			1为填充，0为去掉填充
//		IN DWORD dwBitsLen			RSA密钥对的模长(Bits)			
//		IN LPBYTE pbInData			输入数据
//		IN DWORD dwInDataLen		输入数据的长度
//		OUT LPBYTE pbOutData		输出数据
//		OUT LPDWORD pdwOutDataLen	输出数据的长度
//
//  说明
//		不论何种填充类型，如果bPadding为1则输入数据的长度应小于 
//	dwBitsLen/8 - 11；输出数据的长度为 dwBitsLen / 8
//		
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardAuxPKCSPadding(
	IN int nPaddingType,
	IN BOOL bPadding,
	IN DWORD dwBitsLen,
	IN LPBYTE pbInData,
	IN DWORD dwInDataLen,
	OUT LPBYTE pbOutData,
	OUT LPDWORD pdwOutDataLen
	);

#ifdef __cplusplus
}       // Balance extern "C" above
#endif

#endif