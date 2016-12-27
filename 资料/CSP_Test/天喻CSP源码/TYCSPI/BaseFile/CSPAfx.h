#ifndef __TYCSP_PRECOMPILE_H__
#define __TYCSP_PRECOMPILE_H__

#include "assert.h"
#ifndef ASSERT
#define ASSERT assert
#endif

#include "ArrayTmpl.h"

//软件加密
#include "Cryptlib.h"
USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)
#ifdef _DEBUG
#ifdef _AFXDLL
#pragma message("link cryptlibtd.lib")
#pragma comment(lib, "cryptlibtd.lib")
#else
#pragma message("link cryptlibd.lib")
#pragma comment(lib, "cryptlibd.lib")
#endif
#else
#ifdef _AFXDLL
#pragma message("link cryptlibt.lib")
#pragma comment(lib, "cryptlibt.lib")
#else
#pragma message("link cryptlib.lib")
#pragma comment(lib, "cryptlib.lib")
#endif
#endif

//Win32函数
#define _WIN32_WINNT	0x0400
#include "wincrypt.h"
#include "Winscard.h"
#pragma comment(lib, "WinScard.lib")
#include "lmcons.h"

//////////////////////////////////////////////////////////////////////////////////
//CSP文件系统版本管理 chenji 2005-12-22

//1.CSP应用不再建在2F01目录底下, 而直接建在MF目录底下
//
//2.在MF下建立一个标记文件,记录KEY文件结构系统版本号,四个字节,不存在这个文件的KEY均作为老KEY进行读写操作.
//
//	版本号由八个字节组成,前两个字节是文件系统的版本号,后六个字节按位有意义,共48位,可以表示48种文件系统特性
//	本版本可能要用去其中的两个,其余的在以后进行扩展

typedef struct 
{
	WORD wFileSysVer;  //文件系统版本号
	WORD wDF_flag;		//DF属性标记,共16位可能标记
	DWORD dwEF_flag;	//EF属性标记, 共32位可能标记
}CSP_FILESYS_VER, *LPCSP_FILESYS_VER;

//使用文件时文件属性位标记, 这里用了四个位
#define EF_WRITE_PROTECTED			0x00000002	//写线路保护
#define EF_ENC_WRITE_PROTECTED		0x00000001	//写加密线路保护
#define EF_READ_PROTECTED			0x00000008	//读线路保护
#define EF_ENC_READ_PROTECTED		0x00000004	//读加密线路保护

//这个版本的CSP文件版本号
#define  CSP_FILE_SYS_VERSION		0x0003
#define  DF_CSP_IN_MF				0x0001

//为_tagPathTable添加了一个成员fileSysVerPath,
//为g_cPathTable指定fileSysVerPath为{0x50,0x29}

//生成文件时文件类型设置用的位标记, 可用dwEF_flag的低字节左移三位获得
#define WRITE_PROTECTED			0x10	//写线路保护
#define ENC_WRITE_PROTECTED		0x08	//写加密线路保护
#define READ_PROTECTED			0x40	//读线路保护
#define ENC_READ_PROTECTED		0x20	//读加密线路保护
//这个位是表示MF被保护,只有管理员PIN码校验才能擦除MF
#define  FILE_SYS_MF_PROTECTED		0x0001

//////////////////////////////////////////////////////////////////////////////////
//卡片信息
typedef struct TOKENINFO{
	CHAR manufacturerID[32];		//制造商的名称
	CHAR label[32];					//Token的名字
	CHAR model[16];					//Token的模式
	CHAR serialNumber[16];			//Token的序列号
	BYTE pinMaxRetry;				//管理员和用户PIN的最大重试次数
}TOKENINFO, *LPTOKENINFO;

//格式化信息
typedef struct FORMATINFO{
	TOKENINFO tokenInfo;			//卡片信息
	LPBYTE userPIN;					//用户初始PIN
	DWORD userPINLen;				//用户初始PIN的长度,如果为0,则初始PIN为"1234"
	BYTE userPINMaxRetry;			//用户PIN重试次数			
	LPBYTE soPIN;					//管理员初始PIN
	DWORD soPINLen;					//管理员初始PIN的长度,如果为0,则初始PIN为"1234"
	BYTE soPINMaxRetry;				//管理员PIN重试次数			
}FORMATINFO, *LPFORMATINFO;

//用户文件的操作模式(CPAcquireUserFile中的dwFlags)
#define USERFILE_NEW				0x0000
#define USERFILE_OPEN				0x0001
#define USERFILE_DELETE				0x0002

//新建文件时,读写权限标记
#define USERFILE_AUTH_READ			0x0001
#define USERFILE_AUTH_WRITE			0x0002

//枚举读写器标志
#define ENUM_PCSC_READER			0x00000001
#define ENUM_USBPORT_READER			0x00000002
#define ENUM_SERIALPORT_READER		0x00000004

//用户类型
#define UT_PUBLIC					0				//未登录
#define UT_USER						1				//用户
#define UT_SO						2				//管理员

//文件被删除的标记
#define DESTROIED_TAG				0xff

//RSA密钥对的最大模长
#define MAX_RSAKEYPAIR_MODULUS_LEN	1024
//公钥Blob的最大长度
#define MAX_RSAPUBKEY_BLOB_LEN		(sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + MAX_RSAKEYPAIR_MODULUS_LEN /8)
//私钥Blob的最大长度
#define MAX_RSAPRIKEY_BLOB_LEN		(sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + (MAX_RSAKEYPAIR_MODULUS_LEN /16)*9) 

#include "CSPObject.h"
#include "GlobalVars.h"

//调试信息
#ifdef _DEBUG
#define _TRACE_INFO
#endif
#include "..\Inc\trace\DbgFile.h"
#define SETLASTERROR(err) \
{ \
	SetLastError(err); \
	TRACE_ERROR(err); \
} \


#endif