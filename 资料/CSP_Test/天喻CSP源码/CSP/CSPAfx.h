//-------------------------------------------------------------------
//	本文件为 TY Cryptographic Service Provider 的组成部分
//
//
//	版权所有 天喻信息产业有限公司 (c) 1996 - 2002 保留一切权利
//-------------------------------------------------------------------
#ifndef __TYCSP_PRECOMPILE_H__
#define __TYCSP_PRECOMPILE_H__

#include "assert.h"
#ifndef ASSERT
#define ASSERT assert
#endif

#include "ArrayTmpl.h"

#define _WIN32_WINNT	0x0400
#include "wincrypt.h"
#include "Winscard.h"
#pragma comment(lib, "winscard.lib")
#include "afxtempl.h"
#include "LMCONS.H"


#include "Cryptlib.h"
USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)
#ifdef _DEBUG
#pragma comment(lib, "cryptlibd.lib")
#else
#pragma comment(lib, "cryptlib.lib")
#endif

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
#define  CSP_FILE_SYS_VERSION		0x0011
#define  DF_CSP_IN_MF				0x0001


#include "CSPObject.h"
#include "HelperFunc.h"
#include "GlobalVars.h"



//调试信息
#ifdef _DEBUG
#define _TRACE_INFO
#endif
#include "Inc\trace\DbgFile.h"
#define SETLASTERROR(err) \
{ \
	SetLastError(err); \
	TRACE_ERROR(err); \
} \


//
// MessageId: NTE_SILENT_CONTEXT
//
// MessageText:
//
//  A silent context was acquired.
//
#define NTE_SILENT_CONTEXT                  _HRESULT_TYPEDEF_(0x80090022L)

#endif