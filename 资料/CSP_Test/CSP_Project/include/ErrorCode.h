/*
	最后修改人:严飞
	修改时间:2004-7-7
	添加部分：打印控制
*/

/*
文件: JetErr.h
说明: 统一错误代码定义

 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 +---+-+-+-----------------------+-------------------------------+
 |Sev|C|R|     Facility          |               Code            |
 +---+-+-+-----------------------+-------------------------------+
 Sev 2 Bit
	Indicates the severity. This is one of the following values: 
	00 - Success
	01 - Informational
	10 - Warning
	11 - Error, 这里使用 11

 C 1 bit
	Indicates a customer code (1) or a system code (0). 
	自定义使用 1
 R 1 bit
	Reserved bit.
	这里使用 0
 Facility 12 bit
	Facility code. This can be FACILITY_NULL or one of the following values:
	这里作模块划分如下
	FACILITY_NULL	000000000000 ->	暂时保留
	FACILITY_USBKEY	000000000001 ->	USB Key设备操作模块
	FACILITY_COMM	000000000010 ->	网络通讯模块
	FACILITY_DB		000000000011 ->	数据库操作模块
	FACILITY_GINA	000000000100 ->	GINA模块
	FACILITY_CRYPT	000000000101 ->	加解密模块
	FACILITY_USERAUTH	000000000110 ->	身份认证模块

 Code 16 bit
	Status code for the facility.
	这里作各个模块的错误代码

自定义错误代码宏名称规范

	宏名称结构 --> 头 + "_" + 模块简称 + 错误描述

	说明:
	1.	错误代码宏必须以 " ERR_ " 开头

	2.	后面紧跟各模块简称
			模块简称参见 "模块划分" 部分的定义

	3.	最后为错误简要描述
		要求: 能简要描述错误信息
		例如: 数据库模块->连接错误
		宏名称: ERR_DB_CONNECT 或 ERR_DB_OPEN 等等

	4.	错误描述还可细分, 也可部分
		格式: 子模块 + "_" + 错误描述
		例如: EKEY模块->设备操作子模块->设备没找到
		宏名称: ERR_EKEY_DEV_NONE


*/

#ifndef _KEY_ERROR_DEFINE_H_
#define _KEY_ERROR_DEFINE_H_


//////////////////////////////////////////////////////////////////////////
//
//	常用工具
//
//////////////////////////////////////////////////////////////////////////

#if (defined _DEBUG) || (defined OUTPUT_TEXT)

#define OutputTextW(lpText)			\
	{									\
		OutputDebugStringW(L"\n\t");	\
		OutputDebugStringW(lpText);		\
		OutputDebugStringW(L"\n");		\
	}

#define OutputTextA(lpText)			\
	{									\
		OutputDebugStringW(L"\n\t");	\
		OutputDebugStringA(lpText);		\
		OutputDebugStringW(L"\n");		\
	}

#else

#define OutputTextW(lpText)
#define OutputTextA(lpText)

#endif

#if (defined UNICODE) || (defined _UNICODE)
#define OutputText OutputTextW
#else
#define OutputText OutputTextA
#endif

/* 正确返回值 */
#define ERR_OK	((unsigned long)0)

/* 基数 */
#define ERR_BASE	((unsigned long)0xE0000000)

/*//////////////////////////////////////////////////////////////////////////

	模块划分

//////////////////////////////////////////////////////////////////////////*/

//	公用错误信息
#define FACILITY_PUBLIC		((DWORD)0x00010000)

//	网络通讯模块
#define FACILITY_COMM		((DWORD)0x00020000)
//	数据库操作模块
#define FACILITY_DB			((DWORD)0x00030000)
//	GINA模块
#define FACILITY_GINA		((DWORD)0x00040000)
//	加解密模块
#define FACILITY_CRYPTO		((DWORD)0x00050000)
//	身份认证模块
#define FACILITY_USERAUTH	((DWORD)0x00060000)
//	资源获取
#define FACILITY_RESOURCE	((DWORD)0x00070000)
//	设备控制
#define FACILITY_DEVLOCK	((DWORD)0x00080000)

//智能卡模块
#define FACILITY_PCSC		((DWORD)0x000A0000)
//	明华Usb eKey 以及 IC 卡设备操作模块
#define FACILITY_MWUSBD		((DWORD)0x00070000)
#define FACILITY_MWXCAPI	((DWORD)0x00080000)
#define FACILITY_MWIC32		((DWORD)0x00090000)



//////////////////////////////////////////////////////////////////////////
//
//	错误代码详细定义
//
//////////////////////////////////////////////////////////////////////////

#define ERR_COMM_BASE		((DWORD)(ERR_BASE | FACILITY_COMM + 0))
//无法获取代理, 即表示无法连接服务器
#define ERR_COMM_CANNOT_GET_PROXY	(ERR_COMM_BASE + 1);

//////////////////////////////////////////////////////////////////////////
//
//	共有错误代码
//
//////////////////////////////////////////////////////////////////////////

/* 参数错误代码基数 */
#define ERR_PUBLIC_BASE				((DWORD)(ERR_BASE | FACILITY_PUBLIC + 0))
/* 参数错误 */
#define ERR_PUBLIC_PARAM			((DWORD)(ERR_PUBLIC_BASE + 0))
/* 没有足够的缓冲区 */
#define ERR_PUBLIC_BUF_NOTENOUGH	((DWORD)(ERR_PUBLIC_BASE + 1))
/* 没有足够的内存 */
#define ERR_PUBLIC_MEM_NOTENOUGH	((DWORD)(ERR_PUBLIC_BASE + 2))
/* 加载动态库失败 */
#define ERR_PUBLIC_LOAD_DLL			((DWORD)(ERR_PUBLIC_BASE + 3))
/* 无法识别的主键 */
#define ERR_PUBLIC_REG_UNKNOWHKEY	((DWORD)(ERR_PUBLIC_BASE + 4))
/* 未知错误 */
#define ERR_PUBLIC_UNKNOW			((DWORD)(ERR_PUBLIC_BASE + 5))
/* 动态库调用失败 */
#define ERR_PUBLIC_DLLERROR			((DWORD)(ERR_PUBLIC_BASE + 6))
/* 没有想要的数据 */
#define ERR_PUBLIC_NODATA			((DWORD)(ERR_PUBLIC_BASE + 7))
/* 文件正在使用 */
#define ERR_PUBLIC_FILEISUSEDING	((DWORD)(ERR_PUBLIC_BASE + 8))
/* 不提供相应的支持 */
#define ERR_PUBLIC_UNPROVIDE		((DWORD)(ERR_PUBLIC_BASE + 9))
//////////////////////////////////////////////////////////////////////////
//
//	通讯模块错误代码
//
//////////////////////////////////////////////////////////////////////////



//////////////////////////////////////////////////////////////////////////
//
//	数据库模块错误代码
//
//////////////////////////////////////////////////////////////////////////
// 数据库相关错误代码基数
#define ERR_DB_BASE				((unsigned long)(ERR_BASE | FACILITY_DB))
#define ERR_DB_CONNECT_FAIL		((unsigned long)(ERR_DB_BASE + 0))
#define ERR_DB_QUERY_FAIL		((unsigned long)(ERR_DB_BASE + 1))
#define ERR_DB_RESULT_FAIL      ((unsigned long)(ERR_DB_BASE + 2))
#define ERR_DB_NOT_CONNECT		((unsigned long)(ERR_DB_BASE + 3))
#define ERR_DB_NO_RECORD		((unsigned long)(ERR_DB_BASE + 4))

//////////////////////////////////////////////////////////////////////////
//
//	智能卡模块错误代码
//
//////////////////////////////////////////////////////////////////////////
#define ERR_MWUSBD_BASE			((unsigned long)(ERR_BASE | FACILITY_MWUSBD))
#define ERR_MWUSBD_NODEVICE		((unsigned long)(ERR_MWUSBD_BASE + 1))

#define ERR_PCSC_BASE					(ERR_BASE | FACILITY_PCSC)
#define ERR_PCSC_NO_DEVICE				(ERR_PCSC_BASE + 1)	//没有设备
#define ERR_PCSC_INVALID_DEVICE			(ERR_PCSC_BASE + 2)	//设备不合法
#define ERR_PCSC_VERIFY_PIN				(ERR_PCSC_BASE + 3)	//校验PIN错误
#define ERR_PCSC_MODIFY_PIN				(ERR_PCSC_BASE + 4)	//修改PIN错误
#define ERR_PCSC_MULTI_DEVICE			(ERR_PCSC_BASE + 5)	//多个设备

//////////////////////////////////////////////////////////////////////////
//
//	身份认证
//
//////////////////////////////////////////////////////////////////////////
#define ERR_USERAUTH_BASE			((DWORD)(ERR_BASE | FACILITY_USERAUTH))
#define ERR_USERAUTH_NORIGHT		(ERR_USERAUTH_BASE + 0)



//////////////////////////////////////////////////////////////////////////
//
//	资源获取
//
//////////////////////////////////////////////////////////////////////////
#define ERR_RESOURCE_BASE			((unsigned long)(ERR_BASE | FACILITY_RESOURCE))
// 获取资源失败
#define ERR_RES_GET_FAIL			((unsigned long)(ERR_RESOURCE_BASE + 1))
// 获取Device Setup Class失败
#define ERR_RES_GET_DEV_SETUP		((unsigned long)(ERR_RESOURCE_BASE + 2))
// 获取Device Interface Class失败
#define ERR_RES_GET_DEV_INTERFACE	((unsigned long)(ERR_RESOURCE_BASE + 3))

//////////////////////////////////////////////////////////////////////////
//
//	加解密模块
//
//////////////////////////////////////////////////////////////////////////

#define ERR_CRYPTO_BASE					(ERR_BASE | FACILITY_CRYPTO)

#define ERR_CRYPTO_OPEN_FILE			(ERR_CRYPTO_BASE + 1)
#define ERR_CRYPTO_ALREADY_ENCRYPT		(ERR_CRYPTO_BASE + 2)
#define ERR_CRYPTO_LOAD_DLL				(ERR_CRYPTO_BASE + 3)
#define ERR_CRYPTO_DISABLE_DECRYPT		(ERR_CRYPTO_BASE + 4)
#define ERR_CRYPTO_FILE_SMALL			(ERR_CRYPTO_BASE + 5)
#define ERR_CRYPTO_ACT_CANNCEL			(ERR_CRYPTO_BASE + 6)
#define ERR_CRYPTO_WRITE_FILE			(ERR_CRYPTO_BASE + 7)

//////////////////////////////////////////////////////////////////////////
//
//	设备控制
//
//////////////////////////////////////////////////////////////////////////

#define ERR_DEVLOCK_BASE			(ERR_BASE | FACILITY_DEVLOCK)

#define ERR_DEVLOCK_OPENSCMGR		(ERR_DEVLOCK_BASE + 1)
#define ERR_DEVLOCK_QUERYSC			(ERR_DEVLOCK_BASE + 2)
#define ERR_DEVLOCK_STOPSC			(ERR_DEVLOCK_BASE + 3)
#define ERR_DEVLOCK_STARTSC			(ERR_DEVLOCK_BASE + 4)
#define ERR_DEVLOCK_CONTROL			(ERR_DEVLOCK_BASE + 5)

#endif
