//-------------------------------------------------------------------
//	本文件为 MemCard 的组成部分
//
//
//	版权所有 天喻信息产业有限公司 (c) 1996 - 2002 保留一切权利
//-------------------------------------------------------------------
//	用户接口:数据类型定义
//

#ifndef __MCARD_TYPE_DEFINE_H__
#define __MCARD_TYPE_DEFINE_H__

#pragma pack(push, memcard, 1)

#define IN
#define OUT

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef long LONG;
typedef int BOOL;
typedef BYTE* LPBYTE;
typedef WORD* LPWORD;
typedef DWORD* LPDWORD;
typedef void* LPVOID;

typedef LPVOID HANDLE;
typedef DWORD MC_CARD_HANDLE;
typedef HANDLE MC_FILE_HANDLE;

typedef WORD MC_FILE_ID;
#define MC_MIN_FILE_ID					0x0001	//最小文件标识
#define MC_MAX_FILE_ID					0xFFFE	//最大文件标识

#define MC_MIN_FILE_SIZE				0x0001	//最小文件尺寸
#define MC_MAX_FILE_SIZE				0xFFFF	//最大文件尺寸

typedef DWORD MC_CARD_TYPE;
#define MC_CARDTYPE_DISKFILE			0		//磁盘文件
#define MC_CARDTYPE_PCSCCARD			1		//读写器符合PCSC的存储卡
#define MC_CARDTYPE_TYKEY				2		//读写器为TYKEY的存储卡
#define MC_CARDTYPE_CYPRESSSB			3		//读写器为Cypress的SB卡

typedef BYTE MC_FILE_TYPE;
#define MC_BINARY_FILE					0x00	//二进制文件
#define MC_KEY_FILE						0x05	//密钥文件

typedef DWORD MC_SEEK_TYPE;
#define MC_SEEK_FROM_BEGINNING			0		//从文件头开始查找
#define MC_SEEK_FROM_END				1		//从文件尾开始查找	
#define MC_SEEK_RELATIVE				2		//从文件当前位置开始查找	

typedef DWORD MC_CD_TYPE;
#define MC_CD_FROM_ROOT					0		//从根目录开始更换目录
#define MC_CD_RELATIVE					1		//从当前目录开始更换目录

typedef struct MC_SYSTEM_CREATE_INFO{
	WORD wSize;									//卡片尺寸(单位为KByte)
	BYTE nAlign;								//文件字节对齐数(00表示256)
	WORD wFatItemCount;							//FAT表项数
	BYTE authCreate;							//建立文件的权限
	BYTE authDelete;							//删除文件系统的权限
	WORD reserved;								//保留
}MC_SYSTEM_CREATE_INFO;

typedef struct MC_FILE_CREATE_INFO{
	MC_FILE_TYPE type;							//文件类型
	DWORD dwSize;								//文件大小
	BYTE authRead;								//读权限
	BYTE authWrite;								//写权限
}MC_FILE_CREATE_INFO;

typedef struct MC_DIR_CREATE_INFO{
	BYTE authCreate;							//建立文件的权限
	BYTE authDelete;							//删除文件的权限
}MC_DIR_CREATE_INFO;

typedef struct MC_FILE_PROP{
	MC_FILE_ID fileId;							//文件标识
	BYTE isDir;									//是目录(1)还是文件(0)
	union{
		MC_FILE_CREATE_INFO	file;				//对应于文件的信息
		MC_DIR_CREATE_INFO dir;					//对应于目录的信息
	}prop;
}MC_FILE_PROP;

typedef BYTE MC_KEY_ID;
#define MC_MIN_KEY_ID					0x01	//最小密钥标识
#define MC_MAX_KEY_ID					0xFE	//最大密钥标识

typedef BYTE MC_ALG_ID;
#define MC_ALG_TRIPLEDES				0		//3-DES
#define MC_ALG_SINGLEDES				1		//DES
#define MC_ALG_PIN						0xFF	//PIN

typedef BYTE MC_KEY_TYPE;
#define MC_EXTERNALAUTH_KEY				0x08	//外部认证密钥
#define MC_INTERNALAUTH_KEY				0x09	//内部认证密钥		
#define MC_PIN_KEY						0x0B	//个人密码

typedef struct MC_KEY_INFO{
	MC_KEY_ID	id;								//密钥标识
	BYTE		version;						//版本号
	MC_ALG_ID	algid;							//算法标识
	MC_KEY_TYPE	type;							//密钥类型
	BYTE		useauth;						//使用权限
	BYTE		aftersec;						//后续状态
	BYTE		modifyauth;						//修改权限
	BYTE		errorcount;						//错误计数
	BYTE		key[16];						//密钥
	BYTE		keylen;							//密钥长度
}MC_KEY_INFO;

#define MC_ERRMSG_MAX_LEN				256		//错误描述符的最大长度
typedef DWORD MC_RV;
#define MC_S_SUCCESS					0		//操作成功
#define MC_E_FAIL						1		//操作失败(系统内部错误)
#define MC_E_DEVICE_ABSENT				2		//卡片不存在
#define MC_E_DEVICE_READ_ERROR			3		//卡片读错误
#define MC_E_DEVICE_WRITE_ERROR			4		//卡片写错误
#define MC_E_INVALID_PARAMETER			5		//参数错误
#define MC_E_INVALID_CARD_HANDLE		6		//卡片句柄非法
#define MC_E_INVALID_FILE_HANDLE		7		//文件句柄非法
#define MC_E_NO_FILE_SYSTEM				8		//卡片系统数据未创建或已损坏
#define MC_E_NO_HOST_MEMORY				9		//上位机内存不足
#define MC_E_NO_DEVICE_MEMORY			10		//卡片空间不够
#define MC_E_NO_DEVICE_CONTEXT			11		//没有设备环境
#define MC_E_FILE_ID_BAD				12		//文件标识超出范围
#define MC_E_FILE_SIZE_BAD				13		//文件尺寸超出范围	
#define MC_E_FILE_ALREADY_EXIST			14		//文件已存在
#define MC_E_FILE_NOT_FOUND				15		//文件不存在
#define MC_E_FILE_OPEN_DENY				16		//禁止打开该文件
#define MC_E_EXCEED_FILESIZE			17		//超出文件尺寸范围
#define MC_E_EXCEED_DEVICESIZE			18		//超出卡片范围
#define MC_E_EXCEED_SUBIDRNUM			19		//超出子目录的数目
#define MC_E_BUFFER_TOO_SMALL			20		//空间太小
#define MC_E_DIRNAME_LEN_BAD			21		//目录名长度错误
#define MC_E_DIRNAME_ALREADY_EXIST		22		//目录名已存在
#define MC_E_DIR_NOT_FOUND				23		//目录不存在
#define MC_E_NO_WORKABLE_FILE_ID		24		//没有可用的文件标识
#define MC_E_UNALLOWED_OPERATION		25		//安全状态不满足
#define MC_E_INVALID_ALG_ID				26		//算法标识非法
#define MC_E_INVALID_KEY_TYPE			27		//密钥类型非法
#define MC_E_INVALID_FILE_TYPE			28		//文件类型非法
#define MC_E_DUPLICATE_KEY				29		//密钥不唯一
#define MC_E_KEY_ID_BAD					30		//密钥标识超出范围
#define MC_E_KEY_NOT_FOUND				31		//密钥没有找到
#define MC_E_AUTHENTICATION_FAIL		32		//认证失败
#define MC_E_AUTHENTICATION_LOCK		33		//认证方法被锁定
#define MC_E_DIR_NOT_EMPTY				34		//目录不为空
#define MC_E_DATA_LEN_BAD				35		//数据长度错误
#define MC_E_PIN_LEN_BAD				36		//PIN长度错误
#define MC_E_PIN_ERROR					37		//PIN错误
#define MC_E_PIN_LOCK					38		//PIN被锁

#pragma pack(pop, memcard)

#endif