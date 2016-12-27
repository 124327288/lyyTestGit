#ifndef __DEVICE_INTERFACE_HEADER_
#define __DEVICE_INTERFACE_HEADER_

#include <windows.h>
//#include "Public.h"

#define IN		//表示参数输入
#define OUT		//表示参数输出

#pragma pack(push)
#pragma pack(1)

/************************************************************************/
/*函数调用                                                              */
/************************************************************************/
#define MAXLEN_DEV_NAME		((unsigned long)63)


//表示Usb Key或者IC Card的设备序列号的最大长度
#define MAXLEN_DEV_SERIAL	((unsigned long)255)
//表示个人密码即PIN码的最大长度
#define MAXLEN_DEV_PIN		((unsigned long)255)
//设备类型定义
#define DEV_TYPE_SOFT		((unsigned long)0)	//软件设备,仅用于软件加解密操作
#define DEV_TYPE_USB		((unsigned long)1)	//表示USB KEY设备
#define DEV_TYPE_INSIDEIC	((unsigned long)2)	//表示内置IC CARD设备
#define DEV_TYPE_OUTSIDEIC	((unsigned long)3)	//表示外置IC CARD设备
#define DEV_TYPE_ESM		((unsigned long)4)	//表示ESM设备
#define DEV_TYPE_CSP		((unsigned long)5)	//表示CSP设备
#define DEV_TYPE_UKI_ZJ		((unsigned long)6)	//表示中机Usb Key设备
#define DEV_TYPE_UKI_GA		((unsigned long)7)	//表示公安Usb Key设备
// 天喻IC 卡
#define DEV_TYPE_IC_TY             ((unsigned long)8)

#define DEV_TY_NAME                "ic_ty.dll"
//设备容器名称对应的动态库定义
#define DEV_SOFT_NAME		"JETWAYSOFT.dll"
#define DEV_USB_NAME		"JETWAYKEY.dll"		//明华UsbKey
#define DEV_INSIDEIC_NAME	"JETWAYCARD.dll"	//内置读卡器
#define DEV_OUTSIDEIC_NAME	"JetWayCard.dll"	//外置读卡器
#define DEV_ESM_NAME		"JETWAYESM.dll"		//ESM
#define DEV_CSP_NAME		"JETWAYCSP.dll"
#define DEV_ZJ_NAME			"UKI_ZJ.DLL"	//中机
#define DEV_GA_NAME			"UKI_GA.DLL"	//公安

//设备端口定义
#define DEV_INDEX_COM1		((unsigned long)1)	//读卡器连接端口为COM1
#define DEV_INDEX_COM2		((unsigned long)2)	//读卡器连接端口为COM2
#define DEV_INDEX_COM3		((unsigned long)3)	//读卡器连接端口为COM2
#define DEV_INDEX_COM4		((unsigned long)4)	//读卡器连接端口为COM3
#define DEV_INDEX_LPT		((unsigned long)5)	//读卡器连接端口为LPT
//操作
#define OPT_ENCRYPTO		((unsigned long) 0x10000000)		//加密操作
#define OPT_DECRYPTO		((unsigned long) 0x00000000)		//解密操作
#define OPT_IMPORT			((unsigned long) 0x01000000)		//导入操作
#define OPT_EXPORT			((unsigned long) 0x00000000)		//导出操作

//加解密算法
#define ALG_USER			((unsigned long) 0x00000000)		//自定义加密算法
#define ALG_DES				((unsigned long) 0x00000001)		//DES加密算法
#define ALG_3DES			((unsigned long) 0x00000002)		//3DES加密算法
#define ALG_SF33			((unsigned long) 0x00000003)		//国秘办33加密算法
#define ALG_RSA				((unsigned long) 0x00000004)		//RSA加密算法
#define ALG_SIGN			((unsigned long) 0x00000005)		//签名算法
#define ALG_SHA1			((unsigned long) 0x00000006)		//SHA1算法
#define ALG_MD5				((unsigned long) 0x00000007)		//MD5算法


//安全机制
#define SEC_PIN_READ		((unsigned long)0x00000001)			//需要验证PIN才能读取
#define SEC_PIN_WRITE		((unsigned long)0x00000002) 		//需要验证PIN才能写
//新添加的文件长度定义liuliu
#define CERTFILE_LEN                     1024*6
#define RSAFILE_LEN                      1024*2

//证书类型
#define CERT_TYPE_SIGN			(0)	//签名证书
#define CERT_TYPE_ENCRYPT		(1)	//加密证书

typedef struct
{
	//模块名称
	WCHAR module_name[MAX_PATH];
	//注册的容器名称
	WCHAR class_name[MAXLEN_DEV_NAME + 1];
}PCSC_DEVICE, *PPCSC_DEVICE;

//标识设备的结构
typedef struct 
{
	char	name[MAXLEN_DEV_NAME + 1];	//注册的容器名称	
	unsigned long index;			//索引,如果是Usb Key设备,则该索引值由系统分配
	unsigned long type;				//设备类型索引
	long	nPort;					//设备连接的端口值
	unsigned long baud_rate;		//波特率,该成员仅当type=DEV_TYPE_IC时有效 
	HANDLE  hDevice;				//设备句柄
	//设备序列号, 一般作为设备的唯一标识
	WCHAR	wzSerial[MAXLEN_DEV_SERIAL + 1];	
	//PIN码
	char dev_pin[MAXLEN_DEV_PIN + 1];
	
}DEVICE_INFO, *PDEVICE_INFO;

typedef struct 
{
	CHAR	name[MAXLEN_DEV_NAME + 1];	//注册的容器名称	
	DWORD	index;			//索引,如果是Usb Key设备,则该索引值由系统分配
	DWORD	type;				//设备类型索引
	long	nPort;					//设备连接的端口值
	DWORD	baud_rate;		//波特率,该成员仅当type=DEV_TYPE_IC时有效 
	HANDLE  hDevice;				//设备句柄
	//设备序列号, 一般作为设备的唯一标识
	CHAR	wzSerial[MAXLEN_DEV_SERIAL + 1];	
	//PIN码
	CHAR	dev_pin[MAXLEN_DEV_PIN + 1];
	
}DEVICE_INFO_A;

typedef struct 
{
	WCHAR	name[MAXLEN_DEV_NAME + 1];	//注册的容器名称	
	DWORD	index;			//索引,如果是Usb Key设备,则该索引值由系统分配
	DWORD	type;				//设备类型索引
	long	nPort;					//设备连接的端口值
	DWORD	baud_rate;		//波特率,该成员仅当type=DEV_TYPE_IC时有效 
	HANDLE  hDevice;				//设备句柄
	//设备序列号, 一般作为设备的唯一标识
	WCHAR	wzSerial[MAXLEN_DEV_SERIAL + 1];	
	//PIN码
	WCHAR	dev_pin[MAXLEN_DEV_PIN + 1];

}DEVICE_INFO_W;
/*
//加解密数据结构
typedef struct{
	unsigned long select;		//选择密钥标识
	unsigned long algorithm;	//算法标识
	unsigned char * key;		//密钥,加解密用的密钥
	unsigned long  key_length;	//密钥长度
	unsigned char * plaintext;	//明文,加密前或者解密后的数据
	unsigned long plaintext_length;		//明文长度
	unsigned char * ciphertext;			//密文,加密后或者解密前的数据
	unsigned long ciphertext_length;	//密文长度
}CRYPTO_DATA;


//加解密算法结构
typedef struct {
	unsigned long mode;
	unsigned long algorithm;		//加解密算法标志
	unsigned long (__stdcall *crypto_method)(void *);
}CRYPTO_COMPUTE;

#define MIN_RSA_MODULUS_BITS 508
#define MAX_RSA_MODULUS_BITS 1024
#define MAX_RSA_MODULUS_LEN ((MAX_RSA_MODULUS_BITS + 7) / 8)
#define MAX_RSA_PRIME_BITS ((MAX_RSA_MODULUS_BITS + 1) / 2)
#define MAX_RSA_PRIME_LEN ((MAX_RSA_PRIME_BITS + 7) / 8)

typedef struct {
	unsigned int bits;                           
	unsigned char modulus[MAX_RSA_MODULUS_LEN];        
	unsigned char exponent[MAX_RSA_MODULUS_LEN];       
} R_RSA_PUBLIC_KEY;

typedef struct {
	unsigned int bits;                         
	unsigned char modulus[MAX_RSA_MODULUS_LEN];		
	unsigned char publicExponent[MAX_RSA_MODULUS_LEN]; 
	unsigned char exponent[MAX_RSA_MODULUS_LEN];       
	unsigned char prime[2][MAX_RSA_PRIME_LEN];         
	unsigned char primeExponent[2][MAX_RSA_PRIME_LEN]; 
	unsigned char coefficient[MAX_RSA_PRIME_LEN];      
} R_RSA_PRIVATE_KEY;



//USERLIST 结构
typedef struct stUserListInfo
{
	char caUserID[(unsigned long)8];			//用户ID
	char caOutDate[(unsigned long)4];			//失效日期
	WORD wUserStatus;
}USERLISTINFO;

//卡信息文件结构
typedef struct CARDINFO_st
{ 
	unsigned char card_info;						//卡类型标志	
}CARDINFO;

//密钥BIN文件结构
typedef struct KEYBIN_st
{
	//unsigned char pinunlockkey[MAXLEN_PINUNLOCKKEY];		//PIN解锁密钥
	//unsigned char pinreloadkey[MAXLEN_PINRELOADKEY];		//PIN重装密钥
	unsigned char extdekey[(unsigned long)8];	//外部认证密钥
	unsigned char intdekey[(unsigned long)8];	//内部认证密钥
	unsigned char mainkey[(unsigned long)16];	//主密钥
    WORD certf_len;
} KEYBIN;

//密钥文件结构
typedef struct KEYFILE_st
{ 
	unsigned char privateKey[(unsigned long)6];	
	unsigned char pinunlockkey[(unsigned long)16];			//PIN解锁密钥
	unsigned char pinreloadkey[(unsigned long)16];			//PIN重装密钥
	unsigned char extdekey[(unsigned long)8];				//内部认证密钥
	unsigned char intdekey[(unsigned long)8];				//外部认证密钥
}KEYFILE;


//主密钥文件结构
typedef struct MAINKEY_st
{ 
	unsigned char mainkey[(unsigned long)16];		//PIN解锁密钥
}MAINKEY;


//用户信息文件结构
typedef struct USERINFO_st
{ 
	WORD	UID;
	unsigned char    UNAME[(unsigned long)16];
	WORD	GID;
	unsigned char    USERNAME[(unsigned long)16];
    unsigned char    KEY[(unsigned long)16];
    unsigned char    TYPE[(unsigned long)16];
    unsigned char    CLASS[(unsigned long)16];
    unsigned char    DEVICELOCK[(unsigned long)4];			
}UINFO; 

*/
#pragma pack(pop)

#endif	//__DEVICE_INTERFACE_HEADER_
