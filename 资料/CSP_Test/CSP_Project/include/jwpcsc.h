#ifndef __PCSC_OBJECT_EXPORT_METHON_H_
#define __PCSC_OBJECT_EXPORT_METHON_H_

#include "DevInterface.h"
#pragma pack(push)
#pragma pack(1)

#define JW_APP_DJ_CLIENT	"瑞达单机版客户端\0"

//   文件安全标识位定义
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
// F_SEC_READ_AUTH_USER                                     |0 0 0 1|
// F_SEC_READ_REFUSE_USER                                   |0 0 1 0|
// F_SEC_WRITE_AUTH_USER                                    |0 1 0 0|
// F_SEC_WRITE_REFUSE_USER                                  |1 0 0 0|
// F_SEC_READ_AUTH_ADMIN                            |0 0 0 1 0 0 0 0|
// F_SEC_READ_REFUSE_ADMIN                          |0 0 1 0 0 0 0 0|
// F_SEC_WRITE_AUTH_ADMIN                           |0 1 0 0 0 0 0 0|
// F_SEC_WRITE_REFUSE_ADMIN                         |1 0 0 0 0 0 0 0|
// F_SEC_READ_ALL_USER                      |0 0 0 1 0 0 0 0 0 0 0 0|
// F_SEC_READ_REFUSE_ALL_USER               |0 0 1 0 0 0 0 0 0 0 0 0|
// F_SEC_WRITE_ALL_USER                     |0 1 0 0 0 0 0 0 0 0 0 0|
// F_SEC_WRITE_REFUSE_ALL_USER              |1 0 0 0 0 0 0 0 0 0 0 0|

// 标志位组合原则:拒绝优先
#define F_SEC_READ_AUTH_USER                    (0x00000001)    // 用户可以读
#define F_SEC_READ_REFUSE_USER                  (0x00000002)    // 用户不能读
#define F_SEC_WRITE_AUTH_USER                   (0x00000004)    // 用户可以写
#define F_SEC_WRITE_REFUSE_USER                 (0x00000008)    // 用户不能写
#define F_SEC_READ_AUTH_ADMIN                   (0x00000010)    // 管理员可以读
#define F_SEC_READ_REFUSE_ADMIN                 (0x00000020)    // 管理员不能读
#define F_SEC_WRITE_AUTH_ADMIN                  (0x00000040)    // 管理员可以写
#define F_SEC_WRITE_REFUSE_ADMIN                (0x00000080)    // 管理员不能写
#define F_SEC_READ_ANY_USER                     (0x00000100)    // 任何用户可以读
#define F_SEC_READ_REFUSE_ANY_USER              (0x00000200)    // 任何用户不能读
#define F_SEC_WRITE_ANY_USER                    (0x00000400)    // 任何用户可以写
#define F_SEC_WRITE_REFUSE_ANY_USER             (0x00000800)    // 任何用户不能写


//   文件类型标识定义
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//  |0 0 0 0|                                 F_TYPE_EF
//  |0 0 0 1|                                 F_TYPE_SF
//  |.......|                                 按顺序牌列,不是按位排列
//  |1 1 1 1|                                 F_TYPE_DF

#define F_TYPE_EF                               (0x00000000)	// 二进制文件
#define F_TYPE_SF                               (0x10000000)	// 密钥文件
#define F_TYPE_DF                               (0xF0000000)	// 目录文件

// 方法集合
typedef struct {
	// 版本
	unsigned long version;
	
	const char * (__stdcall* get_container_name_a)();
	const char * (__stdcall* get_container_name_w)();

	//4、查询接口
	unsigned long (__stdcall* query_interface)(
		IN const void* hDevice,
		IN const char* interface_name
		);
	
	unsigned long (__stdcall* dev_search)(
		IN const char * class_name,
		OUT DEVICE_INFO* dev_list,
		OUT unsigned long * pnCount
		);
	
	//7、枚举设备
	unsigned long (__stdcall* dev_enum)(
		IN const char * file_cfg,
		OUT DEVICE_INFO* dev_list,
		IN OUT unsigned long * pnCount
		);
	
	//5、连接设备
	unsigned long (__stdcall* dev_connect)(
		IN OUT void * app_obj
		);
	
	//8、关闭设备
	unsigned long (__stdcall* dev_close)(
		IN void* obj
		);

	unsigned long (__stdcall* dev_reject)(
		IN void* obj
		);

	unsigned long (__stdcall* dev_reset)(
		IN void* obj,
		OUT unsigned char* resp,
		OUT unsigned long* resp_len
		);

	//9、设备版权认证
	unsigned long (__stdcall* dev_authenticate)(
		IN void* obj
		); 
		/*
		参数说明:
		dev_info:设备标识. 
	*/
	

	//10、个人密码校验
	unsigned long (__stdcall* dev_verifypin)(
		IN void* obj,
		IN const char* pin
		); 
	
	
	//11、修改个人密码
	unsigned long (__stdcall* dev_modifypin)(
		IN void* obj,
		IN const char* old_pin,
		IN const char* new_pin
		);
	
	
	//12、创建二进制文件、创建密钥文件
	unsigned long (__stdcall* dev_createfile)(
		IN void* obj,
		IN const char * path,
		IN unsigned long security,
		IN unsigned long length
		);
		/*
		参数说明:
		dev_info:设备标识;
		path:文件路径;
		security:文件安全机制SEC_PIN_READ、SEC_PIN_WRITE;
		file_length:文件长度.
	*/
	
	
	//13、写二进制文件、添加密钥、修改密钥
	unsigned long (__stdcall* dev_writefile)(
		IN void* obj,
		IN const char * path,
		IN const unsigned char * buffer,
		IN unsigned long length,
		IN unsigned long offset,
		IN unsigned long * pnCount
		);
		/*
		参数说明:
		dev_info:设备标识;
		path:文件路径;
		buffer:要写的数据;
		length:数据长度;
		offset:文件偏离量;
		pnCount:实际写的数据长度.
	*/
	
	
	//14、读二进制文件
	unsigned long (__stdcall* dev_readfile)(
		IN void* obj,
		IN const char * path,
		OUT unsigned char * buffer,
		IN unsigned long length,
		IN unsigned long offset,
		IN unsigned long * pnCount
		);
		/*
		参数说明:
		dev_info:设备标识;
		path:文件路径;
		buffer:读出的数据缓冲;
		length:要读取的数据长度;
		offset:文件偏离量;
		pnCount:实际读取的数据长度.
	*/
	
	//16、解锁并更换新PIN码
	unsigned long (__stdcall* dev_unlockpin)(
		IN void* obj,
		IN const char * unlock_pin,
		IN const char * new_pin
		);
		/*
		参数说明:
		dev_info:设备标识;
		reload_pin:PIN重装码;
		new_pin:新PIN码.
	*/
	
	unsigned long (__stdcall* dev_command)(
		IN void* obj,
		IN unsigned char* cmd,
		IN unsigned long cmd_len,
		OUT unsigned char* resp,
		OUT unsigned long* resp_len
		);
	
	//22、导入证书
	unsigned long (__stdcall* dev_importcert)(
		IN void* obj,
		IN unsigned long cert_type,
		IN const unsigned char * cert,
		IN unsigned long cert_length
		);
	
	//22、导出证书
	unsigned long (__stdcall* dev_exportcert)(
		IN void* obj,
		IN unsigned long cert_type,
		OUT unsigned char* cert,
		OUT unsigned long* cert_length
		);

}JW_SC_APP_METHOD;

// 属性集合
typedef struct {
	// 版本
	unsigned long version;
	// 卡类型
	ULONG uCardType;
	char szCardName[64];
	// 读卡器类型
	ULONG uReaderType;
	char szReaderName[64];
	// 应用类型
	ULONG uAppType;
	// 应用名称
	char appname[64];
}JW_SC_APP_PROPERTY;

// 应用对象
typedef struct _jw_sc_app_obj_ {
	// 版本
	unsigned long version;
	// context
	void* context;
	JW_SC_APP_PROPERTY* property;
	JW_SC_APP_METHOD* method;
}JW_SC_APP_OBJ;

#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

unsigned long
__stdcall CreateAppObj(
	OUT void** obj,
	IN void* property
	);

unsigned long
__stdcall DeleteAppObj(
	IN void* obj
	);

#ifdef __cplusplus
}
#endif

#endif
