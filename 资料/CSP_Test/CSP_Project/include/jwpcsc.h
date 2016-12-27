#ifndef __PCSC_OBJECT_EXPORT_METHON_H_
#define __PCSC_OBJECT_EXPORT_METHON_H_

#include "DevInterface.h"
#pragma pack(push)
#pragma pack(1)

#define JW_APP_DJ_CLIENT	"��ﵥ����ͻ���\0"

//   �ļ���ȫ��ʶλ����
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

// ��־λ���ԭ��:�ܾ�����
#define F_SEC_READ_AUTH_USER                    (0x00000001)    // �û����Զ�
#define F_SEC_READ_REFUSE_USER                  (0x00000002)    // �û����ܶ�
#define F_SEC_WRITE_AUTH_USER                   (0x00000004)    // �û�����д
#define F_SEC_WRITE_REFUSE_USER                 (0x00000008)    // �û�����д
#define F_SEC_READ_AUTH_ADMIN                   (0x00000010)    // ����Ա���Զ�
#define F_SEC_READ_REFUSE_ADMIN                 (0x00000020)    // ����Ա���ܶ�
#define F_SEC_WRITE_AUTH_ADMIN                  (0x00000040)    // ����Ա����д
#define F_SEC_WRITE_REFUSE_ADMIN                (0x00000080)    // ����Ա����д
#define F_SEC_READ_ANY_USER                     (0x00000100)    // �κ��û����Զ�
#define F_SEC_READ_REFUSE_ANY_USER              (0x00000200)    // �κ��û����ܶ�
#define F_SEC_WRITE_ANY_USER                    (0x00000400)    // �κ��û�����д
#define F_SEC_WRITE_REFUSE_ANY_USER             (0x00000800)    // �κ��û�����д


//   �ļ����ͱ�ʶ����
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//  |0 0 0 0|                                 F_TYPE_EF
//  |0 0 0 1|                                 F_TYPE_SF
//  |.......|                                 ��˳������,���ǰ�λ����
//  |1 1 1 1|                                 F_TYPE_DF

#define F_TYPE_EF                               (0x00000000)	// �������ļ�
#define F_TYPE_SF                               (0x10000000)	// ��Կ�ļ�
#define F_TYPE_DF                               (0xF0000000)	// Ŀ¼�ļ�

// ��������
typedef struct {
	// �汾
	unsigned long version;
	
	const char * (__stdcall* get_container_name_a)();
	const char * (__stdcall* get_container_name_w)();

	//4����ѯ�ӿ�
	unsigned long (__stdcall* query_interface)(
		IN const void* hDevice,
		IN const char* interface_name
		);
	
	unsigned long (__stdcall* dev_search)(
		IN const char * class_name,
		OUT DEVICE_INFO* dev_list,
		OUT unsigned long * pnCount
		);
	
	//7��ö���豸
	unsigned long (__stdcall* dev_enum)(
		IN const char * file_cfg,
		OUT DEVICE_INFO* dev_list,
		IN OUT unsigned long * pnCount
		);
	
	//5�������豸
	unsigned long (__stdcall* dev_connect)(
		IN OUT void * app_obj
		);
	
	//8���ر��豸
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

	//9���豸��Ȩ��֤
	unsigned long (__stdcall* dev_authenticate)(
		IN void* obj
		); 
		/*
		����˵��:
		dev_info:�豸��ʶ. 
	*/
	

	//10����������У��
	unsigned long (__stdcall* dev_verifypin)(
		IN void* obj,
		IN const char* pin
		); 
	
	
	//11���޸ĸ�������
	unsigned long (__stdcall* dev_modifypin)(
		IN void* obj,
		IN const char* old_pin,
		IN const char* new_pin
		);
	
	
	//12�������������ļ���������Կ�ļ�
	unsigned long (__stdcall* dev_createfile)(
		IN void* obj,
		IN const char * path,
		IN unsigned long security,
		IN unsigned long length
		);
		/*
		����˵��:
		dev_info:�豸��ʶ;
		path:�ļ�·��;
		security:�ļ���ȫ����SEC_PIN_READ��SEC_PIN_WRITE;
		file_length:�ļ�����.
	*/
	
	
	//13��д�������ļ��������Կ���޸���Կ
	unsigned long (__stdcall* dev_writefile)(
		IN void* obj,
		IN const char * path,
		IN const unsigned char * buffer,
		IN unsigned long length,
		IN unsigned long offset,
		IN unsigned long * pnCount
		);
		/*
		����˵��:
		dev_info:�豸��ʶ;
		path:�ļ�·��;
		buffer:Ҫд������;
		length:���ݳ���;
		offset:�ļ�ƫ����;
		pnCount:ʵ��д�����ݳ���.
	*/
	
	
	//14�����������ļ�
	unsigned long (__stdcall* dev_readfile)(
		IN void* obj,
		IN const char * path,
		OUT unsigned char * buffer,
		IN unsigned long length,
		IN unsigned long offset,
		IN unsigned long * pnCount
		);
		/*
		����˵��:
		dev_info:�豸��ʶ;
		path:�ļ�·��;
		buffer:���������ݻ���;
		length:Ҫ��ȡ�����ݳ���;
		offset:�ļ�ƫ����;
		pnCount:ʵ�ʶ�ȡ�����ݳ���.
	*/
	
	//16��������������PIN��
	unsigned long (__stdcall* dev_unlockpin)(
		IN void* obj,
		IN const char * unlock_pin,
		IN const char * new_pin
		);
		/*
		����˵��:
		dev_info:�豸��ʶ;
		reload_pin:PIN��װ��;
		new_pin:��PIN��.
	*/
	
	unsigned long (__stdcall* dev_command)(
		IN void* obj,
		IN unsigned char* cmd,
		IN unsigned long cmd_len,
		OUT unsigned char* resp,
		OUT unsigned long* resp_len
		);
	
	//22������֤��
	unsigned long (__stdcall* dev_importcert)(
		IN void* obj,
		IN unsigned long cert_type,
		IN const unsigned char * cert,
		IN unsigned long cert_length
		);
	
	//22������֤��
	unsigned long (__stdcall* dev_exportcert)(
		IN void* obj,
		IN unsigned long cert_type,
		OUT unsigned char* cert,
		OUT unsigned long* cert_length
		);

}JW_SC_APP_METHOD;

// ���Լ���
typedef struct {
	// �汾
	unsigned long version;
	// ������
	ULONG uCardType;
	char szCardName[64];
	// ����������
	ULONG uReaderType;
	char szReaderName[64];
	// Ӧ������
	ULONG uAppType;
	// Ӧ������
	char appname[64];
}JW_SC_APP_PROPERTY;

// Ӧ�ö���
typedef struct _jw_sc_app_obj_ {
	// �汾
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
