//-------------------------------------------------------------------
//	���ļ�Ϊ MemCard ����ɲ���
//
//
//	��Ȩ���� ������Ϣ��ҵ���޹�˾ (c) 1996 - 2002 ����һ��Ȩ��
//-------------------------------------------------------------------
//	�û��ӿ�:�������Ͷ���
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
#define MC_MIN_FILE_ID					0x0001	//��С�ļ���ʶ
#define MC_MAX_FILE_ID					0xFFFE	//����ļ���ʶ

#define MC_MIN_FILE_SIZE				0x0001	//��С�ļ��ߴ�
#define MC_MAX_FILE_SIZE				0xFFFF	//����ļ��ߴ�

typedef DWORD MC_CARD_TYPE;
#define MC_CARDTYPE_DISKFILE			0		//�����ļ�
#define MC_CARDTYPE_PCSCCARD			1		//��д������PCSC�Ĵ洢��
#define MC_CARDTYPE_TYKEY				2		//��д��ΪTYKEY�Ĵ洢��
#define MC_CARDTYPE_CYPRESSSB			3		//��д��ΪCypress��SB��

typedef BYTE MC_FILE_TYPE;
#define MC_BINARY_FILE					0x00	//�������ļ�
#define MC_KEY_FILE						0x05	//��Կ�ļ�

typedef DWORD MC_SEEK_TYPE;
#define MC_SEEK_FROM_BEGINNING			0		//���ļ�ͷ��ʼ����
#define MC_SEEK_FROM_END				1		//���ļ�β��ʼ����	
#define MC_SEEK_RELATIVE				2		//���ļ���ǰλ�ÿ�ʼ����	

typedef DWORD MC_CD_TYPE;
#define MC_CD_FROM_ROOT					0		//�Ӹ�Ŀ¼��ʼ����Ŀ¼
#define MC_CD_RELATIVE					1		//�ӵ�ǰĿ¼��ʼ����Ŀ¼

typedef struct MC_SYSTEM_CREATE_INFO{
	WORD wSize;									//��Ƭ�ߴ�(��λΪKByte)
	BYTE nAlign;								//�ļ��ֽڶ�����(00��ʾ256)
	WORD wFatItemCount;							//FAT������
	BYTE authCreate;							//�����ļ���Ȩ��
	BYTE authDelete;							//ɾ���ļ�ϵͳ��Ȩ��
	WORD reserved;								//����
}MC_SYSTEM_CREATE_INFO;

typedef struct MC_FILE_CREATE_INFO{
	MC_FILE_TYPE type;							//�ļ�����
	DWORD dwSize;								//�ļ���С
	BYTE authRead;								//��Ȩ��
	BYTE authWrite;								//дȨ��
}MC_FILE_CREATE_INFO;

typedef struct MC_DIR_CREATE_INFO{
	BYTE authCreate;							//�����ļ���Ȩ��
	BYTE authDelete;							//ɾ���ļ���Ȩ��
}MC_DIR_CREATE_INFO;

typedef struct MC_FILE_PROP{
	MC_FILE_ID fileId;							//�ļ���ʶ
	BYTE isDir;									//��Ŀ¼(1)�����ļ�(0)
	union{
		MC_FILE_CREATE_INFO	file;				//��Ӧ���ļ�����Ϣ
		MC_DIR_CREATE_INFO dir;					//��Ӧ��Ŀ¼����Ϣ
	}prop;
}MC_FILE_PROP;

typedef BYTE MC_KEY_ID;
#define MC_MIN_KEY_ID					0x01	//��С��Կ��ʶ
#define MC_MAX_KEY_ID					0xFE	//�����Կ��ʶ

typedef BYTE MC_ALG_ID;
#define MC_ALG_TRIPLEDES				0		//3-DES
#define MC_ALG_SINGLEDES				1		//DES
#define MC_ALG_PIN						0xFF	//PIN

typedef BYTE MC_KEY_TYPE;
#define MC_EXTERNALAUTH_KEY				0x08	//�ⲿ��֤��Կ
#define MC_INTERNALAUTH_KEY				0x09	//�ڲ���֤��Կ		
#define MC_PIN_KEY						0x0B	//��������

typedef struct MC_KEY_INFO{
	MC_KEY_ID	id;								//��Կ��ʶ
	BYTE		version;						//�汾��
	MC_ALG_ID	algid;							//�㷨��ʶ
	MC_KEY_TYPE	type;							//��Կ����
	BYTE		useauth;						//ʹ��Ȩ��
	BYTE		aftersec;						//����״̬
	BYTE		modifyauth;						//�޸�Ȩ��
	BYTE		errorcount;						//�������
	BYTE		key[16];						//��Կ
	BYTE		keylen;							//��Կ����
}MC_KEY_INFO;

#define MC_ERRMSG_MAX_LEN				256		//��������������󳤶�
typedef DWORD MC_RV;
#define MC_S_SUCCESS					0		//�����ɹ�
#define MC_E_FAIL						1		//����ʧ��(ϵͳ�ڲ�����)
#define MC_E_DEVICE_ABSENT				2		//��Ƭ������
#define MC_E_DEVICE_READ_ERROR			3		//��Ƭ������
#define MC_E_DEVICE_WRITE_ERROR			4		//��Ƭд����
#define MC_E_INVALID_PARAMETER			5		//��������
#define MC_E_INVALID_CARD_HANDLE		6		//��Ƭ����Ƿ�
#define MC_E_INVALID_FILE_HANDLE		7		//�ļ�����Ƿ�
#define MC_E_NO_FILE_SYSTEM				8		//��Ƭϵͳ����δ����������
#define MC_E_NO_HOST_MEMORY				9		//��λ���ڴ治��
#define MC_E_NO_DEVICE_MEMORY			10		//��Ƭ�ռ䲻��
#define MC_E_NO_DEVICE_CONTEXT			11		//û���豸����
#define MC_E_FILE_ID_BAD				12		//�ļ���ʶ������Χ
#define MC_E_FILE_SIZE_BAD				13		//�ļ��ߴ糬����Χ	
#define MC_E_FILE_ALREADY_EXIST			14		//�ļ��Ѵ���
#define MC_E_FILE_NOT_FOUND				15		//�ļ�������
#define MC_E_FILE_OPEN_DENY				16		//��ֹ�򿪸��ļ�
#define MC_E_EXCEED_FILESIZE			17		//�����ļ��ߴ緶Χ
#define MC_E_EXCEED_DEVICESIZE			18		//������Ƭ��Χ
#define MC_E_EXCEED_SUBIDRNUM			19		//������Ŀ¼����Ŀ
#define MC_E_BUFFER_TOO_SMALL			20		//�ռ�̫С
#define MC_E_DIRNAME_LEN_BAD			21		//Ŀ¼�����ȴ���
#define MC_E_DIRNAME_ALREADY_EXIST		22		//Ŀ¼���Ѵ���
#define MC_E_DIR_NOT_FOUND				23		//Ŀ¼������
#define MC_E_NO_WORKABLE_FILE_ID		24		//û�п��õ��ļ���ʶ
#define MC_E_UNALLOWED_OPERATION		25		//��ȫ״̬������
#define MC_E_INVALID_ALG_ID				26		//�㷨��ʶ�Ƿ�
#define MC_E_INVALID_KEY_TYPE			27		//��Կ���ͷǷ�
#define MC_E_INVALID_FILE_TYPE			28		//�ļ����ͷǷ�
#define MC_E_DUPLICATE_KEY				29		//��Կ��Ψһ
#define MC_E_KEY_ID_BAD					30		//��Կ��ʶ������Χ
#define MC_E_KEY_NOT_FOUND				31		//��Կû���ҵ�
#define MC_E_AUTHENTICATION_FAIL		32		//��֤ʧ��
#define MC_E_AUTHENTICATION_LOCK		33		//��֤����������
#define MC_E_DIR_NOT_EMPTY				34		//Ŀ¼��Ϊ��
#define MC_E_DATA_LEN_BAD				35		//���ݳ��ȴ���
#define MC_E_PIN_LEN_BAD				36		//PIN���ȴ���
#define MC_E_PIN_ERROR					37		//PIN����
#define MC_E_PIN_LOCK					38		//PIN����

#pragma pack(pop, memcard)

#endif