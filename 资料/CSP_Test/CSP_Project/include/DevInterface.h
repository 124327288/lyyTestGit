#ifndef __DEVICE_INTERFACE_HEADER_
#define __DEVICE_INTERFACE_HEADER_

#include <windows.h>
//#include "Public.h"

#define IN		//��ʾ��������
#define OUT		//��ʾ�������

#pragma pack(push)
#pragma pack(1)

/************************************************************************/
/*��������                                                              */
/************************************************************************/
#define MAXLEN_DEV_NAME		((unsigned long)63)


//��ʾUsb Key����IC Card���豸���кŵ���󳤶�
#define MAXLEN_DEV_SERIAL	((unsigned long)255)
//��ʾ�������뼴PIN�����󳤶�
#define MAXLEN_DEV_PIN		((unsigned long)255)
//�豸���Ͷ���
#define DEV_TYPE_SOFT		((unsigned long)0)	//����豸,����������ӽ��ܲ���
#define DEV_TYPE_USB		((unsigned long)1)	//��ʾUSB KEY�豸
#define DEV_TYPE_INSIDEIC	((unsigned long)2)	//��ʾ����IC CARD�豸
#define DEV_TYPE_OUTSIDEIC	((unsigned long)3)	//��ʾ����IC CARD�豸
#define DEV_TYPE_ESM		((unsigned long)4)	//��ʾESM�豸
#define DEV_TYPE_CSP		((unsigned long)5)	//��ʾCSP�豸
#define DEV_TYPE_UKI_ZJ		((unsigned long)6)	//��ʾ�л�Usb Key�豸
#define DEV_TYPE_UKI_GA		((unsigned long)7)	//��ʾ����Usb Key�豸
// ����IC ��
#define DEV_TYPE_IC_TY             ((unsigned long)8)

#define DEV_TY_NAME                "ic_ty.dll"
//�豸�������ƶ�Ӧ�Ķ�̬�ⶨ��
#define DEV_SOFT_NAME		"JETWAYSOFT.dll"
#define DEV_USB_NAME		"JETWAYKEY.dll"		//����UsbKey
#define DEV_INSIDEIC_NAME	"JETWAYCARD.dll"	//���ö�����
#define DEV_OUTSIDEIC_NAME	"JetWayCard.dll"	//���ö�����
#define DEV_ESM_NAME		"JETWAYESM.dll"		//ESM
#define DEV_CSP_NAME		"JETWAYCSP.dll"
#define DEV_ZJ_NAME			"UKI_ZJ.DLL"	//�л�
#define DEV_GA_NAME			"UKI_GA.DLL"	//����

//�豸�˿ڶ���
#define DEV_INDEX_COM1		((unsigned long)1)	//���������Ӷ˿�ΪCOM1
#define DEV_INDEX_COM2		((unsigned long)2)	//���������Ӷ˿�ΪCOM2
#define DEV_INDEX_COM3		((unsigned long)3)	//���������Ӷ˿�ΪCOM2
#define DEV_INDEX_COM4		((unsigned long)4)	//���������Ӷ˿�ΪCOM3
#define DEV_INDEX_LPT		((unsigned long)5)	//���������Ӷ˿�ΪLPT
//����
#define OPT_ENCRYPTO		((unsigned long) 0x10000000)		//���ܲ���
#define OPT_DECRYPTO		((unsigned long) 0x00000000)		//���ܲ���
#define OPT_IMPORT			((unsigned long) 0x01000000)		//�������
#define OPT_EXPORT			((unsigned long) 0x00000000)		//��������

//�ӽ����㷨
#define ALG_USER			((unsigned long) 0x00000000)		//�Զ�������㷨
#define ALG_DES				((unsigned long) 0x00000001)		//DES�����㷨
#define ALG_3DES			((unsigned long) 0x00000002)		//3DES�����㷨
#define ALG_SF33			((unsigned long) 0x00000003)		//���ذ�33�����㷨
#define ALG_RSA				((unsigned long) 0x00000004)		//RSA�����㷨
#define ALG_SIGN			((unsigned long) 0x00000005)		//ǩ���㷨
#define ALG_SHA1			((unsigned long) 0x00000006)		//SHA1�㷨
#define ALG_MD5				((unsigned long) 0x00000007)		//MD5�㷨


//��ȫ����
#define SEC_PIN_READ		((unsigned long)0x00000001)			//��Ҫ��֤PIN���ܶ�ȡ
#define SEC_PIN_WRITE		((unsigned long)0x00000002) 		//��Ҫ��֤PIN����д
//����ӵ��ļ����ȶ���liuliu
#define CERTFILE_LEN                     1024*6
#define RSAFILE_LEN                      1024*2

//֤������
#define CERT_TYPE_SIGN			(0)	//ǩ��֤��
#define CERT_TYPE_ENCRYPT		(1)	//����֤��

typedef struct
{
	//ģ������
	WCHAR module_name[MAX_PATH];
	//ע�����������
	WCHAR class_name[MAXLEN_DEV_NAME + 1];
}PCSC_DEVICE, *PPCSC_DEVICE;

//��ʶ�豸�Ľṹ
typedef struct 
{
	char	name[MAXLEN_DEV_NAME + 1];	//ע�����������	
	unsigned long index;			//����,�����Usb Key�豸,�������ֵ��ϵͳ����
	unsigned long type;				//�豸��������
	long	nPort;					//�豸���ӵĶ˿�ֵ
	unsigned long baud_rate;		//������,�ó�Ա����type=DEV_TYPE_ICʱ��Ч 
	HANDLE  hDevice;				//�豸���
	//�豸���к�, һ����Ϊ�豸��Ψһ��ʶ
	WCHAR	wzSerial[MAXLEN_DEV_SERIAL + 1];	
	//PIN��
	char dev_pin[MAXLEN_DEV_PIN + 1];
	
}DEVICE_INFO, *PDEVICE_INFO;

typedef struct 
{
	CHAR	name[MAXLEN_DEV_NAME + 1];	//ע�����������	
	DWORD	index;			//����,�����Usb Key�豸,�������ֵ��ϵͳ����
	DWORD	type;				//�豸��������
	long	nPort;					//�豸���ӵĶ˿�ֵ
	DWORD	baud_rate;		//������,�ó�Ա����type=DEV_TYPE_ICʱ��Ч 
	HANDLE  hDevice;				//�豸���
	//�豸���к�, һ����Ϊ�豸��Ψһ��ʶ
	CHAR	wzSerial[MAXLEN_DEV_SERIAL + 1];	
	//PIN��
	CHAR	dev_pin[MAXLEN_DEV_PIN + 1];
	
}DEVICE_INFO_A;

typedef struct 
{
	WCHAR	name[MAXLEN_DEV_NAME + 1];	//ע�����������	
	DWORD	index;			//����,�����Usb Key�豸,�������ֵ��ϵͳ����
	DWORD	type;				//�豸��������
	long	nPort;					//�豸���ӵĶ˿�ֵ
	DWORD	baud_rate;		//������,�ó�Ա����type=DEV_TYPE_ICʱ��Ч 
	HANDLE  hDevice;				//�豸���
	//�豸���к�, һ����Ϊ�豸��Ψһ��ʶ
	WCHAR	wzSerial[MAXLEN_DEV_SERIAL + 1];	
	//PIN��
	WCHAR	dev_pin[MAXLEN_DEV_PIN + 1];

}DEVICE_INFO_W;
/*
//�ӽ������ݽṹ
typedef struct{
	unsigned long select;		//ѡ����Կ��ʶ
	unsigned long algorithm;	//�㷨��ʶ
	unsigned char * key;		//��Կ,�ӽ����õ���Կ
	unsigned long  key_length;	//��Կ����
	unsigned char * plaintext;	//����,����ǰ���߽��ܺ������
	unsigned long plaintext_length;		//���ĳ���
	unsigned char * ciphertext;			//����,���ܺ���߽���ǰ������
	unsigned long ciphertext_length;	//���ĳ���
}CRYPTO_DATA;


//�ӽ����㷨�ṹ
typedef struct {
	unsigned long mode;
	unsigned long algorithm;		//�ӽ����㷨��־
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



//USERLIST �ṹ
typedef struct stUserListInfo
{
	char caUserID[(unsigned long)8];			//�û�ID
	char caOutDate[(unsigned long)4];			//ʧЧ����
	WORD wUserStatus;
}USERLISTINFO;

//����Ϣ�ļ��ṹ
typedef struct CARDINFO_st
{ 
	unsigned char card_info;						//�����ͱ�־	
}CARDINFO;

//��ԿBIN�ļ��ṹ
typedef struct KEYBIN_st
{
	//unsigned char pinunlockkey[MAXLEN_PINUNLOCKKEY];		//PIN������Կ
	//unsigned char pinreloadkey[MAXLEN_PINRELOADKEY];		//PIN��װ��Կ
	unsigned char extdekey[(unsigned long)8];	//�ⲿ��֤��Կ
	unsigned char intdekey[(unsigned long)8];	//�ڲ���֤��Կ
	unsigned char mainkey[(unsigned long)16];	//����Կ
    WORD certf_len;
} KEYBIN;

//��Կ�ļ��ṹ
typedef struct KEYFILE_st
{ 
	unsigned char privateKey[(unsigned long)6];	
	unsigned char pinunlockkey[(unsigned long)16];			//PIN������Կ
	unsigned char pinreloadkey[(unsigned long)16];			//PIN��װ��Կ
	unsigned char extdekey[(unsigned long)8];				//�ڲ���֤��Կ
	unsigned char intdekey[(unsigned long)8];				//�ⲿ��֤��Կ
}KEYFILE;


//����Կ�ļ��ṹ
typedef struct MAINKEY_st
{ 
	unsigned char mainkey[(unsigned long)16];		//PIN������Կ
}MAINKEY;


//�û���Ϣ�ļ��ṹ
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
