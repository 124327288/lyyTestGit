#ifndef __TYCSP_PRECOMPILE_H__
#define __TYCSP_PRECOMPILE_H__

#include "assert.h"
#ifndef ASSERT
#define ASSERT assert
#endif

#include "ArrayTmpl.h"

//�������
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

//Win32����
#define _WIN32_WINNT	0x0400
#include "wincrypt.h"
#include "Winscard.h"
#pragma comment(lib, "WinScard.lib")
#include "lmcons.h"

//////////////////////////////////////////////////////////////////////////////////
//CSP�ļ�ϵͳ�汾���� chenji 2005-12-22

//1.CSPӦ�ò��ٽ���2F01Ŀ¼����, ��ֱ�ӽ���MFĿ¼����
//
//2.��MF�½���һ������ļ�,��¼KEY�ļ��ṹϵͳ�汾��,�ĸ��ֽ�,����������ļ���KEY����Ϊ��KEY���ж�д����.
//
//	�汾���ɰ˸��ֽ����,ǰ�����ֽ����ļ�ϵͳ�İ汾��,�������ֽڰ�λ������,��48λ,���Ա�ʾ48���ļ�ϵͳ����
//	���汾����Ҫ��ȥ���е�����,��������Ժ������չ

typedef struct 
{
	WORD wFileSysVer;  //�ļ�ϵͳ�汾��
	WORD wDF_flag;		//DF���Ա��,��16λ���ܱ��
	DWORD dwEF_flag;	//EF���Ա��, ��32λ���ܱ��
}CSP_FILESYS_VER, *LPCSP_FILESYS_VER;

//ʹ���ļ�ʱ�ļ�����λ���, ���������ĸ�λ
#define EF_WRITE_PROTECTED			0x00000002	//д��·����
#define EF_ENC_WRITE_PROTECTED		0x00000001	//д������·����
#define EF_READ_PROTECTED			0x00000008	//����·����
#define EF_ENC_READ_PROTECTED		0x00000004	//��������·����

//����汾��CSP�ļ��汾��
#define  CSP_FILE_SYS_VERSION		0x0003
#define  DF_CSP_IN_MF				0x0001

//Ϊ_tagPathTable�����һ����ԱfileSysVerPath,
//Ϊg_cPathTableָ��fileSysVerPathΪ{0x50,0x29}

//�����ļ�ʱ�ļ����������õ�λ���, ����dwEF_flag�ĵ��ֽ�������λ���
#define WRITE_PROTECTED			0x10	//д��·����
#define ENC_WRITE_PROTECTED		0x08	//д������·����
#define READ_PROTECTED			0x40	//����·����
#define ENC_READ_PROTECTED		0x20	//��������·����
//���λ�Ǳ�ʾMF������,ֻ�й���ԱPIN��У����ܲ���MF
#define  FILE_SYS_MF_PROTECTED		0x0001

//////////////////////////////////////////////////////////////////////////////////
//��Ƭ��Ϣ
typedef struct TOKENINFO{
	CHAR manufacturerID[32];		//�����̵�����
	CHAR label[32];					//Token������
	CHAR model[16];					//Token��ģʽ
	CHAR serialNumber[16];			//Token�����к�
	BYTE pinMaxRetry;				//����Ա���û�PIN��������Դ���
}TOKENINFO, *LPTOKENINFO;

//��ʽ����Ϣ
typedef struct FORMATINFO{
	TOKENINFO tokenInfo;			//��Ƭ��Ϣ
	LPBYTE userPIN;					//�û���ʼPIN
	DWORD userPINLen;				//�û���ʼPIN�ĳ���,���Ϊ0,���ʼPINΪ"1234"
	BYTE userPINMaxRetry;			//�û�PIN���Դ���			
	LPBYTE soPIN;					//����Ա��ʼPIN
	DWORD soPINLen;					//����Ա��ʼPIN�ĳ���,���Ϊ0,���ʼPINΪ"1234"
	BYTE soPINMaxRetry;				//����ԱPIN���Դ���			
}FORMATINFO, *LPFORMATINFO;

//�û��ļ��Ĳ���ģʽ(CPAcquireUserFile�е�dwFlags)
#define USERFILE_NEW				0x0000
#define USERFILE_OPEN				0x0001
#define USERFILE_DELETE				0x0002

//�½��ļ�ʱ,��дȨ�ޱ��
#define USERFILE_AUTH_READ			0x0001
#define USERFILE_AUTH_WRITE			0x0002

//ö�ٶ�д����־
#define ENUM_PCSC_READER			0x00000001
#define ENUM_USBPORT_READER			0x00000002
#define ENUM_SERIALPORT_READER		0x00000004

//�û�����
#define UT_PUBLIC					0				//δ��¼
#define UT_USER						1				//�û�
#define UT_SO						2				//����Ա

//�ļ���ɾ���ı��
#define DESTROIED_TAG				0xff

//RSA��Կ�Ե����ģ��
#define MAX_RSAKEYPAIR_MODULUS_LEN	1024
//��ԿBlob����󳤶�
#define MAX_RSAPUBKEY_BLOB_LEN		(sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + MAX_RSAKEYPAIR_MODULUS_LEN /8)
//˽ԿBlob����󳤶�
#define MAX_RSAPRIKEY_BLOB_LEN		(sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + (MAX_RSAKEYPAIR_MODULUS_LEN /16)*9) 

#include "CSPObject.h"
#include "GlobalVars.h"

//������Ϣ
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