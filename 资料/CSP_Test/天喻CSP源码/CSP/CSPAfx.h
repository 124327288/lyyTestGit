//-------------------------------------------------------------------
//	���ļ�Ϊ TY Cryptographic Service Provider ����ɲ���
//
//
//	��Ȩ���� ������Ϣ��ҵ���޹�˾ (c) 1996 - 2002 ����һ��Ȩ��
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
#define  CSP_FILE_SYS_VERSION		0x0011
#define  DF_CSP_IN_MF				0x0001


#include "CSPObject.h"
#include "HelperFunc.h"
#include "GlobalVars.h"



//������Ϣ
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