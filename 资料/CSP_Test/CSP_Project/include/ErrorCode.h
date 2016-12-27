/*
	����޸���:�Ϸ�
	�޸�ʱ��:2004-7-7
	��Ӳ��֣���ӡ����
*/

/*
�ļ�: JetErr.h
˵��: ͳһ������붨��

 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 +---+-+-+-----------------------+-------------------------------+
 |Sev|C|R|     Facility          |               Code            |
 +---+-+-+-----------------------+-------------------------------+
 Sev 2 Bit
	Indicates the severity. This is one of the following values: 
	00 - Success
	01 - Informational
	10 - Warning
	11 - Error, ����ʹ�� 11

 C 1 bit
	Indicates a customer code (1) or a system code (0). 
	�Զ���ʹ�� 1
 R 1 bit
	Reserved bit.
	����ʹ�� 0
 Facility 12 bit
	Facility code. This can be FACILITY_NULL or one of the following values:
	������ģ�黮������
	FACILITY_NULL	000000000000 ->	��ʱ����
	FACILITY_USBKEY	000000000001 ->	USB Key�豸����ģ��
	FACILITY_COMM	000000000010 ->	����ͨѶģ��
	FACILITY_DB		000000000011 ->	���ݿ����ģ��
	FACILITY_GINA	000000000100 ->	GINAģ��
	FACILITY_CRYPT	000000000101 ->	�ӽ���ģ��
	FACILITY_USERAUTH	000000000110 ->	�����֤ģ��

 Code 16 bit
	Status code for the facility.
	����������ģ��Ĵ������

�Զ�������������ƹ淶

	�����ƽṹ --> ͷ + "_" + ģ���� + ��������

	˵��:
	1.	������������� " ERR_ " ��ͷ

	2.	���������ģ����
			ģ���Ʋμ� "ģ�黮��" ���ֵĶ���

	3.	���Ϊ�����Ҫ����
		Ҫ��: �ܼ�Ҫ����������Ϣ
		����: ���ݿ�ģ��->���Ӵ���
		������: ERR_DB_CONNECT �� ERR_DB_OPEN �ȵ�

	4.	������������ϸ��, Ҳ�ɲ���
		��ʽ: ��ģ�� + "_" + ��������
		����: EKEYģ��->�豸������ģ��->�豸û�ҵ�
		������: ERR_EKEY_DEV_NONE


*/

#ifndef _KEY_ERROR_DEFINE_H_
#define _KEY_ERROR_DEFINE_H_


//////////////////////////////////////////////////////////////////////////
//
//	���ù���
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

/* ��ȷ����ֵ */
#define ERR_OK	((unsigned long)0)

/* ���� */
#define ERR_BASE	((unsigned long)0xE0000000)

/*//////////////////////////////////////////////////////////////////////////

	ģ�黮��

//////////////////////////////////////////////////////////////////////////*/

//	���ô�����Ϣ
#define FACILITY_PUBLIC		((DWORD)0x00010000)

//	����ͨѶģ��
#define FACILITY_COMM		((DWORD)0x00020000)
//	���ݿ����ģ��
#define FACILITY_DB			((DWORD)0x00030000)
//	GINAģ��
#define FACILITY_GINA		((DWORD)0x00040000)
//	�ӽ���ģ��
#define FACILITY_CRYPTO		((DWORD)0x00050000)
//	�����֤ģ��
#define FACILITY_USERAUTH	((DWORD)0x00060000)
//	��Դ��ȡ
#define FACILITY_RESOURCE	((DWORD)0x00070000)
//	�豸����
#define FACILITY_DEVLOCK	((DWORD)0x00080000)

//���ܿ�ģ��
#define FACILITY_PCSC		((DWORD)0x000A0000)
//	����Usb eKey �Լ� IC ���豸����ģ��
#define FACILITY_MWUSBD		((DWORD)0x00070000)
#define FACILITY_MWXCAPI	((DWORD)0x00080000)
#define FACILITY_MWIC32		((DWORD)0x00090000)



//////////////////////////////////////////////////////////////////////////
//
//	���������ϸ����
//
//////////////////////////////////////////////////////////////////////////

#define ERR_COMM_BASE		((DWORD)(ERR_BASE | FACILITY_COMM + 0))
//�޷���ȡ����, ����ʾ�޷����ӷ�����
#define ERR_COMM_CANNOT_GET_PROXY	(ERR_COMM_BASE + 1);

//////////////////////////////////////////////////////////////////////////
//
//	���д������
//
//////////////////////////////////////////////////////////////////////////

/* �������������� */
#define ERR_PUBLIC_BASE				((DWORD)(ERR_BASE | FACILITY_PUBLIC + 0))
/* �������� */
#define ERR_PUBLIC_PARAM			((DWORD)(ERR_PUBLIC_BASE + 0))
/* û���㹻�Ļ����� */
#define ERR_PUBLIC_BUF_NOTENOUGH	((DWORD)(ERR_PUBLIC_BASE + 1))
/* û���㹻���ڴ� */
#define ERR_PUBLIC_MEM_NOTENOUGH	((DWORD)(ERR_PUBLIC_BASE + 2))
/* ���ض�̬��ʧ�� */
#define ERR_PUBLIC_LOAD_DLL			((DWORD)(ERR_PUBLIC_BASE + 3))
/* �޷�ʶ������� */
#define ERR_PUBLIC_REG_UNKNOWHKEY	((DWORD)(ERR_PUBLIC_BASE + 4))
/* δ֪���� */
#define ERR_PUBLIC_UNKNOW			((DWORD)(ERR_PUBLIC_BASE + 5))
/* ��̬�����ʧ�� */
#define ERR_PUBLIC_DLLERROR			((DWORD)(ERR_PUBLIC_BASE + 6))
/* û����Ҫ������ */
#define ERR_PUBLIC_NODATA			((DWORD)(ERR_PUBLIC_BASE + 7))
/* �ļ�����ʹ�� */
#define ERR_PUBLIC_FILEISUSEDING	((DWORD)(ERR_PUBLIC_BASE + 8))
/* ���ṩ��Ӧ��֧�� */
#define ERR_PUBLIC_UNPROVIDE		((DWORD)(ERR_PUBLIC_BASE + 9))
//////////////////////////////////////////////////////////////////////////
//
//	ͨѶģ��������
//
//////////////////////////////////////////////////////////////////////////



//////////////////////////////////////////////////////////////////////////
//
//	���ݿ�ģ��������
//
//////////////////////////////////////////////////////////////////////////
// ���ݿ���ش���������
#define ERR_DB_BASE				((unsigned long)(ERR_BASE | FACILITY_DB))
#define ERR_DB_CONNECT_FAIL		((unsigned long)(ERR_DB_BASE + 0))
#define ERR_DB_QUERY_FAIL		((unsigned long)(ERR_DB_BASE + 1))
#define ERR_DB_RESULT_FAIL      ((unsigned long)(ERR_DB_BASE + 2))
#define ERR_DB_NOT_CONNECT		((unsigned long)(ERR_DB_BASE + 3))
#define ERR_DB_NO_RECORD		((unsigned long)(ERR_DB_BASE + 4))

//////////////////////////////////////////////////////////////////////////
//
//	���ܿ�ģ��������
//
//////////////////////////////////////////////////////////////////////////
#define ERR_MWUSBD_BASE			((unsigned long)(ERR_BASE | FACILITY_MWUSBD))
#define ERR_MWUSBD_NODEVICE		((unsigned long)(ERR_MWUSBD_BASE + 1))

#define ERR_PCSC_BASE					(ERR_BASE | FACILITY_PCSC)
#define ERR_PCSC_NO_DEVICE				(ERR_PCSC_BASE + 1)	//û���豸
#define ERR_PCSC_INVALID_DEVICE			(ERR_PCSC_BASE + 2)	//�豸���Ϸ�
#define ERR_PCSC_VERIFY_PIN				(ERR_PCSC_BASE + 3)	//У��PIN����
#define ERR_PCSC_MODIFY_PIN				(ERR_PCSC_BASE + 4)	//�޸�PIN����
#define ERR_PCSC_MULTI_DEVICE			(ERR_PCSC_BASE + 5)	//����豸

//////////////////////////////////////////////////////////////////////////
//
//	�����֤
//
//////////////////////////////////////////////////////////////////////////
#define ERR_USERAUTH_BASE			((DWORD)(ERR_BASE | FACILITY_USERAUTH))
#define ERR_USERAUTH_NORIGHT		(ERR_USERAUTH_BASE + 0)



//////////////////////////////////////////////////////////////////////////
//
//	��Դ��ȡ
//
//////////////////////////////////////////////////////////////////////////
#define ERR_RESOURCE_BASE			((unsigned long)(ERR_BASE | FACILITY_RESOURCE))
// ��ȡ��Դʧ��
#define ERR_RES_GET_FAIL			((unsigned long)(ERR_RESOURCE_BASE + 1))
// ��ȡDevice Setup Classʧ��
#define ERR_RES_GET_DEV_SETUP		((unsigned long)(ERR_RESOURCE_BASE + 2))
// ��ȡDevice Interface Classʧ��
#define ERR_RES_GET_DEV_INTERFACE	((unsigned long)(ERR_RESOURCE_BASE + 3))

//////////////////////////////////////////////////////////////////////////
//
//	�ӽ���ģ��
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
//	�豸����
//
//////////////////////////////////////////////////////////////////////////

#define ERR_DEVLOCK_BASE			(ERR_BASE | FACILITY_DEVLOCK)

#define ERR_DEVLOCK_OPENSCMGR		(ERR_DEVLOCK_BASE + 1)
#define ERR_DEVLOCK_QUERYSC			(ERR_DEVLOCK_BASE + 2)
#define ERR_DEVLOCK_STOPSC			(ERR_DEVLOCK_BASE + 3)
#define ERR_DEVLOCK_STARTSC			(ERR_DEVLOCK_BASE + 4)
#define ERR_DEVLOCK_CONTROL			(ERR_DEVLOCK_BASE + 5)

#endif
