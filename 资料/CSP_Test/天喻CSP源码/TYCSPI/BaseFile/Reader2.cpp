#include "stdafx.h"
#include "reader.h"
#include "md5.h"
#include "HelperFunc.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

extern BYTE g_pbMacKey[];

BOOL CCSPReader::cpuFormatCard(LPFORMATINFO pFormatInfo)
{
	if(pFormatInfo == NULL)
		return FALSE;

	CSP_FILESYS_VER ver;
	memset(&ver, 0, sizeof(m_FileSys));
	ver.wFileSysVer = CSP_FILE_SYS_VERSION;
// 	ver.wFileSysVer |= FILE_SYS_MF_PROTECTED;
//	ver.dwEF_flag |= EF_WRITE_PROTECTED;
	ver.wDF_flag |= DF_CSP_IN_MF;

	//�ļ�ͨ����·��������
	BYTE bCommProtect = (LOBYTE(LOWORD(ver.dwEF_flag)) << 4);

	//�����Ӧ��SO PIN��USER PIN���ⲿ��֤��Կ
	BYTE so_pin[16], user_pin[16];
	MD5 hash;
	if(pFormatInfo->soPINLen == 0)
		hash.CalculateDigest(so_pin, (LPBYTE)"1234", 4);
	else
		hash.CalculateDigest(so_pin, pFormatInfo->soPIN, pFormatInfo->soPINLen);

	if(pFormatInfo->userPINLen == 0)
		hash.CalculateDigest(user_pin, (LPBYTE)"1234", 4);
	else
		hash.CalculateDigest(user_pin, pFormatInfo->userPIN, pFormatInfo->userPINLen);

	//����PIN�����Դ���
	BYTE soPinMaxRetry = 0x33, userPinMaxRetry = 0x33;
	if(pFormatInfo->soPINMaxRetry > 0)
		soPinMaxRetry = ((pFormatInfo->soPINMaxRetry << 4) & 0xF0) | (pFormatInfo->soPINMaxRetry & 0x0F);
	if(pFormatInfo->userPINMaxRetry > 0)
		userPinMaxRetry = ((pFormatInfo->userPINMaxRetry << 4) & 0xF0) | (pFormatInfo->userPINMaxRetry & 0x0F);

	ByteArray baTokenInfo;
	if(!TokenInfoDEREncoding(&(pFormatInfo->tokenInfo), baTokenInfo))
		return FALSE;

	BYTE pbCmd[256];
	DWORD cbCmdLen;
	BOOL bReturn;
	WORD wStatus;

	//ѡ�����ļ�
	cbCmdLen = 7;
	memcpy(pbCmd, "\x00\xa4\x00\x00\x02\x3f\x00", cbCmdLen);
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);

	if(m_FileSys.wFileSysVer & FILE_SYS_MF_PROTECTED)
	{
		DWORD dwRetry = 0;
		if(!Login(UT_SO, pFormatInfo->soPIN, pFormatInfo->soPINLen, dwRetry))
			return FALSE;
	}

	//�������ļ�
	cbCmdLen = 7;
	memcpy(pbCmd,"\x80\x0e\x00\x00\x02\x3f\x00",cbCmdLen);
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//�������ļ�
	cbCmdLen = 15;
	memcpy(pbCmd,"\x80\xe0\x00\x00\x0a\x0f\x01\xff\xff\xff\xff\xff\xff\xff\xff",cbCmdLen);
	if(ver.wFileSysVer & FILE_SYS_MF_PROTECTED)
		pbCmd[5] = 0x5A;
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn){
		memcpy(pbCmd,"\x80\xe0\x00\x00\x0a\x0f\x01\x00\x00\x00\x00\x00\x00\x00\x00",cbCmdLen);
		if(ver.wFileSysVer & FILE_SYS_MF_PROTECTED)
			pbCmd[5] = 0x5A;
		bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
		if(!bReturn) return FALSE;
	}

	//�����ļ�ϵͳ�汾���ļ�
	cbCmdLen = 12;
	memcpy(pbCmd,"\x80\xE0\x02\x00\x07\x50\x32\x00\x0f\x0f\x00\x80",cbCmdLen);
	pbCmd[5] = g_cPathTable.fileSysVerPath[0];//�ļ�·��
	pbCmd[6] = g_cPathTable.fileSysVerPath[1];//�ļ�·��
	pbCmd[7] &= bCommProtect;				//��·����
	pbCmd[10] = 0x00;						//�ļ���С
	pbCmd[11] = (BYTE)sizeof(ver);			//�ļ���С

	/*��������*/
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//д�뵽�ļ�,����
	memcpy(pbCmd,"\x00\xA4\x02\x00\x02\x50\x32",7);
	pbCmd[5] = g_cPathTable.fileSysVerPath[0];//�ļ�·��
	pbCmd[6] = g_cPathTable.fileSysVerPath[1];//�ļ�·��
	cbCmdLen = 7;
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//д��Token Info
	bReturn = cpuUpdateCurrentBinaryFile((BYTE*)&ver, (DWORD)sizeof(ver), 0, TRUE);
	if (!bReturn)
		return FALSE;

	
	//������Կ�ļ�
	cbCmdLen = 12;
	memcpy(pbCmd,"\x80\xE0\x02\x00\x07\x88\x01\x05\x0F\x0f\x06\x19",cbCmdLen);
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	if(ver.dwEF_flag & EF_WRITE_PROTECTED)
	{
		//д��Ӧ��ά����Կ#4()
		memcpy(pbCmd, "\x80\xd4\x00\x00\x18\x01\x01\x00\x05\x0f\x05\x0F\xFF", 13);
		memcpy(pbCmd + 13, g_pbMacKey, 16);
		cbCmdLen = 29;
		bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
		if (!bReturn)
			return FALSE;
	}

	//д���ⲿ��֤��Կ#1(so pin)
	memcpy(pbCmd, "\x80\xd4\x00\x00\x18\x01\x01\x00\x08\x0f\x05\x55", 12);
	pbCmd[12] = soPinMaxRetry;
	memcpy(pbCmd + 13, so_pin, 16);
	cbCmdLen = 29;
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//д���ⲿ��֤��Կ#2(user pin)
	memcpy(pbCmd, "\x80\xd4\x00\x00\x18\x02\x01\x00\x08\x0f\x0a\x4b", 12);
	pbCmd[12] = userPinMaxRetry;
	memcpy(pbCmd + 13, user_pin, 16);
	cbCmdLen = 29;
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//д��SSF33�㷨����Կ#3
	memcpy(pbCmd, "\x80\xd4\x00\x00\x18\x03\x01\x02\x0a\x0f\x00\x0f\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 29);
	cbCmdLen = 29;
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//����token info�ļ�(50 32)
	memcpy(pbCmd,"\x80\xE0\x02\x00\x07\x50\x32\x00\x0f\x0f\x00\x80",12);
	cbCmdLen = 12;
	pbCmd[7] |= bCommProtect;				//��·����
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//ѡ���token info
	memcpy(pbCmd,"\x00\xA4\x02\x00\x02\x50\x32",7);
	cbCmdLen = 7;
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//д��Token Info
	bReturn = cpuUpdateCurrentBinaryFile(baTokenInfo.GetData(), baTokenInfo.GetSize(), 0, TRUE);
	if (!bReturn)
		return FALSE;

	//����FAT
	cbCmdLen = 12;
	memcpy(pbCmd,"\x80\xE0\x02\x00\x07\x50\x33\x00\x0f\x0f\x01\xF7",cbCmdLen);
	pbCmd[7] |= bCommProtect;				//��·����
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;
	
	//ѡ��FAT
	cbCmdLen = 7;
	memcpy(pbCmd,"\x00\xa4\x02\x00\x02\x50\x33",cbCmdLen);
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//дFAT
	cbCmdLen = 8;
	memcpy(pbCmd,"\x00\xd6\x00\x00\x03\x01\x00\x00",cbCmdLen);
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;
	
	//����KeyContainerĿ¼�ļ�
	cbCmdLen = 12;
	memcpy(pbCmd,"\x80\xE0\x02\x00\x07\x60\x80\x00\x0f\x0f\x04\x00",cbCmdLen);
	pbCmd[7] |= bCommProtect;				//��·����
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//ѡ��KeyContainerĿ¼�ļ�
	cbCmdLen = 7;
	memcpy(pbCmd,"\x00\xa4\x02\x00\x02\x60\x80",cbCmdLen);
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//дKeyContainerĿ¼�ļ�
	cbCmdLen = 7;
	memcpy(pbCmd,"\x00\xd6\x00\x00\x02\x00\x00",cbCmdLen);
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//����UserFileĿ¼�ļ�
	cbCmdLen = 12;
	memcpy(pbCmd,"\x80\xE0\x02\x00\x07\x60\x87\x00\x0f\x0f\x02\x00",cbCmdLen);
	pbCmd[7] |= bCommProtect;				//��·����
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//ѡ��UserFileĿ¼�ļ�
	cbCmdLen = 7;
	memcpy(pbCmd,"\x00\xa4\x02\x00\x02\x60\x87",cbCmdLen);
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//дUserFileĿ¼�ļ�
	cbCmdLen = 7;
	memcpy(pbCmd,"\x00\xd6\x00\x00\x02\x00\x00",cbCmdLen);
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

///////////////////////////////////////////////////////////////////////////////////////
	//����һ����Ӧ��Ŀ¼,ר�������ǳ�
	cbCmdLen = 18;
	memcpy(pbCmd,"\x80\xE0\x01\x00\x0d\x2F\x01\x0f\x00\x54\x49\x41\x4E\x59\x55\x43\x53\x50",cbCmdLen);
	/*��������*/
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//����Ӧ��Ŀ¼����
	cbCmdLen = 4;
	memcpy(pbCmd,"\x80\xea\x2f\x01",cbCmdLen);
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;
////////////////////////////////////////////////////////////////////////////////////////

	//�������ļ�����
	cbCmdLen = 4;
	memcpy(pbCmd,"\x80\xea\x3f\x00",cbCmdLen);
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//ѡ�����ļ��½���
	cbCmdLen = 7;
	memcpy(pbCmd,"\x00\xA4\x00\x00\x02\x3F\x00",cbCmdLen);
	bReturn = SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
	if (!bReturn)
		return FALSE;

	//���ɹ���,���ļ��汾��Ϣ��������
	memcpy(&m_FileSys, &ver, sizeof(ver));

	return TRUE;
}



BOOL CCSPReader::cpuEraseE2()
{
	BYTE pbCmd[256];
	DWORD cbCmdLen;
	WORD wStatus;

	//ѡ�����ļ�
	cbCmdLen = 7;
	memcpy(pbCmd, "\x00\xa4\x00\x00\x02\x3f\x00", cbCmdLen);
	SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);

	cbCmdLen = 7;
	memcpy(pbCmd,"\x80\x0e\x00\x00\x02\x3f\x00",cbCmdLen);

	
	return SendCommand(pbCmd, cbCmdLen, NULL, NULL, &wStatus);
}

