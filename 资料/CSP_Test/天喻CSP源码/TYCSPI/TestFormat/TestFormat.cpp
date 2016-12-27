// TestFormat.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "stdio.h"

//#include "../tycspi/tycspI.h"
#include "../ref/tycspi.h"
#ifdef _DEBUG
#pragma comment(lib, "..\\debug\\tycspid.lib")
#else
#pragma comment(lib, "..\\release\\tycspi.lib")
#endif

int main(int argc, char* argv[])
{ 
	//������ʽ����Ϣ
	FORMATINFO info;
	memset(&info, 0, sizeof(info));
	//�û�PIN��Ϣ
	info.userPIN = (LPBYTE)"12345678";
	info.userPINLen = 8;
	info.userPINMaxRetry = 0xFF;
	//����ԱPIN��Ϣ
	info.soPIN = (LPBYTE)"12345600";
	info.soPINLen = 8;
	info.soPINMaxRetry = 0xFF;
	//Token��Ϣ
	memcpy(info.tokenInfo.manufacturerID, "WuHan Tianyu", 12);
	memcpy(info.tokenInfo.model, "USB TOKEN", 9);
	memcpy(info.tokenInfo.label, "Chenji", 6);
	memcpy(info.tokenInfo.serialNumber, "1234567890123456", 16);

	//��ָʾ��

	//��ʽ��
	BOOL rv = CPFormat2(0, &info);
	CPFinalize2(0);

	return 1;
}
