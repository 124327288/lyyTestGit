#ifndef __TYRD32_H__
#define __TYRD32_H__

#ifdef __cplusplus
extern "C" {
#endif
	
//所支持的最大串口数目
#define MAX_COMPORT_NUM					2

#define TYREADER_STATUS_NOREADER		-1
#define TYREADER_STATUS_SUCCESS			0x9000
#define TYREADER_STATUS_NOCARD			0x8500
#define TYREADER_STATUS_NORESET			0x9200

int WINAPI TY_Open(DWORD dwBaudRate, DWORD dwComPort);
WORD WINAPI TY_Close(int hReader);
WORD WINAPI TY_reset(int hReader, WORD* pwATRLen, BYTE* pbATR);
WORD WINAPI TY_tsi_api(int hReader, WORD wCmdLen, BYTE* pbCmd, WORD* pwRespLen, BYTE* pbResp);
WORD WINAPI TY_CardExist(int hReader);

WORD WINAPI TY_GetATR(int hReader, WORD* pwATRLen, BYTE* pbATR);
void WINAPI TY_BeginTrans(int hReader);
void WINAPI TY_EndTrans(int hReader);

void WINAPI TY_Status(BYTE* pbStatus);
int WINAPI TY_GetOpenedHandle(DWORD dwComPort);

#ifdef __cplusplus
}       // Balance extern "C" above
#endif

#endif