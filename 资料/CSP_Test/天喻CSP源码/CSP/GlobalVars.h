#ifndef __TYCSP_GLOBALVARS_H__
#define __TYCSP_GLOBALVARS_H__

/////////////////////////////////////////////////////////////////////

//�ļ���ɾ���ı��
#define DESTROIED_TAG				0xff

//RSA��Կ�Ե����ģ��
#define MAX_RSAKEYPAIR_MODULUS_LEN	1024
//��ԿBlob����󳤶�
#define MAX_RSAPUBKEY_BLOB_LEN		(sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + MAX_RSAKEYPAIR_MODULUS_LEN /8)
//˽ԿBlob����󳤶�
#define MAX_RSAPRIKEY_BLOB_LEN		(sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + (MAX_RSAKEYPAIR_MODULUS_LEN /16)*9) 


/////////////////////////////////////////////////////////////////////
//	����Ψһ��TYCSPManagerʵ��
extern CTYCSPManager g_theTYCSPManager;

/////////////////////////////////////////////////////////////////////
//	����Ψһ��CCSPRandomNumberGeneratorʵ��
extern CCSPRandomNumberGenerator g_rng;

/////////////////////////////////////////////////////////////////////
//	����ȫ����Դƫ����
extern UINT g_nRscOffset;

/////////////////////////////////////////////////////////////////////
//	���ܿ��и��ļ�·�������
struct	_tagPathTable{
    BYTE mfPath[2];				//���ļ���ʶ					
    BYTE dirPath[2];			//Ӧ��Ŀ¼��ʶ
    BYTE tokenInfoPath[2];		//������Ϣ�ļ���ʶ
    BYTE fileTablePath[2];		//FAT���ļ���ʶ

    BYTE prkdfPath[2];			//��Կ����Ŀ¼��ʶ

    BYTE prkStartPath[2];		//˽Կ�ļ���ʼ·��
    BYTE prkexStarPath[2];		//˽Կ��չ�ļ���ʼ·��(��¼��˽Կ��Ӧ�Ĺ�ԿDER����)
    BYTE pukStartPath[2];		//��Կ�ļ���ʼ·��

	BYTE eccprkStartPath[2];		//ecc˽Կ�ļ���ʼ·��
    BYTE eccprkexStarPath[2];		//ecc˽Կ��չ�ļ���ʼ·��(��¼��˽Կ��Ӧ�Ĺ�ԿDER����)
    BYTE eccpukStartPath[2];		//ecc��Կ�ļ���ʼ·��

    BYTE skStartPath[2]	;		//�Գ���Կ��ʼ·��
    BYTE certStartPath[2];		//֤���ļ���ʼ·��
    BYTE dataStartPath[2];		//�û��ļ���ʼ·��

	BYTE fileSysVerPath[2];		//�ļ�ϵͳ�汾��·��

    BYTE eitherNeed;			//
    BYTE free;					//

    BYTE bufSize;				//���ջ���������(������5������ͷ)
    ULONG rsaPukFileLen;		//��Կ�ļ�����
    ULONG rsaPrkFileLen;		//˽Կ�ļ�����
    ULONG rsaPrkExFileLen;		//˽Կ��չ�ļ�����

	ULONG eccPukFileLen;		//��Կ�ļ�����
    ULONG eccPrkFileLen;		//˽Կ�ļ�����
    ULONG eccPrkExFileLen;		//˽Կ��չ�ļ�����


    ULONG fileTableHeadLen;		//FAT��ͷ�ĳ���
    ULONG fileTableRecLen;		//FAT��¼�ĳ���

	ULONG prkAttrLen;			//��Կ����Ŀ¼�м�¼һ��˽Կ���Եĳ���
}; 

extern _tagPathTable g_cPathTable;


extern BYTE g_pbMacKey[];

class CModifyManager;
extern CModifyManager g_ModifyManager;

/////////////////////////////////////////////////////////////////////
//	TYKey Function List

#define g_szTYKEYNAMEBASE _T("Tianyu USB Port Reader")
#include "tykeyint.h"

typedef void (_stdcall* TYKey_Change_PTR)();
typedef void (_stdcall* TYKey_Status_PTR)(
	IN OUT UCHAR* keyStatus
	);
typedef TYKEYSTATUS (_stdcall* TYKey_OpenTYKey_PTR)(
	IN int	nKeyIndex,
	OUT TYKEYHANDLE* hKey
	);
typedef TYKEYSTATUS (_stdcall* TYKey_CloseTYKey_PTR)(
	IN TYKEYHANDLE hKey
	);
typedef TYKEYSTATUS (_stdcall* TYKey_ColdReset_PTR)(
	IN	TYKEYHANDLE	hKey,
	OUT	int* nATRLen,
	OUT unsigned char* pATRContext
	);
typedef TYKEYSTATUS (_stdcall* TYKey_GetATR_PTR)(
	IN	TYKEYHANDLE		hKey,
	OUT	int				*nATRLen,
	OUT unsigned char	*pATRContext
	);
typedef TYKEYSTATUS (_stdcall* TYKey_SendCommand_PTR)(
	IN	TYKEYHANDLE	hKey,
	IN	int	nCommandLen,
	IN	unsigned char* pCommandContext,
	OUT	int* nResponseLen,
	OUT	unsigned char* pResponseContext
	);
typedef int (_stdcall* TYKey_CardExist_PTR)(
	IN TYKEYHANDLE hKey
	);
typedef int (_stdcall* TYKey_KeyExist_PTR)(
	IN TYKEYHANDLE hKey
	);
typedef void (_stdcall* TYKey_BeginTrans_PTR)(
	IN TYKEYHANDLE hKey
	);
typedef void (_stdcall* TYKey_EndTrans_PTR)(
	IN TYKEYHANDLE hKey
	);
struct TYKeyFuncList{
	TYKey_Change_PTR		pfnTYKey_Change;
	TYKey_Status_PTR		pfnTYKey_Status;
	TYKey_OpenTYKey_PTR		pfnTYKey_OpenTYKey;
	TYKey_CloseTYKey_PTR	pfnTYKey_CloseTYKey;
	TYKey_ColdReset_PTR		pfnTYKey_ColdReset;
	TYKey_GetATR_PTR		pfnTYKey_GetATR;
	TYKey_SendCommand_PTR	pfnTYKey_SendCommand;
	TYKey_CardExist_PTR		pfnTYKey_CardExist;
	TYKey_KeyExist_PTR		pfnTYKey_KeyExist;
	TYKey_BeginTrans_PTR	pfnTYKey_BeginTrans;
	TYKey_EndTrans_PTR		pfnTYKey_EndTrans;
};

class CTYkeyFuncHolder{
public:
	CTYkeyFuncHolder(){ m_hDllModule = NULL; }
	~CTYkeyFuncHolder(){ Unload(); }

public:
	TYKeyFuncList	m_listFunc;
public:
	void Load()
	{
		if(m_hDllModule != NULL)
			return;

		memset(&m_listFunc, 0, sizeof(TYKeyFuncList));
		m_hDllModule = LoadLibrary("tykeyint.dll");
		if(m_hDllModule != NULL){
			m_listFunc.pfnTYKey_Change = (TYKey_Change_PTR)GetProcAddress(m_hDllModule, "TYKey_Change");
			m_listFunc.pfnTYKey_Status = (TYKey_Status_PTR)GetProcAddress(m_hDllModule, "TYKey_Status");
			m_listFunc.pfnTYKey_OpenTYKey = (TYKey_OpenTYKey_PTR)GetProcAddress(m_hDllModule, "TYKey_OpenTYKey");
			m_listFunc.pfnTYKey_CloseTYKey = (TYKey_CloseTYKey_PTR)GetProcAddress(m_hDllModule, "TYKey_CloseTYKey");
			m_listFunc.pfnTYKey_ColdReset = (TYKey_ColdReset_PTR)GetProcAddress(m_hDllModule, "TYKey_ColdReset");
			m_listFunc.pfnTYKey_GetATR = (TYKey_GetATR_PTR)GetProcAddress(m_hDllModule, "TYKey_GetATR");
			m_listFunc.pfnTYKey_SendCommand = (TYKey_SendCommand_PTR)GetProcAddress(m_hDllModule, "TYKey_SendCommand");
			m_listFunc.pfnTYKey_CardExist = (TYKey_CardExist_PTR)GetProcAddress(m_hDllModule, "TYKey_CardExist");
			m_listFunc.pfnTYKey_KeyExist = (TYKey_KeyExist_PTR)GetProcAddress(m_hDllModule, "TYKey_KeyExist");
			m_listFunc.pfnTYKey_BeginTrans = (TYKey_BeginTrans_PTR)GetProcAddress(m_hDllModule, "TYKey_BeginTransEx");
			m_listFunc.pfnTYKey_EndTrans = (TYKey_EndTrans_PTR)GetProcAddress(m_hDllModule, "TYKey_EndTransEx");
		}
		else{
			DWORD dwErr = GetLastError();
		}
	}
	void Unload()
	{
		if(m_hDllModule != NULL)
			FreeLibrary(m_hDllModule);
		m_hDllModule = NULL;
	}

private:
	HMODULE			m_hDllModule;
};

extern CTYkeyFuncHolder g_TYKeyFuncHolder;

/////////////////////////////////////////////////////////////////////
//	SCard  Function List

typedef LONG (WINAPI* SCardEstablishContext_PTR)(
    IN DWORD dwScope,
    IN LPCVOID pvReserved1,
    IN LPCVOID pvReserved2,
    OUT LPSCARDCONTEXT phContext
	);
typedef LONG (WINAPI* SCardReleaseContext_PTR)(
    IN SCARDCONTEXT hContext
	);
typedef LONG (WINAPI* SCardListReaders_PTR)(
    IN SCARDCONTEXT hContext,
    IN LPCSTR mszGroups,
    OUT LPSTR mszReaders,
    IN OUT LPDWORD pcchReaders
	);
typedef LONG (WINAPI* SCardFreeMemory_PTR)(
    IN SCARDCONTEXT hContext,
    IN LPVOID pvMem
	);
typedef LONG (WINAPI* SCardConnect_PTR)(
    IN SCARDCONTEXT hContext,
    IN LPCSTR szReader,
    IN DWORD dwShareMode,
    IN DWORD dwPreferredProtocols,
    OUT LPSCARDHANDLE phCard,
    OUT LPDWORD pdwActiveProtocol
	);
typedef LONG (WINAPI* SCardReconnect_PTR)(
    IN SCARDHANDLE hCard,
    IN DWORD dwShareMode,
    IN DWORD dwPreferredProtocols,
    IN DWORD dwInitialization,
    OUT LPDWORD pdwActiveProtocol
	);
typedef LONG (WINAPI* SCardDisconnect_PTR)(
    IN SCARDHANDLE hCard,
    IN DWORD dwDisposition
	);
typedef LONG (WINAPI* SCardBeginTransaction_PTR)(
    IN SCARDHANDLE hCard
	);
typedef LONG (WINAPI* SCardEndTransaction_PTR)(
    IN SCARDHANDLE hCard,
    IN DWORD dwDisposition
	);
typedef LONG (WINAPI* SCardStatus_PTR)(
    IN SCARDHANDLE hCard,
    OUT LPSTR szReaderName,
    IN OUT LPDWORD pcchReaderLen,
    OUT LPDWORD pdwState,
    OUT LPDWORD pdwProtocol,
    OUT LPBYTE pbAtr,
    OUT LPDWORD pcbAtrLen
	);
typedef LONG (WINAPI* SCardTransmit_PTR)(
    IN SCARDHANDLE hCard,
    IN LPCSCARD_IO_REQUEST pioSendPci,
    IN LPCBYTE pbSendBuffer,
    IN DWORD cbSendLength,
    IN OUT LPSCARD_IO_REQUEST pioRecvPci,
    OUT LPBYTE pbRecvBuffer,
    IN OUT LPDWORD pcbRecvLength
	);
typedef LONG (WINAPI* SCardGetAttrib_PTR)(
    IN SCARDHANDLE hCard,
    IN DWORD dwAttrId,
    OUT LPBYTE pbAttr,
    IN OUT LPDWORD pcbAttrLen
	);
typedef LONG (WINAPI* SCardLocateCards_PTR)(
    IN SCARDCONTEXT hContext,
    IN LPCSTR mszCards,
    IN OUT LPSCARD_READERSTATE_A rgReaderStates,
    IN DWORD cReaders
	);
typedef LONG (WINAPI* SCardListCards_PTR)(
    IN SCARDCONTEXT hContext,
    IN LPCBYTE pbAtr,
    IN LPCGUID rgquidInterfaces,
    IN DWORD cguidInterfaceCount,
    OUT LPSTR mszCards,
    IN OUT LPDWORD pcchCards
	);
typedef LONG (WINAPI* SCardForgetCardType_PTR)(
    IN SCARDCONTEXT hContext,
    IN LPCSTR szCardName
	);
typedef LONG (WINAPI* SCardGetStatusChange_PTR)(
    IN SCARDCONTEXT hContext,
    IN DWORD dwTimeout,
    IN OUT LPSCARD_READERSTATE_A rgReaderStates,
    IN DWORD cReaders);

struct SCardFuncList{
	SCardEstablishContext_PTR		pfnSCardEstablishContext;
	SCardReleaseContext_PTR			pfnSCardReleaseContext;
	SCardListReaders_PTR			pfnSCardListReaders;
	SCardFreeMemory_PTR				pfnSCardFreeMemory;
	SCardConnect_PTR				pfnSCardConnect;
	SCardReconnect_PTR				pfnSCardReconnect;
	SCardDisconnect_PTR				pfnSCardDisconnect;
	SCardBeginTransaction_PTR		pfnSCardBeginTransaction;
	SCardEndTransaction_PTR			pfnSCardEndTransaction;
	SCardStatus_PTR					pfnSCardStatus;
	SCardTransmit_PTR				pfnSCardTransmit;
	SCardGetAttrib_PTR				pfnSCardGetAttrib;
	SCardLocateCards_PTR			pfnSCardLocateCards;
	SCardListCards_PTR				pfnSCardListCards;
	SCardForgetCardType_PTR			pfnSCardForgetCardType;
	SCardGetStatusChange_PTR		pfnSCardGetStatusChange;
	};

class CSCardFuncHolder{
public:
	CSCardFuncHolder(){ m_hDllModule = NULL; }
	~CSCardFuncHolder(){ Unload(); }

public:
	SCardFuncList m_listFunc;
	LPCSCARD_IO_REQUEST	pcSCardT0Pci;

public:
	void Load()
	{
		if(m_hDllModule != NULL)
			return;

		memset(&m_listFunc, 0, sizeof(SCardFuncList));
		m_hDllModule = LoadLibrary("winscard.dll");
		if(m_hDllModule != NULL){
			m_listFunc.pfnSCardEstablishContext = (SCardEstablishContext_PTR)GetProcAddress(m_hDllModule, "SCardEstablishContext");
			m_listFunc.pfnSCardReleaseContext = (SCardReleaseContext_PTR)GetProcAddress(m_hDllModule, "SCardReleaseContext");
			m_listFunc.pfnSCardListReaders = (SCardListReaders_PTR)GetProcAddress(m_hDllModule, "SCardListReadersA");
			m_listFunc.pfnSCardFreeMemory = (SCardFreeMemory_PTR)GetProcAddress(m_hDllModule, "SCardFreeMemory");
			m_listFunc.pfnSCardConnect = (SCardConnect_PTR)GetProcAddress(m_hDllModule, "SCardConnectA");
			m_listFunc.pfnSCardReconnect = (SCardReconnect_PTR)GetProcAddress(m_hDllModule, "SCardReconnect");
			m_listFunc.pfnSCardDisconnect = (SCardDisconnect_PTR)GetProcAddress(m_hDllModule, "SCardDisconnect");
			m_listFunc.pfnSCardBeginTransaction = (SCardBeginTransaction_PTR)GetProcAddress(m_hDllModule, "SCardBeginTransaction");
			m_listFunc.pfnSCardEndTransaction = (SCardEndTransaction_PTR)GetProcAddress(m_hDllModule, "SCardEndTransaction");
			m_listFunc.pfnSCardStatus = (SCardStatus_PTR)GetProcAddress(m_hDllModule, "SCardStatusA");
			m_listFunc.pfnSCardTransmit = (SCardTransmit_PTR)GetProcAddress(m_hDllModule, "SCardTransmit");
			m_listFunc.pfnSCardGetAttrib = (SCardGetAttrib_PTR)GetProcAddress(m_hDllModule, "SCardGetAttrib");
			m_listFunc.pfnSCardLocateCards = (SCardLocateCards_PTR)GetProcAddress(m_hDllModule, "SCardLocateCardsA");
			m_listFunc.pfnSCardListCards = (SCardListCards_PTR)GetProcAddress(m_hDllModule, "SCardListCardsA");
			m_listFunc.pfnSCardForgetCardType = (SCardForgetCardType_PTR)GetProcAddress(m_hDllModule, "SCardForgetCardTypeA");
			pcSCardT0Pci = (LPCSCARD_IO_REQUEST)GetProcAddress(m_hDllModule, "g_rgSCardT0Pci");
			m_listFunc.pfnSCardGetStatusChange = (SCardGetStatusChange_PTR)GetProcAddress(m_hDllModule, "SCardGetStatusChangeA");
		}
	}
	void Unload()
	{
		if(m_hDllModule != NULL)
			FreeLibrary(m_hDllModule);
		m_hDllModule = NULL;
	}

private:
	HMODULE			m_hDllModule;
};

extern CSCardFuncHolder g_SCardFuncHolder;


/////////////////////////////////////////////////////////////////////
//	TYReader  Function List

#define g_szTYREADERNAMEBASE _T("Tianyu Serial Port Reader")

#include "TYRD32.H"

typedef int (WINAPI* TY_Open_PTR)(
	IN DWORD dwBaudRate, 
	IN DWORD dwComPort
	);
typedef WORD (WINAPI* TY_Close_PTR)(
	IN int hReader
	);
typedef WORD (WINAPI* TY_reset_PTR)(
	IN int hReader,
	OUT WORD* pwATRLen,
	OUT BYTE* pbATR
	);
typedef WORD (WINAPI* TY_tsi_api_PTR)(
	IN int hReader, 
	IN WORD wCmdLen,
	IN BYTE* pbCmd,
	OUT WORD* pwRespLen,
	OUT BYTE* pbResp
	);
typedef WORD (WINAPI* TY_CardExist_PTR)(
	IN int hReader
	);
typedef WORD (WINAPI* TY_GetATR_PTR)(
	IN int hReader,
	OUT WORD* pwATRLen,
	OUT BYTE* pbATR
	);
typedef void (WINAPI* TY_BeginTrans_PTR)(
	IN int hReader
	);
typedef void (WINAPI* TY_EndTrans_PTR)(
	IN int hReader
	);
typedef void (WINAPI* TY_Status_PTR)(
	IN BYTE* pbStatus
	);
typedef int (WINAPI* TY_GetOpenedHandle_PTR)(
	IN DWORD dwComPort
	);

struct TYReaderFuncList{
	TY_Open_PTR			pfnTY_Open;
	TY_Close_PTR		pfnTY_Close;
	TY_reset_PTR		pfnTY_reset;
	TY_tsi_api_PTR		pfnTY_tsi_api;
	TY_CardExist_PTR	pfnTY_CardExist;
	TY_GetATR_PTR		pfnTY_GetATR;
	TY_BeginTrans_PTR	pfnTY_BeginTrans;
	TY_EndTrans_PTR		pfnTY_EndTrans;
	TY_Status_PTR		pfnTY_Status;
	TY_GetOpenedHandle_PTR pfnTY_GetOpenedHandle;
};

class CTYReaderFuncHolder{
public:
	CTYReaderFuncHolder(){ m_hDllModule = NULL; }
	~CTYReaderFuncHolder(){ Unload(); }

public:
	TYReaderFuncList	m_listFunc;
	
public:
	void Load()
	{
		if(m_hDllModule != NULL)
			return;

		memset(&m_listFunc, 0, sizeof(TYReaderFuncList));
		m_hDllModule = LoadLibrary("tyrd32.dll");
		if(m_hDllModule != NULL){
			m_listFunc.pfnTY_Open = (TY_Open_PTR)GetProcAddress(m_hDllModule, "TY_Open");
			m_listFunc.pfnTY_Close = (TY_Close_PTR)GetProcAddress(m_hDllModule, "TY_Close");
			m_listFunc.pfnTY_reset = (TY_reset_PTR)GetProcAddress(m_hDllModule, "TY_reset");
			m_listFunc.pfnTY_tsi_api = (TY_tsi_api_PTR)GetProcAddress(m_hDllModule, "TY_tsi_api");
			m_listFunc.pfnTY_CardExist = (TY_CardExist_PTR)GetProcAddress(m_hDllModule, "TY_CardExist");
			m_listFunc.pfnTY_GetATR = (TY_GetATR_PTR)GetProcAddress(m_hDllModule, "TY_GetATR");
			m_listFunc.pfnTY_BeginTrans = (TY_BeginTrans_PTR)GetProcAddress(m_hDllModule, "TY_BeginTrans");
			m_listFunc.pfnTY_EndTrans = (TY_EndTrans_PTR)GetProcAddress(m_hDllModule, "TY_EndTrans");
			m_listFunc.pfnTY_Status = (TY_Status_PTR)GetProcAddress(m_hDllModule, "TY_Status");
			m_listFunc.pfnTY_GetOpenedHandle = (TY_GetOpenedHandle_PTR)GetProcAddress(m_hDllModule, "TY_GetOpenedHandle");
		}
	}
	void Unload()
	{
		if(m_hDllModule != NULL)
			FreeLibrary(m_hDllModule);
		m_hDllModule = NULL;
		memset(&m_listFunc, 0, sizeof(TYReaderFuncList));
	}

private:
	HMODULE			m_hDllModule;
};

extern CTYReaderFuncHolder g_TYReaderFuncHolder;

#endif