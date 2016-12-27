#include "stdafx.h"
#include "reader.h"
#include "md5.h"
#include "des.h"
#include "HelperFunc.h"
#include "Mac.h"

/////////////////////////////////////////////////////////////////////
//	���ֿ�Ƭ��ATR����

//����MAC����Կ, д��KEY����Ӧ��ά����Կ
BYTE g_pbMacKey[] = {0x98, 0xAE, 0xAA, 0x9A, 0x6F, 0xE2, 0x5E, 0xF5, 0x62, 0x19, 0xBE, 0x31, 0x9E, 0x01, 0xF3, 0x7F};

#define MAKEFILEID(path) MAKEWORD((path)[1], (path)[0])

/////////////////////////////////////////////////////////////////////
//	TYKey Function Holder
//
CTYkeyFuncHolder g_TYKeyFuncHolder;

/////////////////////////////////////////////////////////////////////
//	SCard Function Holder
//
CSCardFuncHolder g_SCardFuncHolder;


/////////////////////////////////////////////////////////////////////
//	TYReader Function Holder
//
CTYReaderFuncHolder g_TYReaderFuncHolder;

//-------------------------------------------------------------------
//	���ܣ�
//		���캯��
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
CCSPReader::CCSPReader()
{
	//��Ա������ʼ��
	m_hSC = NULL;
	m_hCard = NULL;
	m_cardType = NOCARD;
	m_szName = NULL;
	m_nIndex = -1;
	m_readerType = RT_UNKNOWN;
	m_pTokenInfo = NULL;

	memset(&m_FileSys, 0, sizeof(m_FileSys));
	m_FileSys.wFileSysVer = CSP_FILE_SYS_VERSION;
	m_FileSys.dwEF_flag &= EF_WRITE_PROTECTED;
	m_FileSys.wDF_flag &= DF_CSP_IN_MF;
	
	//������Դ������
	EstablishContext();
}

//-------------------------------------------------------------------
//	���ܣ�
//		��������
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
CCSPReader::~CCSPReader()
{
	ClearTokenInfoBuffer();

	ReleaseContext();
	//��ն�����������
	SetName(NULL);
}

//
//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ�ļ�ϵͳ�汾��Ϣ
//
//	���أ�
//		�ɹ������ļ�������,���سɹ�,�쳣�������ʧ��
//
//  ������
//		��
//
//  ˵�������û�ж�������ļ�,�Ѱ汾���赽�ɰ汾����
//-------------------------------------------------------------------
BOOL CCSPReader::ReadFileSysVer()
{
	BYTE pbResp[256] = {0};
	DWORD dwLen = (DWORD)sizeof(m_FileSys);
	
	if(cpuSelectEF(g_cPathTable.fileSysVerPath) && cpuReadCurrentBinaryFile(pbResp, dwLen))
		memcpy(&m_FileSys, pbResp, dwLen);
	else
		memset(&m_FileSys, 0, sizeof(m_FileSys));

	return TRUE;
}
//
//-------------------------------------------------------------------
//	���ܣ�
//		����ļ�ϵͳ�汾��Ϣ, ����һ����Ϣ�ṹָ��
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
void CCSPReader::GetFileSysVer(LPCSP_FILESYS_VER pFileSysVer)
{
	memcpy(pFileSysVer, &m_FileSys, sizeof(m_FileSys));
}
//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ����������������
//
//	���أ�
//		����������������
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
int CCSPReader::GetRealIndex()
{
	return (m_nIndex - ((int)GetType())*1000);
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ջ����Token��Ϣ
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
void CCSPReader::ClearTokenInfoBuffer()
{
	if(m_pTokenInfo != NULL){
		delete m_pTokenInfo;
		m_pTokenInfo = NULL;
	}
}

//-------------------------------------------------------------------
//	���ܣ�
//		��������
//
//	���أ�
//		��
//
//  ������
//		int nIndex	����
//
//  ˵����
//-------------------------------------------------------------------
void CCSPReader::SetIndex(int nIndex)
{
	m_nIndex = nIndex;

	if(GetType() == RT_USBPORT){
		TCHAR szName[MAX_PATH];
		_stprintf(szName, "%s %d", g_szTYKEYNAMEBASE, GetRealIndex());
		SetName(szName);
	}
	else if(GetType() == RT_COMPORT){
		TCHAR szName[MAX_PATH];
		_stprintf(szName, "%s %d", g_szTYREADERNAMEBASE, GetRealIndex());
		SetName(szName);
	}
}

//-------------------------------------------------------------------
//	���ܣ�
//		��������
//
//	���أ�
//		��
//
//  ������
//		LPCTSTR szName	����
//
//  ˵����
//-------------------------------------------------------------------
void CCSPReader::SetName(LPCTSTR szName)
{
	if(m_szName != NULL){
		delete m_szName;
		m_szName = NULL;
	}

	if(szName){
		int nLen = lstrlen(szName);
		m_szName = new TCHAR[nLen + 1];
		if(m_szName) lstrcpy(m_szName, szName);
	}
}

//-------------------------------------------------------------------
//	���ܣ�
//		������Դ������
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		DWORD dwScope	��Χ
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::EstablishContext(
	DWORD dwScope /*= SCARD_SCOPE_USER */
	)
{
	if(m_hSC != NULL)
		return TRUE;

	if(g_SCardFuncHolder.m_listFunc.pfnSCardEstablishContext == NULL)
		return FALSE;

	LONG lResult = g_SCardFuncHolder.m_listFunc.pfnSCardEstablishContext(
		dwScope, NULL, NULL, &m_hSC
		);
	return (lResult == SCARD_S_SUCCESS);
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ͷ���Դ������
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::ReleaseContext()
{
	if(m_hSC == NULL)
		return TRUE;

	if(g_SCardFuncHolder.m_listFunc.pfnSCardReleaseContext == NULL)
		return FALSE;

	LONG lResult = g_SCardFuncHolder.m_listFunc.pfnSCardReleaseContext(m_hSC);
	if(lResult == SCARD_S_SUCCESS){
		m_hSC = NULL;
		return TRUE;
	}
	else{
		TRACE_ERROR(lResult);
		return FALSE;
	}
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ʼһ������
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::BeginTransaction()
{
	if(!IsConnectCard())
		return FALSE;

	if(GetType() == RT_PCSC){
		if(g_SCardFuncHolder.m_listFunc.pfnSCardBeginTransaction == NULL ||
			g_SCardFuncHolder.m_listFunc.pfnSCardEndTransaction == NULL)
			return FALSE;
		LONG lResult = g_SCardFuncHolder.m_listFunc.pfnSCardBeginTransaction(
			(SCARDHANDLE)m_hCard
			);
		return (lResult == SCARD_S_SUCCESS);
	}
	else if(GetType() == RT_USBPORT){
		if(GetCardType() == CPU_PKI){
			if(g_TYKeyFuncHolder.m_listFunc.pfnTYKey_BeginTrans == NULL ||
				g_TYKeyFuncHolder.m_listFunc.pfnTYKey_EndTrans == NULL)
				return FALSE;
			g_TYKeyFuncHolder.m_listFunc.pfnTYKey_BeginTrans((TYKEYHANDLE)m_hCard);
		}
		else{
			return FALSE;
		}
		return TRUE;
	}
	else if(GetType() == RT_COMPORT){
		if(g_TYReaderFuncHolder.m_listFunc.pfnTY_BeginTrans == NULL ||
			g_TYReaderFuncHolder.m_listFunc.pfnTY_EndTrans == NULL)
			return FALSE;

		g_TYReaderFuncHolder.m_listFunc.pfnTY_BeginTrans((int)m_hCard);
		return TRUE;
	}
	else
		return FALSE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		����һ������
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		DWORD dwDisposition	��������ʱ�Կ�����������
//
//  ˵����
//		dwDisposition��ȡ����ֵ
//
//		ֵ					���� 
//		SCARD_LEAVE_CARD	�����κδ��� 
//		SCARD_RESET_CARD	������λ 
//		SCARD_UNPOWER_CARD  �����µ� 
//		SCARD_EJECT_CARD	�������� 
//-------------------------------------------------------------------
BOOL
CCSPReader::EndTransaction(
	DWORD dwDisposition /*=SCARD_LEAVE_CARD*/
	)
{
	if(!IsConnectCard())
		return FALSE;

	if(GetType() == RT_PCSC){
		if(g_SCardFuncHolder.m_listFunc.pfnSCardEndTransaction == NULL)
			return FALSE;
		LONG lResult = g_SCardFuncHolder.m_listFunc.pfnSCardEndTransaction(
			(SCARDHANDLE)m_hCard, dwDisposition
			);
		return (lResult == SCARD_S_SUCCESS);
	}
	else if(GetType() == RT_USBPORT){
		if(GetCardType() == CPU_PKI){
			if(g_TYKeyFuncHolder.m_listFunc.pfnTYKey_EndTrans == NULL)
				return FALSE;
			g_TYKeyFuncHolder.m_listFunc.pfnTYKey_EndTrans((TYKEYHANDLE)m_hCard);
		}
		else{
			return FALSE;
		}
		return TRUE;
	}
	else if(GetType() == RT_COMPORT){
		if(g_TYReaderFuncHolder.m_listFunc.pfnTY_EndTrans == NULL)
			return FALSE;
		g_TYReaderFuncHolder.m_listFunc.pfnTY_EndTrans((int)m_hCard);
		return TRUE;
	}
	else
		return FALSE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��λ	 
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		BYTE* pbATR			ATR����
//		DWORD* pdwATR		ATR�ĳ���
//		ResetMode mode		��λģʽ
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::Reset(
	BYTE* pbATR,
	DWORD* pdwATR,
	ResetMode mode /*=WARM*/
	)
{
	//���δ�������ܿ����Ƚ��������ܿ�������
	if(!IsConnectCard()){
		if(!ConnectCard(FALSE))
			return FALSE;
	}

	//��ȡ��λ��Ϣ
	BOOL bRetVal = FALSE;
	BYTE cATR[256];
	DWORD dwATRBufferLen = sizeof(cATR);
	if(GetType() == RT_PCSC){
		if(g_SCardFuncHolder.m_listFunc.pfnSCardGetAttrib){
			DWORD dwProtocol = 0;
			LONG lResult = SCARD_S_SUCCESS;
			if(COLD == mode)
				lResult = g_SCardFuncHolder.m_listFunc.pfnSCardReconnect(
						(SCARDHANDLE)m_hCard, 
						SCARD_SHARE_SHARED, 
						SCARD_PROTOCOL_T0, 
						SCARD_RESET_CARD, 
						&dwProtocol);
			if(lResult == SCARD_S_SUCCESS)
				lResult = g_SCardFuncHolder.m_listFunc.pfnSCardGetAttrib(
					(SCARDHANDLE)m_hCard, SCARD_ATTR_ATR_STRING, cATR, &dwATRBufferLen
					);
			bRetVal = (lResult == SCARD_S_SUCCESS);
		}
	}
	else if(GetType() == RT_USBPORT){
		if(g_TYKeyFuncHolder.m_listFunc.pfnTYKey_GetATR){
			TYKEYSTATUS status = g_TYKeyFuncHolder.m_listFunc.pfnTYKey_GetATR(
				(TYKEYHANDLE)m_hCard, (int* )&dwATRBufferLen, cATR
				);
			if(status == STATUS_TYKEY_SUCCESS)
				bRetVal = TRUE;
			else{
				if(g_TYKeyFuncHolder.m_listFunc.pfnTYKey_ColdReset){
					//���ܴ�δ���й��临λ,��������һ���临λ
					//(��Զ����������ܿ���Ӳ����״̬)
					status = g_TYKeyFuncHolder.m_listFunc.pfnTYKey_ColdReset(
						(TYKEYHANDLE)m_hCard, (int* )&dwATRBufferLen, cATR
						);
					bRetVal = (status == STATUS_TYKEY_SUCCESS);
				}
			}
		}
	}
	else if(GetType() == RT_COMPORT){
		if(g_TYReaderFuncHolder.m_listFunc.pfnTY_GetATR){
			WORD status = g_TYReaderFuncHolder.m_listFunc.pfnTY_GetATR(
				(int)m_hCard, (WORD* )&dwATRBufferLen, cATR
				);
			bRetVal = (status == TYREADER_STATUS_SUCCESS);
		}
	}

	if(bRetVal && pbATR != NULL && pdwATR != NULL){
		*pdwATR = dwATRBufferLen;
		memcpy(pbATR, cATR, dwATRBufferLen);

		TRACE_LINE("��λ��Ϣ:\n");
		TRACE_DATA(pbATR, dwATRBufferLen);
	}

	if(!bRetVal){
		TRACE_LINE("Fail to get ATR!\n");
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡATR��Ϣ
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		BYTE* pbATR				���ص�ATR
//		DWORD* pdwATR			���ص�ATR�ĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::GetATR(BYTE* pbATR, DWORD* pdwATR)
{
	if(!IsConnectCard()){
		return FALSE;
	}

	//��ȡ��λ��Ϣ
	BOOL bRetVal = FALSE;
	BYTE cATR[256];
	DWORD dwATRBufferLen = sizeof(cATR);
	if(GetType() == RT_PCSC){
		if(g_SCardFuncHolder.m_listFunc.pfnSCardGetAttrib){
			LONG lResult = g_SCardFuncHolder.m_listFunc.pfnSCardGetAttrib(
				(SCARDHANDLE)m_hCard, SCARD_ATTR_ATR_STRING, cATR, &dwATRBufferLen
				);
			bRetVal = (lResult == SCARD_S_SUCCESS);
		}
	}
	else if(GetType() == RT_USBPORT){
		if(g_TYKeyFuncHolder.m_listFunc.pfnTYKey_GetATR){
			TYKEYSTATUS status = g_TYKeyFuncHolder.m_listFunc.pfnTYKey_GetATR(
				(TYKEYHANDLE)m_hCard, (int* )&dwATRBufferLen, cATR
				);
			if(status == STATUS_TYKEY_SUCCESS)
				bRetVal = TRUE;
			else{
				bRetVal = FALSE;
			}
		}
	}
	else if(GetType() == RT_COMPORT){
		if(g_TYReaderFuncHolder.m_listFunc.pfnTY_GetATR){
			WORD status = g_TYReaderFuncHolder.m_listFunc.pfnTY_GetATR(
				(int)m_hCard, (WORD* )&dwATRBufferLen, cATR
				);
			bRetVal = (status == TYREADER_STATUS_SUCCESS);
		}
	}

	if(bRetVal && pbATR != NULL && pdwATR != NULL){
		*pdwATR = dwATRBufferLen;
		memcpy(pbATR, cATR, dwATRBufferLen);

		TRACE_LINE("��λ��Ϣ:\n");
		TRACE_DATA(pbATR, dwATRBufferLen);
	}

	if(!bRetVal){
		TRACE_LINE("Fail to get ATR!\n");
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�������ܿ�
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		BOOL bCheckCardValid	�Ƿ��⿨�ĺϷ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::ConnectCard(BOOL bCheckCardValid)
{
	//��������ӣ�ֱ�ӷ���
	if(IsConnectCard())
		return TRUE;

	//�������ܿ�
	BOOL bRetVal = FALSE;
	if(GetType() == RT_PCSC){
		int nCount = 5;
		while(nCount){
			if(m_hSC != NULL && g_SCardFuncHolder.m_listFunc.pfnSCardConnect != NULL){
				TRACE_LINE("Connect Reader:%s ", m_szName);
				DWORD dwActiveProtocol;
				LONG lResult = g_SCardFuncHolder.m_listFunc.pfnSCardConnect(
					m_hSC, m_szName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, (SCARDHANDLE*)&m_hCard, &dwActiveProtocol
					);
				bRetVal = (lResult == SCARD_S_SUCCESS);
			}
			if(bRetVal){
				TRACE_LINE("Success!\n");
				break;
			}
			else{
				TRACE_LINE("Fail!\n");
			}
			Sleep(200);
			nCount--;
		}
	}
	else if(GetType() == RT_USBPORT){
		if(g_TYKeyFuncHolder.m_listFunc.pfnTYKey_OpenTYKey && 
			g_TYKeyFuncHolder.m_listFunc.pfnTYKey_CloseTYKey &&
			g_TYKeyFuncHolder.m_listFunc.pfnTYKey_CardExist)
		{
			//�򿪶�����
			TYKEYHANDLE hTYKey = NULL;
			TYKEYSTATUS status = g_TYKeyFuncHolder.m_listFunc.pfnTYKey_OpenTYKey(
				GetRealIndex(), &hTYKey
				);
			
			//�ж����ܿ��Ƿ����
			if(status == STATUS_TYKEY_SUCCESS){
				int nExistFlag = g_TYKeyFuncHolder.m_listFunc.pfnTYKey_CardExist(hTYKey);
				if(nExistFlag){
					m_hCard = (CARDHANDLE)hTYKey;
					bRetVal = TRUE;
				}
				else{
					//�رն�����
					g_TYKeyFuncHolder.m_listFunc.pfnTYKey_CloseTYKey(hTYKey);
				}
			}
		}
	}
	else if(GetType() == RT_COMPORT){
		if(g_TYReaderFuncHolder.m_listFunc.pfnTY_Open && 
			g_TYReaderFuncHolder.m_listFunc.pfnTY_CardExist &&
			g_TYReaderFuncHolder.m_listFunc.pfnTY_Close)
		{
			//�򿪶�����
			int hReader = g_TYReaderFuncHolder.m_listFunc.pfnTY_Open(57600, GetRealIndex());

			//�ж����ܿ��Ƿ����
			if(hReader > 0){
				WORD status = g_TYReaderFuncHolder.m_listFunc.pfnTY_CardExist(hReader);
				if(status == TYREADER_STATUS_SUCCESS){
					m_hCard = hReader;
					bRetVal = TRUE;
				}
				else{
					//�رն�����
					g_TYReaderFuncHolder.m_listFunc.pfnTY_Close(hReader);
				}
			}
		}
	}

	if(!bRetVal)
		return FALSE;

	//��ȡATR,��������Ƭ����
	BYTE pbATR[256];
	DWORD dwATRLen = sizeof(pbATR);
	bRetVal = Reset(pbATR, &dwATRLen);
	if(!bRetVal)
		return FALSE;
	m_cardType = CPU_PKI;

	if(bRetVal){
		BeginTransaction();
		{
			if(!ReadFileSysVer())
			{
				bRetVal = FALSE;
			}
			else if(!(m_FileSys.wDF_flag & DF_CSP_IN_MF))
			{
				//����Ƿ�Ϊ�Ϸ������ܿ�
				if(!cpuSelectDF(TYCSP) && bCheckCardValid)
					bRetVal = FALSE;
			}

			if(bRetVal){
				//�������е�FAT�ļ�
				cpuInitFatFile();
				bRetVal =  cpuReadFatFile();
				if(!bCheckCardValid)
					bRetVal = TRUE;
			}
		}

		EndTransaction();
	}

	if(!bRetVal){
		if(GetType() == RT_PCSC){
			if(g_SCardFuncHolder.m_listFunc.pfnSCardDisconnect){
				g_SCardFuncHolder.m_listFunc.pfnSCardDisconnect(
					(SCARDHANDLE)m_hCard, SCARD_LEAVE_CARD
					);
			}
		}
		else if(GetType() == RT_USBPORT){
			if(GetCardType() == CPU_PKI){
				if(g_TYKeyFuncHolder.m_listFunc.pfnTYKey_CloseTYKey){
					g_TYKeyFuncHolder.m_listFunc.pfnTYKey_CloseTYKey(
						(TYKEYHANDLE)m_hCard
						);
				}
			}
		}
		else if(GetType() == RT_COMPORT){
			if(g_TYReaderFuncHolder.m_listFunc.pfnTY_Close){
				g_TYReaderFuncHolder.m_listFunc.pfnTY_Close((int)m_hCard);
			}
		}
		m_hCard = NULL;
		ClearTokenInfoBuffer();
		m_cardType = NOCARD;
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�Ͽ������ܿ�������
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::DisconnectCard()
{
	if(!IsConnectCard())
		return TRUE;

	if(GetType() == RT_PCSC){
		if(g_SCardFuncHolder.m_listFunc.pfnSCardDisconnect){
			g_SCardFuncHolder.m_listFunc.pfnSCardDisconnect(
				(SCARDHANDLE)m_hCard, SCARD_LEAVE_CARD
				);
		}
	}
	else if(GetType() == RT_USBPORT){
		if(GetCardType() == CPU_PKI){
			if(g_TYKeyFuncHolder.m_listFunc.pfnTYKey_CloseTYKey){
				g_TYKeyFuncHolder.m_listFunc.pfnTYKey_CloseTYKey(
					(TYKEYHANDLE)m_hCard
					);
			}
		}
	}
	else if(GetType() == RT_COMPORT){
		if(g_TYReaderFuncHolder.m_listFunc.pfnTY_Close){
			g_TYReaderFuncHolder.m_listFunc.pfnTY_Close((int)m_hCard);
		}
	}

	m_hCard = NULL;
	ClearTokenInfoBuffer();
	m_cardType = NOCARD;

	return TRUE;
}
   
//-------------------------------------------------------------------
//	���ܣ�
//		������ܿ��Ƿ񻹴�������״̬
//
//	���أ�
//		TRUE:��������		FALSE:����������
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::CheckCardConnect()
{
	if(!IsConnectCard())
		return FALSE;

	BOOL bRetVal = FALSE;
	if(GetType() == RT_PCSC){
		if(g_SCardFuncHolder.m_listFunc.pfnSCardStatus){
			TCHAR           szReader[MAX_PATH];
			DWORD           cch = MAX_PATH;
			BYTE            bAttr[32];
			DWORD           cByte = 32;
			DWORD           dwState, dwProtocol;
			LONG            lReturn;
			lReturn = g_SCardFuncHolder.m_listFunc.pfnSCardStatus(
				(SCARDHANDLE)m_hCard, szReader, &cch, &dwState, &dwProtocol, (LPBYTE)&bAttr, &cByte
				);
			bRetVal = (lReturn == SCARD_S_SUCCESS && dwState == SCARD_SPECIFIC);
			if(!bRetVal){
				if(lReturn == SCARD_E_SERVICE_STOPPED || lReturn == SCARD_E_NO_SERVICE){
					m_hSC = NULL;
				}
			}
		}
	}
	else if(GetType() == RT_USBPORT){
		if(GetCardType() == CPU_PKI){
			if(g_TYKeyFuncHolder.m_listFunc.pfnTYKey_CardExist)
				bRetVal = g_TYKeyFuncHolder.m_listFunc.pfnTYKey_CardExist((TYKEYHANDLE)m_hCard);
		}
	}
	else if(GetType() == RT_COMPORT){
		if(g_TYReaderFuncHolder.m_listFunc.pfnTY_CardExist){
			WORD status = g_TYReaderFuncHolder.m_listFunc.pfnTY_CardExist((int)m_hCard);
			bRetVal = (status == TYREADER_STATUS_SUCCESS);
		}
	}

	if(!bRetVal) 
		DisconnectCard();

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�����������Ƿ���ڿ�Ƭ
//
//	���أ�
//		TRUE:����	FALSE:������
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::CheckCardIsExist()
{
	if(IsConnectCard())
		return CheckCardConnect();

	BOOL bRetVal = FALSE;
	if(GetType() == RT_PCSC){
		SCARD_READERSTATE ReaderState = {0};
		ReaderState.szReader = m_szName;
		ReaderState.dwCurrentState = SCARD_STATE_UNAWARE;
		LONG lResult = g_SCardFuncHolder.m_listFunc.pfnSCardGetStatusChange(m_hSC, 100, &ReaderState, 1);
		if(lResult == SCARD_S_SUCCESS){
			if(ReaderState.dwEventState & SCARD_STATE_PRESENT)
				bRetVal = TRUE;
		}
	}
	else if(GetType() == RT_USBPORT){
		if(g_TYKeyFuncHolder.m_listFunc.pfnTYKey_OpenTYKey && 
			g_TYKeyFuncHolder.m_listFunc.pfnTYKey_CardExist)
		{
			//�жϿ�Ƭ�Ƿ����
			TYKEYHANDLE hTYKey;
			TYKEYSTATUS sw = g_TYKeyFuncHolder.m_listFunc.pfnTYKey_OpenTYKey(GetRealIndex(), &hTYKey);
			if(sw == STATUS_TYKEY_SUCCESS)
				bRetVal = g_TYKeyFuncHolder.m_listFunc.pfnTYKey_CardExist(hTYKey);
		}
	}
	else if(GetType() == RT_COMPORT){
		if(g_TYReaderFuncHolder.m_listFunc.pfnTY_CardExist &&
			g_TYReaderFuncHolder.m_listFunc.pfnTY_GetOpenedHandle)
		{
			int hReader = g_TYReaderFuncHolder.m_listFunc.pfnTY_GetOpenedHandle(GetRealIndex());
			if(hReader){
				WORD sw = g_TYReaderFuncHolder.m_listFunc.pfnTY_CardExist(hReader);
				bRetVal = (sw == TYREADER_STATUS_SUCCESS);
			}
		}
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��������
//
//	���أ�
//		TRUE:�ɹ�(SW1SW2 = 0x9000��0x61XX)	FALSE:ʧ��
//
//  ������
//		BYTE* pbCommand			������
//		DWORD dwCommandLen		������ĳ���
//		BYTE* pbRespond			��Ӧ��
//		DWORD* pdwRespondLen	��Ӧ��ĳ���
//		WORD* pwStatus			״̬�ֽ�
//
//  ˵����
//		�������Ҫ��Ӧ���״̬�ֽ�,ֻ�踳��NULL
//-------------------------------------------------------------------
BOOL 
CCSPReader::SendCommand(
	BYTE* pbCommand,
	DWORD dwCommandLen,
	BYTE* pbRespond, /*= NULL*/
	DWORD* pdwRespondLen, /*= NULL*/
	WORD* pwStatus /*= NULL*/
	)
{

	if(pbRespond != NULL && pdwRespondLen == NULL){
		TRACE_LINE("pbRespond != NULL && pdwRespondLen == NULL\n");
		return FALSE;
	}

	BYTE cRecvBuffer[258];
	DWORD cbRecvLength = sizeof(cRecvBuffer);
	WORD SW;

	TRACE_LINE("���");
	TRACE_DATA(pbCommand, dwCommandLen);

	if(GetType() == RT_PCSC){
		if(g_SCardFuncHolder.m_listFunc.pfnSCardTransmit == NULL)
			return FALSE;
		LONG lResult = g_SCardFuncHolder.m_listFunc.pfnSCardTransmit(
			(SCARDHANDLE)m_hCard, g_SCardFuncHolder.pcSCardT0Pci, pbCommand, dwCommandLen, NULL, cRecvBuffer, &cbRecvLength
			);
		if(lResult != SCARD_S_SUCCESS){
			TRACE_ERROR(lResult);
			return FALSE;
		}
		
		SW = MAKEWORD(cRecvBuffer[cbRecvLength - 1], cRecvBuffer[cbRecvLength - 2]);

		TRACE_LINE("��Ӧ���ݣ�");
		TRACE_DATA(cRecvBuffer, cbRecvLength - 2);
		TRACE_LINE("״̬�룺%04X\n", SW);

		if(pwStatus != NULL)
			*pwStatus = SW;


		if(SW == 0x9000){
			if(pbRespond){
				//Ҫ���ǵ�SW1 SW2
				*pdwRespondLen = cbRecvLength - 2;
				if(*pdwRespondLen > 0)
					memcpy(pbRespond, cRecvBuffer, *pdwRespondLen);
			}
		}
		else{
			//������Ӧ���ݿ�ȡ
			if(HIBYTE(SW) == 0x61){
				if(pbRespond != NULL){ 
					cbRecvLength = sizeof(cRecvBuffer);
					BYTE cmdGetResponse[5];
					cmdGetResponse[0] = 0x00;			//CLS
					cmdGetResponse[1] = 0xC0;			//INS
					cmdGetResponse[2] = 0x00;			//P1
					cmdGetResponse[3] = 0x00;			//P2
					cmdGetResponse[4] = LOBYTE(SW);		//LE

					TRACE_LINE("���");
					TRACE_DATA(cmdGetResponse, sizeof(cmdGetResponse));

					lResult = g_SCardFuncHolder.m_listFunc.pfnSCardTransmit(
						(SCARDHANDLE)m_hCard, g_SCardFuncHolder.pcSCardT0Pci, cmdGetResponse, sizeof(cmdGetResponse), NULL, cRecvBuffer, &cbRecvLength
						);
					if(lResult != SCARD_S_SUCCESS){
						TRACE_ERROR(lResult);
						return FALSE;
					}
					
					SW = MAKEWORD(cRecvBuffer[cbRecvLength - 1], cRecvBuffer[cbRecvLength - 2]);
					if(pwStatus != NULL)
						*pwStatus = SW;

					TRACE_LINE("��Ӧ���ݣ�");
					TRACE_DATA(cRecvBuffer, cbRecvLength - 2);
					TRACE_LINE("״̬�룺%04X\n", SW);

					if(SW == 0x9000){
						memcpy(pbRespond, cRecvBuffer, cbRecvLength - 2);
						*pdwRespondLen = cbRecvLength - 2;
					}
					else
						return FALSE;
				}
			}
			else
				return FALSE;
		}
	}
	else if(GetType() == RT_USBPORT){
		if(g_TYKeyFuncHolder.m_listFunc.pfnTYKey_SendCommand == NULL)
			return FALSE;

		TYKEYSTATUS status = g_TYKeyFuncHolder.m_listFunc.pfnTYKey_SendCommand(
			(TYKEYHANDLE)m_hCard, dwCommandLen, pbCommand, (int* )&cbRecvLength, cRecvBuffer
			);
		SW = status;
		TRACE_LINE("״̬�룺%04X\n", SW);

		if(pwStatus != NULL)
			*pwStatus = SW;

		if(SW == 0x9000){
			TRACE_LINE("��Ӧ���ݣ�");
			TRACE_DATA(cRecvBuffer, cbRecvLength);
			if(pbRespond){
				*pdwRespondLen = cbRecvLength;
				if(*pdwRespondLen > 0)
					memcpy(pbRespond, cRecvBuffer, *pdwRespondLen);
			}
		}
		else{
			//������Ӧ���ݿ�ȡ
			if(HIBYTE(SW) == 0x61){
				if(pbRespond != NULL){ 
					cbRecvLength = sizeof(cRecvBuffer);
					BYTE cmdGetResponse[5];
					cmdGetResponse[0] = 0x00;			//CLS
					cmdGetResponse[1] = 0xC0;			//INS
					cmdGetResponse[2] = 0x00;			//P1
					cmdGetResponse[3] = 0x00;			//P2
					cmdGetResponse[4] = LOBYTE(SW);		//LE

					TRACE_LINE("���");
					TRACE_DATA(cmdGetResponse, sizeof(cmdGetResponse));

					status = g_TYKeyFuncHolder.m_listFunc.pfnTYKey_SendCommand(
						(TYKEYHANDLE)m_hCard, sizeof(cmdGetResponse), cmdGetResponse, (int* )&cbRecvLength, cRecvBuffer
						);
					SW = status;
					TRACE_LINE("״̬�룺%04X\n", SW);

					if(pwStatus != NULL)
						*pwStatus = SW;

					if(SW == 0x9000){
						TRACE_LINE("��Ӧ���ݣ�");
						TRACE_DATA(cRecvBuffer, cbRecvLength);
						memcpy(pbRespond, cRecvBuffer, cbRecvLength);
						*pdwRespondLen = cbRecvLength;
					}
					else{
						if(SW == STATUS_TYKEY_DEVICE_ERROR || SW == STATUS_TYKEY_NO_TYKEY ||
							SW == STATUS_TYKEY_NO_CARD)
							DisconnectCard();
						return FALSE;
					}
				}
			}
			else{
				if(SW == STATUS_TYKEY_DEVICE_ERROR || SW == STATUS_TYKEY_NO_TYKEY ||
					SW == STATUS_TYKEY_NO_CARD)
					DisconnectCard();
				return FALSE;
			}
		}
	}
	else if(GetType() == RT_COMPORT){
		if(g_TYReaderFuncHolder.m_listFunc.pfnTY_tsi_api == NULL)
			return FALSE;
		
		SW = g_TYReaderFuncHolder.m_listFunc.pfnTY_tsi_api(
			(int)m_hCard, (WORD)dwCommandLen, pbCommand, (WORD* )&cbRecvLength, cRecvBuffer
			);
		if(pwStatus != NULL)
			*pwStatus = SW;
		TRACE_LINE("״̬�룺%04X\n", SW);

		if(SW == 0x9000){
			TRACE_LINE("��Ӧ���ݣ�");
			TRACE_DATA(cRecvBuffer, cbRecvLength);
			if(pbRespond){
				*pdwRespondLen = cbRecvLength;
				if(*pdwRespondLen > 0)
					memcpy(pbRespond, cRecvBuffer, *pdwRespondLen);
			}
		}
		else{
			//������Ӧ���ݿ�ȡ
			if(HIBYTE(SW) == 0x61){
				if(pbRespond != NULL){ 
					cbRecvLength = sizeof(cRecvBuffer);
					BYTE cmdGetResponse[5];
					cmdGetResponse[0] = 0x00;			//CLS
					cmdGetResponse[1] = 0xC0;			//INS
					cmdGetResponse[2] = 0x00;			//P1
					cmdGetResponse[3] = 0x00;			//P2
					cmdGetResponse[4] = LOBYTE(SW);		//LE

					TRACE_LINE("���");
					TRACE_DATA(cmdGetResponse, sizeof(cmdGetResponse));

					SW = g_TYReaderFuncHolder.m_listFunc.pfnTY_tsi_api(
						(int)m_hCard, sizeof(cmdGetResponse), cmdGetResponse, 
						(WORD* )&cbRecvLength, cRecvBuffer);
					if(pwStatus != NULL)
						*pwStatus = SW;
					TRACE_LINE("״̬�룺%04X\n", SW);

					if(SW == 0x9000){
						TRACE_LINE("��Ӧ���ݣ�");
						TRACE_DATA(cRecvBuffer, cbRecvLength);
						memcpy(pbRespond, cRecvBuffer, cbRecvLength);
						*pdwRespondLen = cbRecvLength;
					}
					else{
						if(SW == TYREADER_STATUS_NOREADER || SW == TYREADER_STATUS_NORESET)
							DisconnectCard();
						return FALSE;
					}
				}
			}
			else{
				if(SW == TYREADER_STATUS_NOREADER || SW == TYREADER_STATUS_NORESET)
					DisconnectCard();
				return FALSE;
			}
		}
	}
	else
		return FALSE;

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ���õ��ļ�
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		BYTE flag
//		DWORD dwSize
//		BYTE path[2]
//
//  ˵����
//		����ʹ�ÿ����ÿռ�,���û�лᴴ��һ��
//-------------------------------------------------------------------
BOOL 
CCSPReader::GetWorkableFile(
	WORD flag,
	DWORD dwSize,
	BYTE path[2]
	)
{
	if(GetCardType() == CPU_PKI)
		return cpuGetWorkableFile(flag, dwSize, path);
	return FALSE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�����ļ�
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		BYTE path[2]			��ʶ
//		DWORD dwSize			��С
//		FILEHANDLE* phFile		���ص��ļ����
//		BYTE type				�ļ�����
//		BYTE readAuth			��Ȩ��
//		BYTE writeAuth			дȨ��
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::CreateFile(
	BYTE path[2],
	DWORD dwSize,
	FILEHANDLE* phFile,
	BYTE type,
	BYTE readAuth,
	BYTE writeAuth
	)
{
	if(phFile == NULL)
		return FALSE;
	*phFile = NULL;

	if(GetCardType() == CPU_PKI){
		if(!cpuCreateEF(path, dwSize, type, readAuth, writeAuth))
			return FALSE;
		*phFile = HFILECOS;
	}
	else return FALSE;

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		ɾ���ļ�
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		BYTE path[2]	��ʶ	
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::DeleteFile(
	BYTE path[2]
	)
{
	if(GetCardType() == CPU_PKI){
		return cpuSetFileUseableFlag(path, TRUE);
	}	
	return FALSE;
}


//-------------------------------------------------------------------
//	���ܣ�
//		���ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		BYTE path[2]			��ʶ			
//		FILEHANDLE* phFile		�ļ����
//		LPDWORD pdwFileSize		�ļ���С
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::OpenFile(
	BYTE path[2],
	FILEHANDLE* phFile,
	LPDWORD pdwFileSize
	)
{
	if(phFile == NULL)
		return FALSE;
	*phFile = NULL;

	if(GetCardType() == CPU_PKI){
		BYTE cRetData[256];
		DWORD dwRetDataLen;
		if(!cpuSelectEF(path, cRetData, &dwRetDataLen))
			return FALSE;
		if(pdwFileSize != NULL)
			*pdwFileSize = MAKEWORD(cRetData[dwRetDataLen - 1], cRetData[dwRetDataLen - 2]);

		*phFile = HFILECOS;
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ�ļ�
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		FILEHANDLE hFile				�ļ����
//		DWORD dwReadLen					��ȡ�ĳ���
//		LPBYTE pReadBuffer				��ȡ������
//		LPDWORD pdwRealReadLen			ʵ�ʷ��صĳ���
//		DWORD dwOffset					ƫ����
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::ReadFile(
	FILEHANDLE hFile,
	DWORD dwReadLen,
	LPBYTE pReadBuffer,
	LPDWORD pdwRealReadLen,
	DWORD dwOffset
	)
{
	if(hFile == HFILECOS){
		if(!cpuReadCurrentBinaryFile(pReadBuffer, dwReadLen, dwOffset))
			return FALSE;

		if(pdwRealReadLen != NULL)
			*pdwRealReadLen = dwReadLen;
	}
	else{
		return FALSE;
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		д�ļ�
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		FILEHANDLE hFile			�ļ����
//		LPBYTE pWriteBuffer			д�������
//		DWORD dwWriteBufferLen		д�����ݵĳ���
//		DWORD dwOffset				ƫ����
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::WriteFile(
	FILEHANDLE hFile,
	LPBYTE pWriteBuffer,
	DWORD dwWriteBufferLen,
	DWORD dwOffset
	)
{
	if(hFile == HFILECOS){
		if(!cpuUpdateCurrentBinaryFile(pWriteBuffer, dwWriteBufferLen, dwOffset))
			return FALSE;
	}
	else{
			return FALSE;
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ر��ļ�
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		FILEHANDLE hFile	�ļ����
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::CloseFile(
	FILEHANDLE hFile
	)
{
	if(hFile == HFILECOS)
		return TRUE;

	return FALSE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ʽ����Ƭ
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		LPFORMATINFO pInfo	��ʽ����Ϣ
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::FormatCard(
	LPFORMATINFO pInfo
	)
{
	if(pInfo == NULL)
		return FALSE;

	if(!CheckCardConnect()){
		if(!ConnectCard(FALSE))
			return FALSE;
	}

	pInfo->tokenInfo.pinMaxRetry = ((pInfo->soPINMaxRetry << 4) & 0xF0) | (pInfo->userPINMaxRetry & 0x0F);
	
		return cpuFormatCard(pInfo);
}

//-------------------------------------------------------------------
//	���ܣ�
//		�س�EEPROM
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::EraseE2()
{
	if(!CheckCardConnect()){
		if(!ConnectCard(FALSE))
			return FALSE;
	}

	return cpuEraseE2();
}


//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ��Ƭ��Ϣ
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		LPTOKENINFO pTokenInfo	��ȡ�Ŀ�Ƭ��Ϣ
//		BOOL bReload			�Ƿ���������
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::GetTokenInfo(
	LPTOKENINFO pTokenInfo,
	BOOL bReload
	)
{
	if(pTokenInfo == NULL)
		return FALSE;

	//����Ѷ�����ֱ�ӷ��ؽ��
	if(m_pTokenInfo != NULL && !bReload){
		memcpy(pTokenInfo, m_pTokenInfo, sizeof(TOKENINFO));
		return TRUE;
	}

	ClearTokenInfoBuffer();
		
	//�����ܿ��ж�ȡ������
	BeginTransaction();

	FILEHANDLE hFile;
	DWORD dwBufferLen;
	if(!OpenFile(g_cPathTable.tokenInfoPath, &hFile, &dwBufferLen)){
		EndTransaction();
		return FALSE;
	}

	LPBYTE pbBuffer = new BYTE[dwBufferLen];
	if(pbBuffer == NULL){
		CloseFile(hFile);
		EndTransaction();
		return FALSE;
	}

	BOOL bRetVal = ReadFile(hFile, dwBufferLen, pbBuffer, &dwBufferLen, 0);
	CloseFile(hFile);


	if(!bRetVal){
		delete pbBuffer;
		EndTransaction();
		return FALSE;
	}

	BYTE cTokenInfoVersion = 1;
	bRetVal = TokenInfoDERDecoding(pbBuffer, dwBufferLen, pTokenInfo, &cTokenInfoVersion);
	delete pbBuffer;

	//����
	if(bRetVal){
		m_pTokenInfo = new TOKENINFO;
		memcpy(m_pTokenInfo, pTokenInfo, sizeof(TOKENINFO));
		///////////////////////////////////////////////////////////////////////
		//����ƬӲ�����к��滻
		HWReadCardSN(m_pTokenInfo->serialNumber, sizeof(m_pTokenInfo->serialNumber));
	}

	EndTransaction();
	return bRetVal;
}
//-------------------------------------------------------------------
//	���ܣ�
//		��ȡӲ�����к�
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		BYTE *	pbSN,		//����Ӳ�����к�
//		DWORD *	pdwLen		//�������кų���
//
//  ˵����
//-------------------------------------------------------------------
BOOL CCSPReader::HWReadCardSN(char *szSN, int nMaxLen)
{
	if(GetCardType() != CPU_PKI)
		return FALSE;

	BYTE pbCmd[256];
	BYTE pbResp[256] = {0};
	DWORD dwRespLen = 256;
	//Ϊ�˷�ֹд����0ʱд����,���˸���ʱ��
	CHAR szSnTemp[256] = {0};

	//�ⲿ��֤
	memcpy(pbCmd, "\x80\xd8\x00\x00\x10\x11\x22\x33\x44\x55\x66\x77\x88\xa3\x2a\xd8\xac\xd2\x0c\x38\xfc", 0x15);
	if(!SendCommand(pbCmd, 0x15))
	{
		if(!GetATR(pbResp, &dwRespLen))
			return FALSE;
		char *szItor = szSnTemp;
		for(DWORD dwI = 8; dwI > 0; dwI--)
		{
			sprintf(szItor, _T("%02x"), pbResp[dwRespLen - dwI]);
			szItor += 2;
		}
	}
	else
	{
		memcpy(pbCmd, "\x80\xCA\xDF\x62\x0B", 5);
		
		if(!SendCommand(pbCmd, 5, pbResp, &dwRespLen))
			return FALSE;
		if(dwRespLen > ( 3 + DWORD(nMaxLen/2)))
			dwRespLen = 3 + DWORD(nMaxLen/2);
		for(DWORD dwI = 3; dwI < dwRespLen; dwI++)
			sprintf(szSnTemp + (dwI-3) * 2, _T("%02x"), pbResp[dwI]);
	}

	_strupr(szSnTemp);
	memset(szSN, 0, nMaxLen);
	memcpy(szSN, szSnTemp, (dwRespLen-3)*2);

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		���ÿ�Ƭ��Ϣ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		LPTOKENINFO pTokenInfo	Ҫ���õĿ�Ƭ��Ϣ
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::SetTokenInfo(
	LPTOKENINFO pTokenInfo
	)
{
	if(pTokenInfo == NULL)
		return FALSE;
	
	//�µ�Token��Ϣ�ı���
	ByteArray baTokenInfo;
	if(!TokenInfoDEREncoding(pTokenInfo, baTokenInfo))
		return FALSE;

	//�������ܿ��е��ļ�
	BeginTransaction();

	BOOL bRetVal = FALSE;
	FILEHANDLE hFile;
	if(OpenFile(g_cPathTable.tokenInfoPath, &hFile, NULL)){
		bRetVal = WriteFile(hFile, baTokenInfo.GetData(), baTokenInfo.GetSize(), 0);
		CloseFile(hFile);
	}

	EndTransaction();

	//����
	if(bRetVal){
		ClearTokenInfoBuffer();
		m_pTokenInfo = new TOKENINFO;
		memcpy(m_pTokenInfo, pTokenInfo, sizeof(TOKENINFO));
		///////////////////////////////////////////////////////////////////////
		//����ƬӲ�����к��滻
		HWReadCardSN(m_pTokenInfo->serialNumber, sizeof(m_pTokenInfo->serialNumber));
	}

	return bRetVal;
}


//-------------------------------------------------------------------
//	���ܣ�
//		��ָ���û����͵���ݵ�¼
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		int nUserType		�û�����
//		LPBYTE pPIN			PIN
//		DWORD dwPINLen		PIN�ĳ���
//		DWORD& dwRetryCount	ʣ������ԵĴ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::Login(
	int nUserType,
	LPBYTE pPIN,
	DWORD dwPINLen,
	DWORD& dwRetryCount
	)
{
	//
	//	�������
	//
	if(nUserType != UT_USER && nUserType != UT_SO){
		dwRetryCount = -1;
		return FALSE;
	}
	
	if(pPIN == NULL || dwPINLen == 0){
		dwRetryCount = -1;
		return FALSE;
	}
	
	//
	//	step1:���û������������һ��HASH���㣬�õ���֤��Կ
	//
	MD5 hash;
	BYTE key[16];
	hash.CalculateDigest(key, pPIN, dwPINLen);

	if(GetCardType() == CPU_PKI){
		//
		//	step2:�ӿ���ȡһ4�ֽ�����������0x00��8�ֽ�
		//
		BYTE data[8];
		BYTE cCommand[13];
		DWORD dwRespLen;
		WORD SW;
		cCommand[0] = 0x00;			//CLA
		cCommand[1] = 0x84;			//INS
		cCommand[2] = 0x00;			//P1
		cCommand[3] = 0x00;			//P2
		cCommand[4] = 0x04;			//LE
		BOOL bRetVal = SendCommand(
			cCommand, 5, data, &dwRespLen, NULL
			);
		if(!bRetVal){
			dwRetryCount = -1;
			return FALSE;
		}
		memset(data + 4, 0x00, 4);

		//
		//	step3:����֤��Կ����3-DES����
		//
		DES_EDE_Encryption cipher(key);
		cipher.ProcessBlock(data);

		//
		//	step4:��֤
		//
		BYTE bKeyID = (nUserType == UT_USER ? 0x02 : 0x01); 

		cCommand[0] = 0x00;							//CLA
		cCommand[1] = 0x82;							//INS
		cCommand[2] = 0x00;							//P1
		cCommand[3] = bKeyID;	//P2(��Կ��ʶ)
		cCommand[4] = 0x08;							//LC
		memcpy(&cCommand[5], data, 8);				//DATA

		bRetVal = SendCommand(cCommand, 13, NULL, NULL, &SW);

		if(bRetVal)
			return TRUE;

		//
		//	�жϳ����ԭ��
		//
		if(HIBYTE(SW) == 0x63){
			if((LOBYTE(SW) & 0xF0) == 0xC0){
				dwRetryCount = LOBYTE(SW) & 0X0F;
			}
		}
		else if(SW == 0x6983){
			dwRetryCount = 0;
		}
		else
			dwRetryCount = -1;
	}

	return FALSE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�û��˳�
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		��
//
//  ˵����
//		ִ�гɹ��󣬵�ǰ�û����Ϊ����(δ��¼)
//-------------------------------------------------------------------
BOOL 
CCSPReader::Logout()
{
	if(GetCardType() == CPU_PKI){
		if(m_FileSys.wDF_flag & DF_CSP_IN_MF)
		{//ѡ��Ӧ��,��ѡ��MF,��һ��״̬�ָ�
			if(!cpuSelectDF(TYCSP))
				return FALSE;
			if(!cpuSelectDF(MF))
				return FALSE;
		}
		else
		{
			if(!cpuSelectDF(MF))
				return FALSE;
			if(!cpuSelectDF(TYCSP))
				return FALSE;
		}
	}

	return TRUE;
}
	
//-------------------------------------------------------------------
//	���ܣ�
//		����PIN��
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		int nUserType			�û�����
//		LPBYTE pOldPIN			��PIN
//		DWORD dwOldPINLen		��PIN�ĳ���
//		LPBYTE pNewPIN			��PIN
//		DWORD dwNewPINLen		��PIN�ĳ���
//
//  ˵����
//		�ı䵱ǰ�û���PIN
//-------------------------------------------------------------------
BOOL 
CCSPReader::ChangePIN(
	int nUserType,
	LPBYTE pOldPIN,
	DWORD dwOldPINLen,
	LPBYTE pNewPIN,
	DWORD dwNewPINLen
	)
{
	//
	//	�������
	//
	if(pNewPIN == NULL || dwNewPINLen == 0)
	{
		return FALSE;
	}

	//
	//	��֤PIN��
	//
	if(pOldPIN != NULL){
		DWORD dwRetryCount;
		if(!Login(nUserType, pOldPIN, dwOldPINLen, dwRetryCount))
			return FALSE;
	}

	//����Ա���û�PIN��������Դ���
	BYTE pinMaxRetry = 0x33;
	TOKENINFO Info;
	if(GetTokenInfo(&Info))
		pinMaxRetry = Info.pinMaxRetry;

	//
	//	����PIN��
	//
	//	step1: ��PIN����һ�ι�ϣ����(MD5)���õ��ⲿ��֤��Կ
	MD5 hash;
	BYTE key[16];
	hash.CalculateDigest(key, pNewPIN, dwNewPINLen);

	//���ⲿ��֤��Կд�뿨��
	if(GetCardType() == CPU_PKI){
		//������Կ��Ϣ
		BYTE cKeyData[24];
		BYTE bKeyID = (nUserType == UT_USER ? 0x02 : 0x01); 

		cKeyData[0] = bKeyID;		//��ʶ��
		cKeyData[1] = 0x01;										//�汾��
		cKeyData[2] = 0x00;										//�㷨��ʶ
		cKeyData[3] = 0x08;										//��Կ����
		cKeyData[4] = 0x0f;										//ʹ��Ȩ��
		cKeyData[5] = (nUserType == UT_USER ? 0x0a : 0x05);		//����״̬
		cKeyData[6] = (nUserType == UT_USER ? 0x4b : 0x55);		//�޸�Ȩ��
		if(nUserType == UT_USER){
			BYTE cErrCnt = pinMaxRetry & 0x0F;
			cKeyData[7] = ((cErrCnt << 4) & 0xF0) | (cErrCnt & 0x0F);
		}
		else{
			BYTE cErrCnt = (pinMaxRetry >> 4) & 0x0F;
			cKeyData[7] = ((cErrCnt << 4) & 0xF0) | (cErrCnt & 0x0F);
		}
		memcpy(cKeyData + 8, key, 16);							//��Կ����

		//д����Կ��Ϣ
		return cpuWriteKey(cKeyData, sizeof(cKeyData), FALSE);
	}
	return false;
}

//-------------------------------------------------------------------
//	���ܣ�
//		PIN����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		LPBYTE pUserDefaultPIN		�������û���ȱʡPIN
//		DWORD dwUserDefaultPINLen	�������û���ȱʡPIN�ĳ���
//
//  ˵����
//		��ǰ�û���ݱ���Ϊ����Ա
//-------------------------------------------------------------------
BOOL 
CCSPReader::UnlockPIN(
	LPBYTE pUserDefaultPIN,
	DWORD dwUserDefaultPINLen
	)
{
	//
	//	�������
	//
	if(pUserDefaultPIN == NULL || dwUserDefaultPINLen == 0)
		return FALSE;

	//����Ա���û�PIN��������Դ���
	BYTE pinMaxRetry = 0x33;
	TOKENINFO Info;
	if(GetTokenInfo(&Info))
		pinMaxRetry = Info.pinMaxRetry;

	//
	//	����PIN��
	//

	//	step1: ��PIN����һ�ι�ϣ����(MD5)���õ��ⲿ��֤��Կ
	MD5 hash;
	BYTE key[16];
	hash.CalculateDigest(key, pUserDefaultPIN, dwUserDefaultPINLen);

	//���ⲿ��֤��Կд�뿨��
	if(GetCardType() == CPU_PKI){
		//������Կ��Ϣ
		BYTE cKeyData[24];
		cKeyData[0] = 0x02;										//��ʶ��
		cKeyData[1] = 0x01;										//�汾��
		cKeyData[2] = 0x00;										//�㷨��ʶ
		cKeyData[3] = 0x08;										//��Կ����
		cKeyData[4] = 0x0f;										//ʹ��Ȩ��
		cKeyData[5] = 0x0a;										//����״̬
		cKeyData[6] = 0x4b;										//�޸�Ȩ��
		BYTE cErrCnt = pinMaxRetry & 0x0F;
		cKeyData[7] = ((cErrCnt << 4) & 0xF0) | (cErrCnt & 0x0F);
		memcpy(cKeyData + 8, key, 16);							//��Կ����

		//д����Կ��Ϣ
		return cpuWriteKey(cKeyData, sizeof(cKeyData), FALSE);
	}
	return false;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ѯ����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		DWORD& dwTotalSize				�ܿռ�(��ϵͳռ��)
//		DWORD& dwTotalSize2				�ܿռ�(����ϵͳռ��)
//		DWORD& dwUnusedSize				���ÿռ�
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::GetE2Size(
	DWORD& dwTotalSize,
	DWORD& dwTotalSize2,
	DWORD& dwUnusedSize
	)
{
	if(GetCardType() == CPU_PKI){		
		BOOL bErrBecauseNoMF = FALSE;
		if(!cpuGetE2Size(0x00, dwTotalSize))
			return FALSE;

		if(!cpuGetE2Size(0x01, dwTotalSize2, &bErrBecauseNoMF)){
			if(!bErrBecauseNoMF)
				return FALSE;
			else
				dwTotalSize2 = dwTotalSize;
		}

		if(!cpuGetE2Size(0x02, dwUnusedSize, &bErrBecauseNoMF)){
			if(!bErrBecauseNoMF)
				return FALSE;
			else
				dwUnusedSize = dwTotalSize;
		}
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ѯCOS�汾
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		DWORD& dwCosVersion				COS�汾
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::GetCosVer(
	DWORD& dwVersion
	)
{
		return cpuGetCosVer(dwVersion);
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ѯ�з�SSF33�㷨
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::IsSSF33Support()
{
		return cpuIsSSF33Support();
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡPIN��������Ϣ
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		int nUserType					�û�����
//		int nMaxRetry					������Դ���
//		int nLeftRetry					ʣ�����Դ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::GetPinRetryInfo(
	int nUserType,
	int& nMaxRetry,
	int& nLeftRetry
	)
{
	int nKeyId = (nUserType == UT_USER ? 0x02 : 0x01);
	int nKeyType = 0x08;

	if(GetCardType() != CPU_PKI ){
		return FALSE;
	}
	else{
		BYTE cErrCount;
		if(!cpuGetKeyErrCount(nKeyId, nKeyType, cErrCount))
			return FALSE;

		nMaxRetry = ((cErrCount & 0xF0) >> 4);
		nLeftRetry = (cErrCount & 0x0F);
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		ѡ��DF�ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		DF_ID dfId		DF�ļ��ı�ʶ
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::cpuSelectDF(DF_ID dfId)
{
	BOOL bRetVal;

	BYTE cCommand[64];
	BYTE cLen;
	WORD wSW;
	cCommand[0] = 0x00;								//CLA
	cCommand[1] = 0xA4;								//INS

	switch(dfId){
	case MF:
		cLen = 7;
		cCommand[2] = 0x00;							//P1
		cCommand[3] = 0x00;							//P2
		cCommand[4] = 0x02;							//LC
		//DATA(��ID����ѡ�� 3F 00)
		cCommand[5] = g_cPathTable.mfPath[0];
		cCommand[6] = g_cPathTable.mfPath[1];

		bRetVal = SendCommand(cCommand, cLen, NULL, NULL, &wSW);

		break;

	case TYCSP:
		cLen = 7;
		cCommand[2] = 0x00;							//P1
		cCommand[3] = 0x00;							//P2
		cCommand[4] = 0x02;							//LC
		//DATA(��ID����ѡ�� 2f 01)
		cCommand[5] = g_cPathTable.dirPath[0];
		cCommand[6] = g_cPathTable.dirPath[1];

		//��������
		bRetVal = SendCommand(cCommand, cLen, NULL, NULL, &wSW);

		break;
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		ѡ��EF�ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		BYTE cPath[2]				�ļ���ʶ
//		BYTE* pbRetData				��Ӧ����
//		DWORD* pdwRetDataLen		��Ӧ���ݵĳ���
//
//  ˵����
//		���ļ���ʶ����ѡ��
//-------------------------------------------------------------------
BOOL
CCSPReader::cpuSelectEF(
	BYTE cPath[2],
	BYTE* pbRetData, /* = NULL*/
	DWORD* pdwRetDataLen /* = NULL*/
	)
{
	BYTE cCommand[7];
	cCommand[0] = 0x00;
	cCommand[1] = 0xA4;
	cCommand[2] = 0x02;
	cCommand[3] = 0x00;
	cCommand[4] = 0x02;
	memcpy(cCommand + 5, cPath, 2);

	BOOL bRetVal = SendCommand(cCommand, sizeof(cCommand), pbRetData, pdwRetDataLen);
	if(!bRetVal)
	{
		cCommand[2] = 0x00;
		bRetVal = SendCommand(cCommand, sizeof(cCommand), pbRetData, pdwRetDataLen);
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		����EF�ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		BYTE path[2]
//		DWORD dwSize
//		BYTE type
//		BYTE readAuth
//		BYTE writeAuth
//		BYTE* pbUseAuth
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::cpuCreateEF(
	BYTE path[2],
	DWORD dwSize,
	BYTE type,
	BYTE readAuth,
	BYTE writeAuth,
	BYTE* pbUseAuth
	)
{
	BYTE cmd[16];
	memcpy(cmd,"\x80\xe0\x02\x00\x07",5);
	if(pbUseAuth) cmd[4] = 0x08;

	cmd[5] = path[0];
	cmd[6] = path[1];
	cmd[7] = type;
	cmd[8] = readAuth;
	cmd[9] = writeAuth;
	cmd[10] = BYTE(dwSize>>8);
	cmd[11] = BYTE(dwSize);
	if(pbUseAuth) cmd[12] = *pbUseAuth;

	return SendCommand(cmd, cmd[4] + 5, NULL, NULL);
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ��ǰ�ļ��еĶ����Ƽ�¼
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		BYTE* pbData			����������
//		DWORD dwDataLen			���ݵĳ���
//		DWORD dwOffset			�ڵ�ǰ�ļ���ƫ����
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::cpuReadCurrentBinaryFile(
	BYTE* pbData,
	DWORD dwDataLen,
	DWORD dwOffset /*= 0*/
	)
{
	ASSERT(pbData != NULL);

	BOOL bRetVal;
	BYTE cCommand[5], cRespond[256];
	DWORD dwRespondLen;
	DWORD dwRealOffset = dwOffset;

	cCommand[0] = 0x00;										//CLA
	cCommand[1] = 0xB0;										//INS

	for(DWORD i = 0; i < dwDataLen; i += g_cPathTable.bufSize){
		cCommand[2] = HIBYTE(LOWORD(dwRealOffset));			//P1
		cCommand[3] = LOBYTE(LOWORD(dwRealOffset));			//P2
		if(dwDataLen - i < g_cPathTable.bufSize)			//LE
			cCommand[4] = BYTE(dwDataLen - i);
		else
			cCommand[4] = g_cPathTable.bufSize;

		bRetVal = SendCommand(
			cCommand, 5, cRespond, &dwRespondLen
			);
		if (bRetVal != TRUE) 
			return FALSE;

		memcpy(pbData + i, cRespond, dwRespondLen);
		dwRealOffset += g_cPathTable.bufSize;
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ڵ�ǰ�ļ���д�����Ƽ�¼
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		BYTE* pbData			����
//		DWORD dwDataLen			��С
//		DWORD dwOffset			�ڵ�ǰ�ļ���ƫ����
//		BOOL bPlain = FALSE		//�Ƿ�ǿ������д
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::cpuUpdateCurrentBinaryFile(
	BYTE* pbData,
	DWORD dwDataLen,
	DWORD dwOffset,
	BOOL bPlain /*= FALSE	*/
	)
{
	//�������·����, �����ļ�MACд
	if((!bPlain) && (m_FileSys.dwEF_flag & EF_WRITE_PROTECTED))
		return cpuUpdateBinaryWithMac(pbData, dwDataLen, dwOffset);
	
	BYTE* pCommand = new BYTE[5+g_cPathTable.bufSize];
	if(pCommand == NULL)
		return FALSE;

	BOOL bRetVal = TRUE;
	DWORD dwRealOffset = dwOffset;

	pCommand[0] = 0x00;								//CLA
	pCommand[1] = 0xD6;								//INS

	for(DWORD i = 0; i < dwDataLen; i += g_cPathTable.bufSize){
		pCommand[2] = HIBYTE(LOWORD(dwRealOffset));	//P1
		pCommand[3] = LOBYTE(LOWORD(dwRealOffset));	//P2
		if(dwDataLen - i < g_cPathTable.bufSize)	//LE
			pCommand[4] = BYTE(dwDataLen - i);
		else
			pCommand[4] = g_cPathTable.bufSize;
		
		memcpy(pCommand+5, pbData + i, pCommand[4]);

		bRetVal = SendCommand(pCommand, 5 + pCommand[4], NULL, NULL);
		if (bRetVal != TRUE) 
			break;

		dwRealOffset += g_cPathTable.bufSize;
	}

	delete pCommand;

	return bRetVal;
}


//-------------------------------------------------------------------
//	���ܣ�
//		��ǰ�ļ������ļ�MACд������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		BYTE* pbData			����
//		DWORD dwDataLen			��С
//		DWORD dwOffset			�ڵ�ǰ�ļ���ƫ����
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::cpuUpdateBinaryWithMac(
	BYTE* pbData,
	DWORD dwDataLen,
	DWORD dwOffset
	)
{
	BYTE* pCommand = new BYTE[5+g_cPathTable.bufSize + 4];
	if(pCommand == NULL)
		return FALSE;

	BOOL bRetVal = TRUE;
	DWORD dwRealOffset = dwOffset;

	pCommand[0] = 0x04;								//CLA
	pCommand[1] = 0xD6;								//INS

	//ȡ������õ��ı���
	BYTE pbRandCmd[] = {0x00, 0x84, 0x00, 0x00, 0x04};
	BYTE pbRand[256] = {0};
	DWORD dwLen = 256;

	for(DWORD i = 0; i < dwDataLen; i += g_cPathTable.bufSize){
		pCommand[2] = HIBYTE(LOWORD(dwRealOffset));	//P1
		pCommand[3] = LOBYTE(LOWORD(dwRealOffset));	//P2
		if(dwDataLen - i < g_cPathTable.bufSize)	//LE
			pCommand[4] = BYTE(dwDataLen - i);	//����MAC����
		else
			pCommand[4] = g_cPathTable.bufSize;

		
		//ȡ�����
		dwLen = 256;
		bRetVal = FALSE;
		if(!SendCommand(pbRandCmd, 5, pbRand, &dwLen))
			break;
		memset(pbRand + 4, 0, 4);

		//��MAC
		memcpy(pCommand+5, pbData + i, pCommand[4]);
		pCommand[4] += 4;
		if(!CulMac(g_pbMacKey, 
			sizeof(g_pbMacKey), 
			pCommand, 
			pCommand[4] + 1, 
			pCommand + pCommand[4] + 1, 
			pbRand))
			break;

		//д����
		bRetVal = SendCommand(pCommand, 5 + pCommand[4], NULL, NULL);
		if (bRetVal != TRUE) 
			break;

		dwRealOffset += g_cPathTable.bufSize;
	}

	delete pCommand;

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		����д����Կ
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		LPBYTE pKeyData		��Կ����
//		DWORD dwKeyDataLen	��Կ���ݵĳ���
//		BOOL bInstall		��װ�����޸�
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::cpuWriteKey(
	LPBYTE pKeyData,
	DWORD dwKeyDataLen,
	BOOL bInstall
	)
{
	//��Կ��Ϣ����Ϊ��
	if(pKeyData == NULL)
		return FALSE;

	//��������Ŀռ�
	BYTE cLen = static_cast<BYTE>(5 + dwKeyDataLen);
	LPBYTE pCommand = new BYTE[cLen];
	if(pCommand == NULL)
		return FALSE;

	//���������(��LE)
	pCommand[0] = 0x80;									//CLA
	pCommand[1] = 0xD4;									//INS
	if(bInstall)
		pCommand[2] = 0x00;								//P1
	else
		pCommand[2] = 0x01;
	pCommand[3] = 0x00;									//P2
	pCommand[4] = static_cast<BYTE>(dwKeyDataLen);		//LC
	memcpy(pCommand + 5, pKeyData, dwKeyDataLen);		//DATA

	//д��Կ
	BOOL bRetVal = SendCommand(pCommand, cLen);
	//�ͷ�����Ŀռ�
	delete pCommand;

	return bRetVal;
}


//-------------------------------------------------------------------
//	���ܣ�
//		��ѯ����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		int nType						����
//		DWORD& dwSize					�ռ��С
//		BOOL* pErrBecauseNoMF			�����Ƿ���Ϊû��MF
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::cpuGetE2Size(
	int nType,
	DWORD& dwSize,
	BOOL* pErrBecauseNoMF
	)
{
	BYTE pbRespond[256];
	DWORD cbRespond;
	BYTE pbCommand[5];
	WORD SW;
	pbCommand[0] = 0x54;
	pbCommand[1] = 0xB4;
	pbCommand[2] = 0x00;
	pbCommand[3] = (BYTE)nType;
	pbCommand[4] = 0x04;

	if(pErrBecauseNoMF) 
		*pErrBecauseNoMF = FALSE;
	if(!SendCommand(pbCommand, sizeof(pbCommand), pbRespond, &cbRespond, &SW)){
		if(pErrBecauseNoMF){
			if(SW == 0x6A81)
				*pErrBecauseNoMF = TRUE;
		}
		return FALSE;
	}
	memcpy(&dwSize, pbRespond, sizeof(dwSize));

	return TRUE;
}
//-------------------------------------------------------------------
//	���ܣ�
//		��ѯCOS�汾
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		DWORD& dwVersion					COS�汾
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::cpuGetCosVer(DWORD& dwVersion)
{
	BYTE pbRespond[256];
	DWORD cbRespond;
	BYTE pbCommand[5];
	WORD SW;
	pbCommand[0] = 0x54;
	pbCommand[1] = 0x09;
	pbCommand[2] = 0x80;
	pbCommand[3] = 0x00;
	pbCommand[4] = 0x04;

	if((!SendCommand(pbCommand, sizeof(pbCommand), pbRespond, &cbRespond, &SW))||(SW != 0x9000))
		return FALSE;
		
	dwVersion = MAKELONG(MAKEWORD(pbRespond[3], pbRespond[2]), MAKEWORD(pbRespond[1], pbRespond[0]));
	
	return TRUE;
}
//-------------------------------------------------------------------
//	���ܣ�
//		��ѯ�Ƿ�������SSF33�㷨
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::cpuIsSSF33Support()
{
	BYTE pbRespond[256];
	DWORD cbRespond;
	BYTE pbCommand[4];
	WORD SW;
	pbCommand[0] = 0x80;
	pbCommand[1] = 0x1D;
	pbCommand[2] = 0x00;
	pbCommand[3] = 0x00;

	if((!SendCommand(pbCommand, sizeof(pbCommand), pbRespond, &cbRespond, &SW))||(SW != 0x9000))
		return FALSE;
		
	return TRUE;
}
	
	
//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ���������
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		int nKeyId					��Կ��ʶ
//		int nKeyType				��Կ����
//		BYTE& cErrCount				����������ֽ�
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::cpuGetKeyErrCount(
	int nKeyId,
	int nKeyType,
	BYTE& cErrCount
	)
{
	BYTE pbRespond[256];
	DWORD cbRespond;
	BYTE pbCommand[5];
	pbCommand[0] = 0x54;
	pbCommand[1] = 0xB6;
	pbCommand[2] = (BYTE)nKeyId;
	pbCommand[3] = (BYTE)nKeyType;
	pbCommand[4] = 0x01;
	if(!SendCommand(pbCommand, sizeof(pbCommand), pbRespond, &cbRespond, NULL))
		return FALSE;

	cErrCount = pbRespond[0];

	return TRUE;
}


//-------------------------------------------------------------------
//	���ܣ�
//		��ʼ��FAT�ļ��ڴ�ӳ��
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::cpuInitFatFile()
{
	memset(&m_fileFAT, 0, sizeof(m_fileFAT));
	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		ˢ��FAT����ڴ�ӳ��
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::cpuRefreshFatFile()
{
	if(GetCardType() != CPU_PKI)
		return FALSE;

	if(!cpuInitFatFile())
		return FALSE;

	if(!cpuReadFatFile())
		return FALSE;

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ӿ��ж���FAT�ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPReader::cpuReadFatFile()
{
	//�Ѵӿ��ж���,�����ٶ�
	if(m_fileFAT.dwTotalLen != 0)
		return TRUE; 

	//�����
	memset(&m_fileFAT, 0, sizeof(m_fileFAT));

	BeginTransaction();

	//��FAT�ļ�
	FILEHANDLE hFile = NULL;
	DWORD dwFileSize;
	if(!OpenFile(g_cPathTable.fileTablePath, &hFile, &dwFileSize)){
		EndTransaction();
		return FALSE;
	}

	if(dwFileSize > MAX_FAT_LEN)
		dwFileSize = MAX_FAT_LEN;
	m_fileFAT.dwTotalLen = dwFileSize;

	//�ȶ����ļ��е�ǰ�����ֽ�,�汾(1) + ��¼��(2)
	if(!ReadFile(hFile, g_cPathTable.fileTableHeadLen, m_fileFAT.cContent, NULL, 0)){
		CloseFile(hFile);
		EndTransaction();
		return FALSE;
	}

	//�����¼�ĳ���
	DWORD dwRecNum = MAKEWORD(m_fileFAT.cContent[2], m_fileFAT.cContent[1]);
	DWORD dwRecLen = dwRecNum*g_cPathTable.fileTableRecLen;

	//��ȡFAT����
	BOOL bRetVal = ReadFile(
		hFile, dwRecLen, m_fileFAT.cContent + g_cPathTable.fileTableHeadLen, NULL, g_cPathTable.fileTableHeadLen
		);

	CloseFile(hFile);
	EndTransaction();

	return bRetVal;
}


//-------------------------------------------------------------------
//	���ܣ�
//		���һ��FAT����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		BYTE path[2]
//		WORD flag
//		DWORD dwSize
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::cpuAddFatFileItem(
	BYTE path[2],
	WORD flag,
	DWORD dwSize
	)
{
	//FAT���ļ�������
	BYTE* pfiletable = m_fileFAT.cContent;

	//����ƫ����
	DWORD dwNum = (pfiletable[1]<<8) + pfiletable[2];
	DWORD dwOffset = g_cPathTable.fileTableHeadLen + dwNum*g_cPathTable.fileTableRecLen;

	FILEHANDLE hFile;
	if(!OpenFile(g_cPathTable.fileTablePath, &hFile, NULL))
		return FALSE;
	
	//�����µı���
	BYTE buf[6];
	buf[0] = path[0];
	buf[1] = path[1];
	buf[2] = BYTE(flag>>8);
	buf[3] = BYTE(flag);
	buf[4] = BYTE(dwSize>>8);
	buf[5] = BYTE(dwSize);
	if(!WriteFile(hFile, buf, 6, dwOffset)){
		CloseFile(hFile);
		return FALSE;
	}
	memcpy(pfiletable + dwOffset, buf, 6);

	//���ı������Ŀ
	buf[0] = BYTE((dwNum + 1)>>8);
	buf[1] = BYTE(dwNum + 1);
	BOOL bRetVal = WriteFile(hFile, buf, 2, 1);
	CloseFile(hFile);
	if(bRetVal == TRUE)
		memcpy(pfiletable + 1, buf, 2);

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		����FAT�������ļ���ʹ�ñ���λ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		BYTE path[2]
//		BOOL bDeleted
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::cpuSetFileUseableFlag(
	BYTE path[2],
	BOOL bDeleted
	)
{
	BYTE* pfiletable = m_fileFAT.cContent;

	//ȷ���ļ���Ӧ��FAT�����λ��
	DWORD dwNum = (pfiletable[1]<<8) + pfiletable[2];
	DWORD dwOffset = 0;
	for(DWORD i = 0; i < dwNum; i++){
		dwOffset = g_cPathTable.fileTableHeadLen + i*g_cPathTable.fileTableRecLen;
		if(memcmp(pfiletable + dwOffset, path, 2) == 0)
			break;
	}
	//û���ҵ���Ӧ���ļ�
	if (i == dwNum) return FALSE;

	dwOffset += 2;
	BYTE flag = pfiletable[dwOffset] & 0xfe;
	if(bDeleted)
		flag |= FILE_UNUSED;
	else
		flag |= FILE_USED;
	
	//���±�־λ
	FILEHANDLE hFile = NULL;
	if(!OpenFile(g_cPathTable.fileTablePath, &hFile, NULL))
		return FALSE;
	BOOL bRetVal = WriteFile(hFile, &flag, 1, dwOffset);
	CloseFile(hFile);
	if(bRetVal)
		pfiletable[dwOffset] = flag;

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡCPU���п��õ��ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		WORD flag
//		DWORD dwSize
//		BYTE pPath[2]
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPReader::cpuGetWorkableFile(
	WORD flag,
	DWORD dwSize,
	BYTE pPath[2]
	)
{
	BOOL rv;
	ULONG path = 0;
	BYTE* pfiletable = m_fileFAT.cContent;
    BYTE byFlag = BYTE(flag&0x00ff);
	byFlag = byFlag&0xfe|FILE_UNUSED;
	ULONG i = 0;
	ULONG ulRecNum = (pfiletable[1]<<8) + pfiletable[2];
	ULONG ulOffset = 0;
	ULONG ulRemain = -1;
	ULONG ulSize = 0;
	ULONG ulPath = 0;
	ULONG ulExPath = 0;
	ULONG exPath = 0;
	

	ULONG ulPathStart = 0;
	ULONG ulExPathStart = 0;
	switch (byFlag&0xfe)
	{
	case FILETYPE_DATA:
		ulPathStart = (g_cPathTable.dataStartPath[0]<<8 )
			+ g_cPathTable.dataStartPath[1];
		break;
	case FILETYPE_CERT:
		ulPathStart = (g_cPathTable.certStartPath[0]<<8 )
			+ g_cPathTable.certStartPath[1];
		break;
	case FILETYPE_SK:
		ulPathStart = (g_cPathTable.skStartPath[0]<<8 )
			+ g_cPathTable.skStartPath[1];
		break;
	case FILETYPE_PUK:
		ulPathStart = (g_cPathTable.pukStartPath[0]<<8) 
			+ g_cPathTable.pukStartPath[1];
		break;
	case FILETYPE_PRK:
	case FILETYPE_PRKEX:
		ulPathStart = (g_cPathTable.prkStartPath[0]<<8)
			+ g_cPathTable.prkStartPath[1];
		ulExPathStart = (g_cPathTable.prkexStarPath[0]<<8)
			+ g_cPathTable.prkexStarPath[1];
		break;
	case FILETYPE_PUK_ECC:
		ulPathStart = (g_cPathTable.eccpukStartPath[0]<<8) 
			+ g_cPathTable.eccpukStartPath[1];
		break;
	case FILETYPE_PRK_ECC:
	case FILETYPE_PRKEX_ECC:
		ulPathStart = (g_cPathTable.eccprkStartPath[0]<<8)
			+ g_cPathTable.eccprkStartPath[1];
		ulExPathStart = (g_cPathTable.eccprkexStarPath[0]<<8)
			+ g_cPathTable.eccprkexStarPath[1];
		break;
	}

	switch (byFlag&0xfe)
	{
	//����dwSizeС���ļ����м�¼��dwSize����ӽ����ļ������û���򴴽�
	case FILETYPE_DATA:
	case FILETYPE_CERT:
	case FILETYPE_SK:
		ulPath = ulPathStart - 1;
		for	( i=0; i<ulRecNum; i++)
		{
			ulOffset = g_cPathTable.fileTableHeadLen+i*g_cPathTable.fileTableRecLen;
			ulSize = (pfiletable[ulOffset+4]<<8) + pfiletable[ulOffset+5];
			ULONG ulCurPath = (pfiletable[ulOffset]<<8) + pfiletable[ulOffset+1];
			if ((ulCurPath > ulPath)&&((pfiletable[ulOffset+3]&0xfe) == (byFlag&0xfe)))
				ulPath = ulCurPath;
			if ((pfiletable[ulOffset+3] == byFlag)&&(ulCurPath != 0))
			{
				if(dwSize <= ulSize)
				{
					if (ulRemain>(ulSize - dwSize))
					{
						ulRemain = (ulSize - dwSize);
						path = ulCurPath;
						if (ulRemain == 0)
							break;
					}
				}
			}
		}
		if (path == 0)
		{
			if (ulRecNum == 0)
				ulPath = ulPathStart;
			else
				ulPath ++;

			//û���ҵ��������õĿռ䣬�������ļ�
			//����filetable�������Ӧ����Ŀ
			BYTE NewFilePath[2];
			NewFilePath[0] = BYTE(ulPath>>8);
			NewFilePath[1] = BYTE(ulPath);
			rv = cpuAddFatFileItem(NewFilePath, flag&0xff00|FILE_USED, dwSize);
			if (rv != TRUE)
				return rv;

			BYTE readAuth, writeAuth;
			if(IS_READ_NEEDAUTH(BYTE((flag&0x0C00)>>8)))
				readAuth = g_cPathTable.eitherNeed;
			else
				readAuth = g_cPathTable.free;
			if(IS_WRITE_NEEDAUTH(BYTE((flag&0x0300)>>8)))
				writeAuth = g_cPathTable.eitherNeed;
			else
				writeAuth = g_cPathTable.free;
			rv = cpuCreateEF(NewFilePath, dwSize, 0x00, readAuth, writeAuth);
			if (rv != TRUE)
				return rv;
			path = ulPath;
		}
		else
		{
			BYTE OldFilePath[2];
			OldFilePath[0] = BYTE(path >> 8);
			OldFilePath[1] = BYTE(path);
			rv = cpuSetFileUseableFlag(OldFilePath, FALSE);
			if (rv != TRUE)
				return rv;
		}
		break;
	//����dwSize�����ļ����м�¼��dwSize���ļ������û���򴴽�
	case FILETYPE_PUK:
		ulPath = ulPathStart - 1;
		for	( i=0; i<ulRecNum; i++)
		{
			ulOffset = g_cPathTable.fileTableHeadLen+i*g_cPathTable.fileTableRecLen;
			ulSize = (pfiletable[ulOffset+4]<<8) + pfiletable[ulOffset+5];
			ULONG ulCurPath = (pfiletable[ulOffset]<<8) + pfiletable[ulOffset+1];
			if ((ulCurPath > ulPath)&&((pfiletable[ulOffset+3]&0xfe) == (byFlag&0xfe)))
				ulPath = ulCurPath;

			if ((pfiletable[ulOffset+3] == byFlag)&&(ulCurPath != 0))
			{
				if(dwSize == ulSize)
				{
					path = ulCurPath;
					break;
				}
			}
		}
		if (path == 0)
		{
			if (ulRecNum == 0)
				ulPath = ulPathStart;
			else
				ulPath ++;

			//û���ҵ��������õĿռ䣬�������ļ�
			//����filetable�������Ӧ����Ŀ
			BYTE NewFilePath[2];
			NewFilePath[0] = BYTE(ulPath>>8);
			NewFilePath[1] = BYTE(ulPath);
			rv = cpuAddFatFileItem(NewFilePath, flag&0xff00|FILE_USED|FILETYPE_PUK, dwSize);
			if (rv != TRUE)
				return rv;

			BYTE readAuth, writeAuth;
			if(IS_READ_NEEDAUTH(BYTE((flag&0x0C00)>>8)))
				readAuth = g_cPathTable.eitherNeed;
			else
				readAuth = g_cPathTable.free;
			if(IS_WRITE_NEEDAUTH(BYTE((flag&0x0300)>>8)))
				writeAuth = g_cPathTable.eitherNeed;
			else
				writeAuth = g_cPathTable.free;
			BYTE* pbUseAuth = NULL;
			//if(GetCardType() == CPU_PKI&&(writeAuth!=0x0f))
				pbUseAuth = &writeAuth;
			rv = cpuCreateEF(NewFilePath, dwSize, 0x09, readAuth, writeAuth, pbUseAuth);
			
			if (rv != TRUE)
				return rv;
			path = ulPath;
		}
		else
		{
			BYTE OldFilePath[2];
			OldFilePath[0] = BYTE(path >> 8);
			OldFilePath[1] = BYTE(path);
			rv = cpuSetFileUseableFlag(OldFilePath, FALSE);
			if (rv != TRUE)
				return rv;
		}
		break;
	//����˽Կ����Ҫ����FILETYPE_PRK��FILETYPE_PRKEX�������ͣ���dwSize��ȵ��ļ���
	//�������û�л�������һ��û�У��򴴽���Ӧ���ļ�
	case FILETYPE_PRK:
	case FILETYPE_PRKEX:
		ulExPath = ulExPathStart -1;
		//�Ȳ���FILETYPE_PRKEX
		byFlag = byFlag&0xf1|FILETYPE_PRKEX;
		for	( i=0; i<ulRecNum; i++)
		{
			ulOffset = g_cPathTable.fileTableHeadLen+i*g_cPathTable.fileTableRecLen;
			ulSize = (pfiletable[ulOffset+4]<<8) + pfiletable[ulOffset+5];
			ULONG ulCurPath = (pfiletable[ulOffset]<<8) + pfiletable[ulOffset+1];
			if ((ulCurPath > ulExPath)&&((pfiletable[ulOffset+3]&0xfe) == (byFlag&0xfe)))
				ulExPath = ulCurPath;

			if ((pfiletable[ulOffset+3] == byFlag)&&(ulCurPath != 0))
			{
				if(dwSize == ulSize)
				{
					exPath = ulCurPath;
					break;
				}
			}
		}
		if (exPath == 0)
		{
			if (ulRecNum == 0)
				ulExPath = ulExPathStart;
			else
				ulExPath ++;

			//û���ҵ��������õĿռ䣬�������ļ�
			//����filetable�������Ӧ����Ŀ
			BYTE NewFilePath[2];
			NewFilePath[0] = BYTE(ulExPath>>8);
			NewFilePath[1] = BYTE(ulExPath);
			rv = cpuAddFatFileItem(NewFilePath, flag&0xff00|FILE_USED|FILETYPE_PRKEX, dwSize);
			if (rv != TRUE)
				return rv;

			//����˽Կ��չ�ļ�,�����дȨ�޷ſ�
			BYTE readAuth, writeAuth;
//			if(IS_READ_NEEDAUTH(flag))
//				readAuth = g_cPathTable.eitherNeed;
//			else
//				readAuth = g_cPathTable.free;
//			if(IS_WRITE_NEEDAUTH(flag))
//				writeAuth = g_cPathTable.eitherNeed;
//			else
//				writeAuth = g_cPathTable.free;
			readAuth = g_cPathTable.free;
			writeAuth = g_cPathTable.free;
			rv = cpuCreateEF(NewFilePath, dwSize, 0x00, readAuth, writeAuth);
			if (rv != TRUE)
				return rv;
			path = ulExPath - ulExPathStart + ulPathStart;

			byFlag = byFlag&0xf1|FILETYPE_PRK;

			if (dwSize == g_cPathTable.rsaPrkExFileLen)
				dwSize = g_cPathTable.rsaPrkFileLen;
			else
				return FALSE;

			NewFilePath[0] = BYTE(path>>8);
			NewFilePath[1] = BYTE(path);
			rv = cpuAddFatFileItem(NewFilePath, flag&0xff00|FILE_USED|FILETYPE_PRK, dwSize);
			if (rv != TRUE)
				return rv;

			if(IS_READ_NEEDAUTH(BYTE((flag&0x0C00)>>8)))
				readAuth = g_cPathTable.eitherNeed;
			else
				readAuth = g_cPathTable.free;
			if(IS_WRITE_NEEDAUTH(BYTE((flag&0x0300)>>8)))
				writeAuth = g_cPathTable.eitherNeed;
			else
				writeAuth = g_cPathTable.free;
			BYTE* pbUseAuth = NULL;
			//if(GetCardType() == CPU_PKI&&(writeAuth!=0x0f))
				pbUseAuth = &writeAuth;
			rv = cpuCreateEF(NewFilePath, dwSize, 0x08, readAuth, writeAuth, pbUseAuth);
			if (rv != TRUE)
				return rv;
		}
		else
		{
			BYTE OldFilePath[2];
			OldFilePath[0] = BYTE(ulExPath >> 8);
			OldFilePath[1] = BYTE(ulExPath);
			rv = cpuSetFileUseableFlag(OldFilePath, FALSE);
			if (rv != TRUE)
				return rv;

			//�ҵ��˿������õĿռ�
			path = ulExPath - (g_cPathTable.prkexStarPath[0]<<8)
				- g_cPathTable.prkexStarPath[1]
				+ (g_cPathTable.prkStartPath[0] << 8)
				+ g_cPathTable.prkStartPath[1];
			byFlag = byFlag&0xf1|FILETYPE_PRK;

			//���ļ����в�����û�и���ļ�¼
			for	( i=0; i<ulRecNum; i++)
			{
				ulOffset = g_cPathTable.fileTableHeadLen+i*g_cPathTable.fileTableRecLen;
				ULONG ulCurPath = (pfiletable[ulOffset]<<8) + pfiletable[ulOffset+1];
				if (ulCurPath == path)
				{
					break;
				}
			}

			//���û�и����¼���򴴽�
			if (i == ulRecNum)
			{
				BYTE NewFilePath[2];
				NewFilePath[0] = BYTE(path>>8);
				NewFilePath[1] = BYTE(path);
				rv = cpuAddFatFileItem(NewFilePath, flag&0xff00|FILE_USED|FILETYPE_PRK, dwSize);
				if (rv != TRUE)
					return rv;

				BYTE readAuth, writeAuth;
				if(IS_READ_NEEDAUTH(BYTE((flag&0x0C00)>>8)))
					readAuth = g_cPathTable.eitherNeed;
				else
					readAuth = g_cPathTable.free;
				if(IS_WRITE_NEEDAUTH(BYTE((flag&0x0300)>>8)))
					writeAuth = g_cPathTable.eitherNeed;
				else
					writeAuth = g_cPathTable.free;
				BYTE* pbUseAuth = NULL;
				//if(GetCardType() == CPU_PKI&&(writeAuth!=0x0f))
					pbUseAuth = &writeAuth;
				rv = cpuCreateEF(NewFilePath, dwSize, 0x08, readAuth, writeAuth, pbUseAuth);
				if (rv != TRUE)
					return rv;
			}
			else
			{
				BYTE OldFilePath[2];
				OldFilePath[0] = BYTE(path >> 8);
				OldFilePath[1] = BYTE(path);
				rv = cpuSetFileUseableFlag(OldFilePath, FALSE);
				if (rv != TRUE)
				return rv;
			}
		}
		break;
		//����dwSize�����ļ����м�¼��dwSize���ļ������û���򴴽�
	case FILETYPE_PUK_ECC:
		ulPath = ulPathStart - 1;
		for	( i=0; i<ulRecNum; i++)
		{
			ulOffset = g_cPathTable.fileTableHeadLen+i*g_cPathTable.fileTableRecLen;
			ulSize = (pfiletable[ulOffset+4]<<8) + pfiletable[ulOffset+5];
			ULONG ulCurPath = (pfiletable[ulOffset]<<8) + pfiletable[ulOffset+1];
			if ((ulCurPath > ulPath)&&((pfiletable[ulOffset+3]&0xfe) == (byFlag&0xfe)))
				ulPath = ulCurPath;

			if ((pfiletable[ulOffset+3] == byFlag)&&(ulCurPath != 0))
			{
				if(dwSize == ulSize)
				{
					path = ulCurPath;
					break;
				}
			}
		}
		if (path == 0)
		{
			if (ulRecNum == 0)
				ulPath = ulPathStart;
			else
				ulPath ++;

			//û���ҵ��������õĿռ䣬�������ļ�
			//����filetable�������Ӧ����Ŀ
			BYTE NewFilePath[2];
			NewFilePath[0] = BYTE(ulPath>>8);
			NewFilePath[1] = BYTE(ulPath);
			rv = cpuAddFatFileItem(NewFilePath, flag&0xff00|FILE_USED|FILETYPE_PUK_ECC, dwSize);
			if (rv != TRUE)
				return rv;

			BYTE readAuth, writeAuth;
			if(IS_READ_NEEDAUTH(BYTE((flag&0x0C00)>>8)))
				readAuth = g_cPathTable.eitherNeed;
			else
				readAuth = g_cPathTable.free;
			if(IS_WRITE_NEEDAUTH(BYTE((flag&0x0300)>>8)))
				writeAuth = g_cPathTable.eitherNeed;
			else
				writeAuth = g_cPathTable.free;
			BYTE* pbUseAuth = NULL;
			//if(GetCardType() == CPU_PKI&&(writeAuth!=0x0f))
				pbUseAuth = &writeAuth;
			rv = cpuCreateEF(NewFilePath, dwSize, 0x0E, readAuth, writeAuth, pbUseAuth);
			
			if (rv != TRUE)
				return rv;
			path = ulPath;
		}
		else
		{
			BYTE OldFilePath[2];
			OldFilePath[0] = BYTE(path >> 8);
			OldFilePath[1] = BYTE(path);
			rv = cpuSetFileUseableFlag(OldFilePath, FALSE);
			if (rv != TRUE)
				return rv;
		}
		break;
	//����˽Կ����Ҫ����FILETYPE_PRK_ECC��FILETYPE_PRKEX_ECC�������ͣ���dwSize��ȵ��ļ���
	//�������û�л�������һ��û�У��򴴽���Ӧ���ļ�
	case FILETYPE_PRK_ECC:
	case FILETYPE_PRKEX_ECC:
		ulExPath = ulExPathStart-1;
		//�Ȳ���FILETYPE_PRKEX
		byFlag = byFlag&0xf1|FILETYPE_PRKEX_ECC;
		for	( i=0; i<ulRecNum; i++)
		{
			ulOffset = g_cPathTable.fileTableHeadLen+i*g_cPathTable.fileTableRecLen;
			ulSize = (pfiletable[ulOffset+4]<<8) + pfiletable[ulOffset+5];
			ULONG ulCurPath = (pfiletable[ulOffset]<<8) + pfiletable[ulOffset+1];
			if ((ulCurPath > ulExPath)&&((pfiletable[ulOffset+3]&0xfe) == (byFlag&0xfe)))
				ulExPath = ulCurPath;

			if ((pfiletable[ulOffset+3] == byFlag)&&(ulCurPath != 0))
			{
				if(dwSize == ulSize)
				{
					exPath = ulCurPath;
					break;
				}
			}
		}
		if (exPath == 0)
		{
			if (ulRecNum == 0)
				ulExPath = ulExPathStart;
			else
				ulExPath ++;

			//û���ҵ��������õĿռ䣬�������ļ�
			//����filetable�������Ӧ����Ŀ
			BYTE NewFilePath[2];
			NewFilePath[0] = BYTE(ulExPath>>8);
			NewFilePath[1] = BYTE(ulExPath);
			rv = cpuAddFatFileItem(NewFilePath, flag&0xff00|FILE_USED|FILETYPE_PRKEX_ECC, dwSize);
			if (rv != TRUE)
				return rv;

			//����˽Կ��չ�ļ�,�����дȨ�޷ſ�
			BYTE readAuth, writeAuth;

			readAuth = g_cPathTable.free;
			writeAuth = g_cPathTable.free;
			rv = cpuCreateEF(NewFilePath, dwSize, 0x00, readAuth, writeAuth);
			if (rv != TRUE)
				return rv;
			path = ulExPath - ulExPathStart + ulPathStart;

			byFlag = byFlag&0xf1|FILETYPE_PRK_ECC;

			if (dwSize == g_cPathTable.eccPrkExFileLen)
				dwSize = g_cPathTable.eccPrkFileLen;
			else
				return FALSE;

			NewFilePath[0] = BYTE(path>>8);
			NewFilePath[1] = BYTE(path);
			rv = cpuAddFatFileItem(NewFilePath, flag&0xff00|FILE_USED|FILETYPE_PRK_ECC, dwSize);
			if (rv != TRUE)
				return rv;

			if(IS_READ_NEEDAUTH(BYTE((flag&0x0C00)>>8)))
				readAuth = g_cPathTable.eitherNeed;
			else
				readAuth = g_cPathTable.free;
			if(IS_WRITE_NEEDAUTH(BYTE((flag&0x0300)>>8)))
				writeAuth = g_cPathTable.eitherNeed;
			else
				writeAuth = g_cPathTable.free;
			BYTE* pbUseAuth = NULL;
			//if(GetCardType() == CPU_PKI&&(writeAuth!=0x0f))
				pbUseAuth = &writeAuth;
			rv = cpuCreateEF(NewFilePath, dwSize, 0x0C, readAuth, writeAuth, pbUseAuth);
			if (rv != TRUE)
				return rv;
		}
		else
		{
			BYTE OldFilePath[2];
			OldFilePath[0] = BYTE(ulExPath >> 8);
			OldFilePath[1] = BYTE(ulExPath);
			rv = cpuSetFileUseableFlag(OldFilePath, FALSE);
			if (rv != TRUE)
				return rv;

			//�ҵ��˿������õĿռ�
			path = ulExPath - (g_cPathTable.eccprkexStarPath[0]<<8)
				- g_cPathTable.eccprkexStarPath[1]
				+ (g_cPathTable.eccprkStartPath[0] << 8)
				+ g_cPathTable.eccprkStartPath[1];
			byFlag = byFlag&0xf1|FILETYPE_PRK_ECC;

			//���ļ����в�����û�и���ļ�¼
			for	( i=0; i<ulRecNum; i++)
			{
				ulOffset = g_cPathTable.fileTableHeadLen+i*g_cPathTable.fileTableRecLen;
				ULONG ulCurPath = (pfiletable[ulOffset]<<8) + pfiletable[ulOffset+1];
				if (ulCurPath == path)
				{
					break;
				}
			}

			//���û�и����¼���򴴽�
			if (i == ulRecNum)
			{
				BYTE NewFilePath[2];
				NewFilePath[0] = BYTE(path>>8);
				NewFilePath[1] = BYTE(path);
				rv = cpuAddFatFileItem(NewFilePath, flag&0xff00|FILE_USED|FILETYPE_PRK_ECC, dwSize);
				if (rv != TRUE)
					return rv;

				BYTE readAuth, writeAuth;
				if(IS_READ_NEEDAUTH(BYTE((flag&0x0C00)>>8)))
					readAuth = g_cPathTable.eitherNeed;
				else
					readAuth = g_cPathTable.free;
				if(IS_WRITE_NEEDAUTH(BYTE((flag&0x0300)>>8)))
					writeAuth = g_cPathTable.eitherNeed;
				else
					writeAuth = g_cPathTable.free;
				BYTE* pbUseAuth = NULL;
				//if(GetCardType() == CPU_PKI&&(writeAuth!=0x0f))
					pbUseAuth = &writeAuth;
				rv = cpuCreateEF(NewFilePath, dwSize, 0x0C, readAuth, writeAuth, pbUseAuth);
				if (rv != TRUE)
					return rv;
			}
			else
			{
				BYTE OldFilePath[2];
				OldFilePath[0] = BYTE(path >> 8);
				OldFilePath[1] = BYTE(path);
				rv = cpuSetFileUseableFlag(OldFilePath, FALSE);
				if (rv != TRUE)
				return rv;
			}
		}
		break;
	}
	
	pPath[0] = BYTE(path>>8);
	pPath[1] = BYTE(path);

	return TRUE;
}

