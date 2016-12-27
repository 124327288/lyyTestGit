#include "stdafx.h"
#include "reader.h"
#include "md5.h"
#include "des.h"
#include "HelperFunc.h"
#include "Mac.h"

/////////////////////////////////////////////////////////////////////
//	各种卡片的ATR数据

//计算MAC的密钥, 写入KEY中作应用维护密钥
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
//	功能：
//		构造函数
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
CCSPReader::CCSPReader()
{
	//成员变量初始化
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
	
	//建立资源上下文
	EstablishContext();
}

//-------------------------------------------------------------------
//	功能：
//		析构函数
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
CCSPReader::~CCSPReader()
{
	ClearTokenInfoBuffer();

	ReleaseContext();
	//清空读卡器的名字
	SetName(NULL);
}

//
//-------------------------------------------------------------------
//	功能：
//		读取文件系统版本信息
//
//	返回：
//		成功或者文件不存在,返回成功,异常情况返回失败
//
//  参数：
//		无
//
//  说明：如果没有读到这个文件,把版本号设到旧版本号上
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
//	功能：
//		获得文件系统版本信息, 传入一个信息结构指针
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
void CCSPReader::GetFileSysVer(LPCSP_FILESYS_VER pFileSysVer)
{
	memcpy(pFileSysVer, &m_FileSys, sizeof(m_FileSys));
}
//-------------------------------------------------------------------
//	功能：
//		获取读卡器的真正索引
//
//	返回：
//		读卡器的真正索引
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
int CCSPReader::GetRealIndex()
{
	return (m_nIndex - ((int)GetType())*1000);
}

//-------------------------------------------------------------------
//	功能：
//		清空缓存的Token信息
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
void CCSPReader::ClearTokenInfoBuffer()
{
	if(m_pTokenInfo != NULL){
		delete m_pTokenInfo;
		m_pTokenInfo = NULL;
	}
}

//-------------------------------------------------------------------
//	功能：
//		设置索引
//
//	返回：
//		无
//
//  参数：
//		int nIndex	索引
//
//  说明：
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
//	功能：
//		设置名字
//
//	返回：
//		无
//
//  参数：
//		LPCTSTR szName	名字
//
//  说明：
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
//	功能：
//		建立资源上下文
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		DWORD dwScope	范围
//
//  说明：
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
//	功能：
//		释放资源上下文
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		无
//
//  说明：
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
//	功能：
//		开始一个事务
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		无
//
//  说明：
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
//	功能：
//		结束一个事务
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		DWORD dwDisposition	结束事务时对卡操作的描述
//
//  说明：
//		dwDisposition可取如下值
//
//		值					意义 
//		SCARD_LEAVE_CARD	不做任何处理 
//		SCARD_RESET_CARD	将卡复位 
//		SCARD_UNPOWER_CARD  将卡下电 
//		SCARD_EJECT_CARD	将卡弹出 
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
//	功能：
//		复位	 
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		BYTE* pbATR			ATR命令
//		DWORD* pdwATR		ATR的长度
//		ResetMode mode		复位模式
//
//  说明：
//-------------------------------------------------------------------
BOOL
CCSPReader::Reset(
	BYTE* pbATR,
	DWORD* pdwATR,
	ResetMode mode /*=WARM*/
	)
{
	//如果未连接智能卡，先建立与智能卡的连接
	if(!IsConnectCard()){
		if(!ConnectCard(FALSE))
			return FALSE;
	}

	//获取复位信息
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
					//可能从未进行过冷复位,因此需进行一次冷复位
					//(针对读卡器和智能卡的硬件形状态)
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

		TRACE_LINE("复位信息:\n");
		TRACE_DATA(pbATR, dwATRBufferLen);
	}

	if(!bRetVal){
		TRACE_LINE("Fail to get ATR!\n");
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		获取ATR信息
//
//	返回：
//		TRUE：成功	FALSE：失败
//
//  参数：
//		BYTE* pbATR				返回的ATR
//		DWORD* pdwATR			返回的ATR的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL
CCSPReader::GetATR(BYTE* pbATR, DWORD* pdwATR)
{
	if(!IsConnectCard()){
		return FALSE;
	}

	//获取复位信息
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

		TRACE_LINE("复位信息:\n");
		TRACE_DATA(pbATR, dwATRBufferLen);
	}

	if(!bRetVal){
		TRACE_LINE("Fail to get ATR!\n");
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		连接智能卡
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		BOOL bCheckCardValid	是否检测卡的合法性
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPReader::ConnectCard(BOOL bCheckCardValid)
{
	//如果已连接，直接返回
	if(IsConnectCard())
		return TRUE;

	//连接智能卡
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
			//打开读卡器
			TYKEYHANDLE hTYKey = NULL;
			TYKEYSTATUS status = g_TYKeyFuncHolder.m_listFunc.pfnTYKey_OpenTYKey(
				GetRealIndex(), &hTYKey
				);
			
			//判断智能卡是否存在
			if(status == STATUS_TYKEY_SUCCESS){
				int nExistFlag = g_TYKeyFuncHolder.m_listFunc.pfnTYKey_CardExist(hTYKey);
				if(nExistFlag){
					m_hCard = (CARDHANDLE)hTYKey;
					bRetVal = TRUE;
				}
				else{
					//关闭读卡器
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
			//打开读卡器
			int hReader = g_TYReaderFuncHolder.m_listFunc.pfnTY_Open(57600, GetRealIndex());

			//判断智能卡是否存在
			if(hReader > 0){
				WORD status = g_TYReaderFuncHolder.m_listFunc.pfnTY_CardExist(hReader);
				if(status == TYREADER_STATUS_SUCCESS){
					m_hCard = hReader;
					bRetVal = TRUE;
				}
				else{
					//关闭读卡器
					g_TYReaderFuncHolder.m_listFunc.pfnTY_Close(hReader);
				}
			}
		}
	}

	if(!bRetVal)
		return FALSE;

	//获取ATR,并决定卡片类型
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
				//检测是否为合法的智能卡
				if(!cpuSelectDF(TYCSP) && bCheckCardValid)
					bRetVal = FALSE;
			}

			if(bRetVal){
				//读出卡中的FAT文件
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
//	功能：
//		断开与智能卡的连接
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		无
//
//  说明：
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
//	功能：
//		检测智能卡是否还处于连接状态
//
//	返回：
//		TRUE:处于连接		FALSE:不处于连接
//
//  参数：
//		无
//
//  说明：
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
//	功能：
//		检测读卡器中是否存在卡片
//
//	返回：
//		TRUE:存在	FALSE:不存在
//
//  参数：
//		无
//
//  说明：
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
			//判断卡片是否存在
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
//	功能：
//		发送命令
//
//	返回：
//		TRUE:成功(SW1SW2 = 0x9000或0x61XX)	FALSE:失败
//
//  参数：
//		BYTE* pbCommand			命令体
//		DWORD dwCommandLen		命令体的长度
//		BYTE* pbRespond			响应体
//		DWORD* pdwRespondLen	响应体的长度
//		WORD* pwStatus			状态字节
//
//  说明：
//		如果不需要响应体或状态字节,只需赋予NULL
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

	TRACE_LINE("命令：");
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

		TRACE_LINE("响应数据：");
		TRACE_DATA(cRecvBuffer, cbRecvLength - 2);
		TRACE_LINE("状态码：%04X\n", SW);

		if(pwStatus != NULL)
			*pwStatus = SW;


		if(SW == 0x9000){
			if(pbRespond){
				//要过虑掉SW1 SW2
				*pdwRespondLen = cbRecvLength - 2;
				if(*pdwRespondLen > 0)
					memcpy(pbRespond, cRecvBuffer, *pdwRespondLen);
			}
		}
		else{
			//还有响应数据可取
			if(HIBYTE(SW) == 0x61){
				if(pbRespond != NULL){ 
					cbRecvLength = sizeof(cRecvBuffer);
					BYTE cmdGetResponse[5];
					cmdGetResponse[0] = 0x00;			//CLS
					cmdGetResponse[1] = 0xC0;			//INS
					cmdGetResponse[2] = 0x00;			//P1
					cmdGetResponse[3] = 0x00;			//P2
					cmdGetResponse[4] = LOBYTE(SW);		//LE

					TRACE_LINE("命令：");
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

					TRACE_LINE("响应数据：");
					TRACE_DATA(cRecvBuffer, cbRecvLength - 2);
					TRACE_LINE("状态码：%04X\n", SW);

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
		TRACE_LINE("状态码：%04X\n", SW);

		if(pwStatus != NULL)
			*pwStatus = SW;

		if(SW == 0x9000){
			TRACE_LINE("响应数据：");
			TRACE_DATA(cRecvBuffer, cbRecvLength);
			if(pbRespond){
				*pdwRespondLen = cbRecvLength;
				if(*pdwRespondLen > 0)
					memcpy(pbRespond, cRecvBuffer, *pdwRespondLen);
			}
		}
		else{
			//还有响应数据可取
			if(HIBYTE(SW) == 0x61){
				if(pbRespond != NULL){ 
					cbRecvLength = sizeof(cRecvBuffer);
					BYTE cmdGetResponse[5];
					cmdGetResponse[0] = 0x00;			//CLS
					cmdGetResponse[1] = 0xC0;			//INS
					cmdGetResponse[2] = 0x00;			//P1
					cmdGetResponse[3] = 0x00;			//P2
					cmdGetResponse[4] = LOBYTE(SW);		//LE

					TRACE_LINE("命令：");
					TRACE_DATA(cmdGetResponse, sizeof(cmdGetResponse));

					status = g_TYKeyFuncHolder.m_listFunc.pfnTYKey_SendCommand(
						(TYKEYHANDLE)m_hCard, sizeof(cmdGetResponse), cmdGetResponse, (int* )&cbRecvLength, cRecvBuffer
						);
					SW = status;
					TRACE_LINE("状态码：%04X\n", SW);

					if(pwStatus != NULL)
						*pwStatus = SW;

					if(SW == 0x9000){
						TRACE_LINE("响应数据：");
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
		TRACE_LINE("状态码：%04X\n", SW);

		if(SW == 0x9000){
			TRACE_LINE("响应数据：");
			TRACE_DATA(cRecvBuffer, cbRecvLength);
			if(pbRespond){
				*pdwRespondLen = cbRecvLength;
				if(*pdwRespondLen > 0)
					memcpy(pbRespond, cRecvBuffer, *pdwRespondLen);
			}
		}
		else{
			//还有响应数据可取
			if(HIBYTE(SW) == 0x61){
				if(pbRespond != NULL){ 
					cbRecvLength = sizeof(cRecvBuffer);
					BYTE cmdGetResponse[5];
					cmdGetResponse[0] = 0x00;			//CLS
					cmdGetResponse[1] = 0xC0;			//INS
					cmdGetResponse[2] = 0x00;			//P1
					cmdGetResponse[3] = 0x00;			//P2
					cmdGetResponse[4] = LOBYTE(SW);		//LE

					TRACE_LINE("命令：");
					TRACE_DATA(cmdGetResponse, sizeof(cmdGetResponse));

					SW = g_TYReaderFuncHolder.m_listFunc.pfnTY_tsi_api(
						(int)m_hCard, sizeof(cmdGetResponse), cmdGetResponse, 
						(WORD* )&cbRecvLength, cRecvBuffer);
					if(pwStatus != NULL)
						*pwStatus = SW;
					TRACE_LINE("状态码：%04X\n", SW);

					if(SW == 0x9000){
						TRACE_LINE("响应数据：");
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
//	功能：
//		获取可用的文件
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		BYTE flag
//		DWORD dwSize
//		BYTE path[2]
//
//  说明：
//		尽量使用可重用空间,如果没有会创建一个
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
//	功能：
//		创建文件
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		BYTE path[2]			标识
//		DWORD dwSize			大小
//		FILEHANDLE* phFile		返回的文件句柄
//		BYTE type				文件类型
//		BYTE readAuth			读权限
//		BYTE writeAuth			写权限
//
//  说明：
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
//	功能：
//		删除文件
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		BYTE path[2]	标识	
//
//  说明：
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
//	功能：
//		打开文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		BYTE path[2]			标识			
//		FILEHANDLE* phFile		文件句柄
//		LPDWORD pdwFileSize		文件大小
//
//  说明：
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
//	功能：
//		读取文件
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		FILEHANDLE hFile				文件句柄
//		DWORD dwReadLen					读取的长度
//		LPBYTE pReadBuffer				读取的数据
//		LPDWORD pdwRealReadLen			实际返回的长度
//		DWORD dwOffset					偏移量
//
//  说明：
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
//	功能：
//		写文件
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		FILEHANDLE hFile			文件句柄
//		LPBYTE pWriteBuffer			写入的数据
//		DWORD dwWriteBufferLen		写入数据的长度
//		DWORD dwOffset				偏移量
//
//  说明：
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
//	功能：
//		关闭文件
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		FILEHANDLE hFile	文件句柄
//
//  说明：
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
//	功能：
//		格式化卡片
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		LPFORMATINFO pInfo	格式化信息
//
//  说明：
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
//	功能：
//		控除EEPROM
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		无
//
//  说明：
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
//	功能：
//		获取卡片信息
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		LPTOKENINFO pTokenInfo	获取的卡片信息
//		BOOL bReload			是否重新载入
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPReader::GetTokenInfo(
	LPTOKENINFO pTokenInfo,
	BOOL bReload
	)
{
	if(pTokenInfo == NULL)
		return FALSE;

	//如果已读过则直接返回结果
	if(m_pTokenInfo != NULL && !bReload){
		memcpy(pTokenInfo, m_pTokenInfo, sizeof(TOKENINFO));
		return TRUE;
	}

	ClearTokenInfoBuffer();
		
	//从智能卡中读取并解码
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

	//缓存
	if(bRetVal){
		m_pTokenInfo = new TOKENINFO;
		memcpy(m_pTokenInfo, pTokenInfo, sizeof(TOKENINFO));
		///////////////////////////////////////////////////////////////////////
		//读卡片硬件序列号替换
		HWReadCardSN(m_pTokenInfo->serialNumber, sizeof(m_pTokenInfo->serialNumber));
	}

	EndTransaction();
	return bRetVal;
}
//-------------------------------------------------------------------
//	功能：
//		读取硬件序列号
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		BYTE *	pbSN,		//返回硬件序列号
//		DWORD *	pdwLen		//返回序列号长度
//
//  说明：
//-------------------------------------------------------------------
BOOL CCSPReader::HWReadCardSN(char *szSN, int nMaxLen)
{
	if(GetCardType() != CPU_PKI)
		return FALSE;

	BYTE pbCmd[256];
	BYTE pbResp[256] = {0};
	DWORD dwRespLen = 256;
	//为了防止写最后的0时写暴了,加了个临时的
	CHAR szSnTemp[256] = {0};

	//外部认证
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
//	功能：
//		设置卡片信息
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		LPTOKENINFO pTokenInfo	要设置的卡片信息
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPReader::SetTokenInfo(
	LPTOKENINFO pTokenInfo
	)
{
	if(pTokenInfo == NULL)
		return FALSE;
	
	//新的Token信息的编码
	ByteArray baTokenInfo;
	if(!TokenInfoDEREncoding(pTokenInfo, baTokenInfo))
		return FALSE;

	//更新智能卡中的文件
	BeginTransaction();

	BOOL bRetVal = FALSE;
	FILEHANDLE hFile;
	if(OpenFile(g_cPathTable.tokenInfoPath, &hFile, NULL)){
		bRetVal = WriteFile(hFile, baTokenInfo.GetData(), baTokenInfo.GetSize(), 0);
		CloseFile(hFile);
	}

	EndTransaction();

	//缓存
	if(bRetVal){
		ClearTokenInfoBuffer();
		m_pTokenInfo = new TOKENINFO;
		memcpy(m_pTokenInfo, pTokenInfo, sizeof(TOKENINFO));
		///////////////////////////////////////////////////////////////////////
		//读卡片硬件序列号替换
		HWReadCardSN(m_pTokenInfo->serialNumber, sizeof(m_pTokenInfo->serialNumber));
	}

	return bRetVal;
}


//-------------------------------------------------------------------
//	功能：
//		以指定用户类型的身份登录
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		int nUserType		用户类型
//		LPBYTE pPIN			PIN
//		DWORD dwPINLen		PIN的长度
//		DWORD& dwRetryCount	剩余可重试的次数
//
//  说明：
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
	//	参数检测
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
	//	step1:将用户输入的密码作一次HASH运算，得到认证密钥
	//
	MD5 hash;
	BYTE key[16];
	hash.CalculateDigest(key, pPIN, dwPINLen);

	if(GetCardType() == CPU_PKI){
		//
		//	step2:从卡中取一4字节随机数并填充0x00至8字节
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
		//	step3:用认证密钥进行3-DES加密
		//
		DES_EDE_Encryption cipher(key);
		cipher.ProcessBlock(data);

		//
		//	step4:认证
		//
		BYTE bKeyID = (nUserType == UT_USER ? 0x02 : 0x01); 

		cCommand[0] = 0x00;							//CLA
		cCommand[1] = 0x82;							//INS
		cCommand[2] = 0x00;							//P1
		cCommand[3] = bKeyID;	//P2(密钥标识)
		cCommand[4] = 0x08;							//LC
		memcpy(&cCommand[5], data, 8);				//DATA

		bRetVal = SendCommand(cCommand, 13, NULL, NULL, &SW);

		if(bRetVal)
			return TRUE;

		//
		//	判断出错的原因
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
//	功能：
//		用户退出
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		无
//
//  说明：
//		执行成功后，当前用户身份为公共(未登录)
//-------------------------------------------------------------------
BOOL 
CCSPReader::Logout()
{
	if(GetCardType() == CPU_PKI){
		if(m_FileSys.wDF_flag & DF_CSP_IN_MF)
		{//选进应用,再选回MF,作一个状态恢复
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
//	功能：
//		更改PIN码
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		int nUserType			用户类型
//		LPBYTE pOldPIN			旧PIN
//		DWORD dwOldPINLen		旧PIN的长度
//		LPBYTE pNewPIN			新PIN
//		DWORD dwNewPINLen		新PIN的长度
//
//  说明：
//		改变当前用户的PIN
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
	//	参数检测
	//
	if(pNewPIN == NULL || dwNewPINLen == 0)
	{
		return FALSE;
	}

	//
	//	验证PIN码
	//
	if(pOldPIN != NULL){
		DWORD dwRetryCount;
		if(!Login(nUserType, pOldPIN, dwOldPINLen, dwRetryCount))
			return FALSE;
	}

	//管理员或用户PIN的最大重试次数
	BYTE pinMaxRetry = 0x33;
	TOKENINFO Info;
	if(GetTokenInfo(&Info))
		pinMaxRetry = Info.pinMaxRetry;

	//
	//	更改PIN码
	//
	//	step1: 将PIN码作一次哈希运算(MD5)，得到外部认证密钥
	MD5 hash;
	BYTE key[16];
	hash.CalculateDigest(key, pNewPIN, dwNewPINLen);

	//将外部认证密钥写入卡中
	if(GetCardType() == CPU_PKI){
		//生成密钥信息
		BYTE cKeyData[24];
		BYTE bKeyID = (nUserType == UT_USER ? 0x02 : 0x01); 

		cKeyData[0] = bKeyID;		//标识符
		cKeyData[1] = 0x01;										//版本号
		cKeyData[2] = 0x00;										//算法标识
		cKeyData[3] = 0x08;										//密钥类型
		cKeyData[4] = 0x0f;										//使用权限
		cKeyData[5] = (nUserType == UT_USER ? 0x0a : 0x05);		//后续状态
		cKeyData[6] = (nUserType == UT_USER ? 0x4b : 0x55);		//修改权限
		if(nUserType == UT_USER){
			BYTE cErrCnt = pinMaxRetry & 0x0F;
			cKeyData[7] = ((cErrCnt << 4) & 0xF0) | (cErrCnt & 0x0F);
		}
		else{
			BYTE cErrCnt = (pinMaxRetry >> 4) & 0x0F;
			cKeyData[7] = ((cErrCnt << 4) & 0xF0) | (cErrCnt & 0x0F);
		}
		memcpy(cKeyData + 8, key, 16);							//密钥数据

		//写入密钥信息
		return cpuWriteKey(cKeyData, sizeof(cKeyData), FALSE);
	}
	return false;
}

//-------------------------------------------------------------------
//	功能：
//		PIN解锁
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		LPBYTE pUserDefaultPIN		解锁后用户的缺省PIN
//		DWORD dwUserDefaultPINLen	解锁后用户的缺省PIN的长度
//
//  说明：
//		当前用户身份必须为管理员
//-------------------------------------------------------------------
BOOL 
CCSPReader::UnlockPIN(
	LPBYTE pUserDefaultPIN,
	DWORD dwUserDefaultPINLen
	)
{
	//
	//	参数检测
	//
	if(pUserDefaultPIN == NULL || dwUserDefaultPINLen == 0)
		return FALSE;

	//管理员或用户PIN的最大重试次数
	BYTE pinMaxRetry = 0x33;
	TOKENINFO Info;
	if(GetTokenInfo(&Info))
		pinMaxRetry = Info.pinMaxRetry;

	//
	//	更改PIN码
	//

	//	step1: 将PIN码作一次哈希运算(MD5)，得到外部认证密钥
	MD5 hash;
	BYTE key[16];
	hash.CalculateDigest(key, pUserDefaultPIN, dwUserDefaultPINLen);

	//将外部认证密钥写入卡中
	if(GetCardType() == CPU_PKI){
		//生成密钥信息
		BYTE cKeyData[24];
		cKeyData[0] = 0x02;										//标识符
		cKeyData[1] = 0x01;										//版本号
		cKeyData[2] = 0x00;										//算法标识
		cKeyData[3] = 0x08;										//密钥类型
		cKeyData[4] = 0x0f;										//使用权限
		cKeyData[5] = 0x0a;										//后续状态
		cKeyData[6] = 0x4b;										//修改权限
		BYTE cErrCnt = pinMaxRetry & 0x0F;
		cKeyData[7] = ((cErrCnt << 4) & 0xF0) | (cErrCnt & 0x0F);
		memcpy(cKeyData + 8, key, 16);							//密钥数据

		//写入密钥信息
		return cpuWriteKey(cKeyData, sizeof(cKeyData), FALSE);
	}
	return false;
}

//-------------------------------------------------------------------
//	功能：
//		查询容量
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		DWORD& dwTotalSize				总空间(含系统占用)
//		DWORD& dwTotalSize2				总空间(不含系统占用)
//		DWORD& dwUnusedSize				可用空间
//
//  说明：
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
//	功能：
//		查询COS版本
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		DWORD& dwCosVersion				COS版本
//
//  说明：
//-------------------------------------------------------------------
BOOL
CCSPReader::GetCosVer(
	DWORD& dwVersion
	)
{
		return cpuGetCosVer(dwVersion);
}

//-------------------------------------------------------------------
//	功能：
//		查询有否SSF33算法
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//
//  说明：
//-------------------------------------------------------------------
BOOL
CCSPReader::IsSSF33Support()
{
		return cpuIsSSF33Support();
}

//-------------------------------------------------------------------
//	功能：
//		获取PIN的重试信息
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		int nUserType					用户类型
//		int nMaxRetry					最大重试次数
//		int nLeftRetry					剩余重试次数
//
//  说明：
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
//	功能：
//		选择DF文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		DF_ID dfId		DF文件的标识
//
//  说明：
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
		//DATA(按ID进行选择 3F 00)
		cCommand[5] = g_cPathTable.mfPath[0];
		cCommand[6] = g_cPathTable.mfPath[1];

		bRetVal = SendCommand(cCommand, cLen, NULL, NULL, &wSW);

		break;

	case TYCSP:
		cLen = 7;
		cCommand[2] = 0x00;							//P1
		cCommand[3] = 0x00;							//P2
		cCommand[4] = 0x02;							//LC
		//DATA(按ID进行选择 2f 01)
		cCommand[5] = g_cPathTable.dirPath[0];
		cCommand[6] = g_cPathTable.dirPath[1];

		//发送命令
		bRetVal = SendCommand(cCommand, cLen, NULL, NULL, &wSW);

		break;
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		选择EF文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		BYTE cPath[2]				文件标识
//		BYTE* pbRetData				响应数据
//		DWORD* pdwRetDataLen		响应数据的长度
//
//  说明：
//		按文件标识进行选择
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
//	功能：
//		创建EF文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		BYTE path[2]
//		DWORD dwSize
//		BYTE type
//		BYTE readAuth
//		BYTE writeAuth
//		BYTE* pbUseAuth
//
//  说明：
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
//	功能：
//		读取当前文件中的二进制记录
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		BYTE* pbData			读出的数据
//		DWORD dwDataLen			数据的长度
//		DWORD dwOffset			在当前文件中偏移量
//
//  说明：
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
//	功能：
//		在当前文件中写二进制记录
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		BYTE* pbData			数据
//		DWORD dwDataLen			大小
//		DWORD dwOffset			在当前文件中偏移量
//		BOOL bPlain = FALSE		//是否强制明文写
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPReader::cpuUpdateCurrentBinaryFile(
	BYTE* pbData,
	DWORD dwDataLen,
	DWORD dwOffset,
	BOOL bPlain /*= FALSE	*/
	)
{
	//如果有线路保护, 用明文加MAC写
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
//	功能：
//		向当前文件中明文加MAC写二进制
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		BYTE* pbData			数据
//		DWORD dwDataLen			大小
//		DWORD dwOffset			在当前文件中偏移量
//
//  说明：
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

	//取随机数用到的变量
	BYTE pbRandCmd[] = {0x00, 0x84, 0x00, 0x00, 0x04};
	BYTE pbRand[256] = {0};
	DWORD dwLen = 256;

	for(DWORD i = 0; i < dwDataLen; i += g_cPathTable.bufSize){
		pCommand[2] = HIBYTE(LOWORD(dwRealOffset));	//P1
		pCommand[3] = LOBYTE(LOWORD(dwRealOffset));	//P2
		if(dwDataLen - i < g_cPathTable.bufSize)	//LE
			pCommand[4] = BYTE(dwDataLen - i);	//加上MAC长度
		else
			pCommand[4] = g_cPathTable.bufSize;

		
		//取随机数
		dwLen = 256;
		bRetVal = FALSE;
		if(!SendCommand(pbRandCmd, 5, pbRand, &dwLen))
			break;
		memset(pbRand + 4, 0, 4);

		//算MAC
		memcpy(pCommand+5, pbData + i, pCommand[4]);
		pCommand[4] += 4;
		if(!CulMac(g_pbMacKey, 
			sizeof(g_pbMacKey), 
			pCommand, 
			pCommand[4] + 1, 
			pCommand + pCommand[4] + 1, 
			pbRand))
			break;

		//写数据
		bRetVal = SendCommand(pCommand, 5 + pCommand[4], NULL, NULL);
		if (bRetVal != TRUE) 
			break;

		dwRealOffset += g_cPathTable.bufSize;
	}

	delete pCommand;

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		向卡中写入密钥
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		LPBYTE pKeyData		密钥数据
//		DWORD dwKeyDataLen	密钥数据的长度
//		BOOL bInstall		安装还是修改
//
//  说明：
//-------------------------------------------------------------------
BOOL
CCSPReader::cpuWriteKey(
	LPBYTE pKeyData,
	DWORD dwKeyDataLen,
	BOOL bInstall
	)
{
	//密钥信息不能为空
	if(pKeyData == NULL)
		return FALSE;

	//创建命令报文空间
	BYTE cLen = static_cast<BYTE>(5 + dwKeyDataLen);
	LPBYTE pCommand = new BYTE[cLen];
	if(pCommand == NULL)
		return FALSE;

	//生成命令报文(无LE)
	pCommand[0] = 0x80;									//CLA
	pCommand[1] = 0xD4;									//INS
	if(bInstall)
		pCommand[2] = 0x00;								//P1
	else
		pCommand[2] = 0x01;
	pCommand[3] = 0x00;									//P2
	pCommand[4] = static_cast<BYTE>(dwKeyDataLen);		//LC
	memcpy(pCommand + 5, pKeyData, dwKeyDataLen);		//DATA

	//写密钥
	BOOL bRetVal = SendCommand(pCommand, cLen);
	//释放命令报文空间
	delete pCommand;

	return bRetVal;
}


//-------------------------------------------------------------------
//	功能：
//		查询容量
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		int nType						类型
//		DWORD& dwSize					空间大小
//		BOOL* pErrBecauseNoMF			出错是否因为没有MF
//
//  说明：
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
//	功能：
//		查询COS版本
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		DWORD& dwVersion					COS版本
//
//  说明：
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
//	功能：
//		查询是否已下载SSF33算法
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//
//  说明：
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
//	功能：
//		获取错误计数器
//
//	返回：
//		TRUE：成功		FALSE；失败
//
//  参数：
//		int nKeyId					密钥标识
//		int nKeyType				密钥类型
//		BYTE& cErrCount				错误计数器字节
//
//  说明：
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
//	功能：
//		初始化FAT文件内存映像
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPReader::cpuInitFatFile()
{
	memset(&m_fileFAT, 0, sizeof(m_fileFAT));
	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		刷新FAT表的内存映象
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		无
//
//  说明：
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
//	功能：
//		从卡中读出FAT文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
BOOL
CCSPReader::cpuReadFatFile()
{
	//已从卡中读出,不需再读
	if(m_fileFAT.dwTotalLen != 0)
		return TRUE; 

	//先清空
	memset(&m_fileFAT, 0, sizeof(m_fileFAT));

	BeginTransaction();

	//打开FAT文件
	FILEHANDLE hFile = NULL;
	DWORD dwFileSize;
	if(!OpenFile(g_cPathTable.fileTablePath, &hFile, &dwFileSize)){
		EndTransaction();
		return FALSE;
	}

	if(dwFileSize > MAX_FAT_LEN)
		dwFileSize = MAX_FAT_LEN;
	m_fileFAT.dwTotalLen = dwFileSize;

	//先读出文件中的前三个字节,版本(1) + 记录数(2)
	if(!ReadFile(hFile, g_cPathTable.fileTableHeadLen, m_fileFAT.cContent, NULL, 0)){
		CloseFile(hFile);
		EndTransaction();
		return FALSE;
	}

	//计算记录的长度
	DWORD dwRecNum = MAKEWORD(m_fileFAT.cContent[2], m_fileFAT.cContent[1]);
	DWORD dwRecLen = dwRecNum*g_cPathTable.fileTableRecLen;

	//读取FAT表项
	BOOL bRetVal = ReadFile(
		hFile, dwRecLen, m_fileFAT.cContent + g_cPathTable.fileTableHeadLen, NULL, g_cPathTable.fileTableHeadLen
		);

	CloseFile(hFile);
	EndTransaction();

	return bRetVal;
}


//-------------------------------------------------------------------
//	功能：
//		添加一个FAT表项
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		BYTE path[2]
//		WORD flag
//		DWORD dwSize
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPReader::cpuAddFatFileItem(
	BYTE path[2],
	WORD flag,
	DWORD dwSize
	)
{
	//FAT表文件的内容
	BYTE* pfiletable = m_fileFAT.cContent;

	//计算偏移量
	DWORD dwNum = (pfiletable[1]<<8) + pfiletable[2];
	DWORD dwOffset = g_cPathTable.fileTableHeadLen + dwNum*g_cPathTable.fileTableRecLen;

	FILEHANDLE hFile;
	if(!OpenFile(g_cPathTable.fileTablePath, &hFile, NULL))
		return FALSE;
	
	//加入新的表项
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

	//更改表项的数目
	buf[0] = BYTE((dwNum + 1)>>8);
	buf[1] = BYTE(dwNum + 1);
	BOOL bRetVal = WriteFile(hFile, buf, 2, 1);
	CloseFile(hFile);
	if(bRetVal == TRUE)
		memcpy(pfiletable + 1, buf, 2);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		设置FAT表项中文件的使用标置位
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		BYTE path[2]
//		BOOL bDeleted
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPReader::cpuSetFileUseableFlag(
	BYTE path[2],
	BOOL bDeleted
	)
{
	BYTE* pfiletable = m_fileFAT.cContent;

	//确定文件对应的FAT表项的位置
	DWORD dwNum = (pfiletable[1]<<8) + pfiletable[2];
	DWORD dwOffset = 0;
	for(DWORD i = 0; i < dwNum; i++){
		dwOffset = g_cPathTable.fileTableHeadLen + i*g_cPathTable.fileTableRecLen;
		if(memcmp(pfiletable + dwOffset, path, 2) == 0)
			break;
	}
	//没有找到相应的文件
	if (i == dwNum) return FALSE;

	dwOffset += 2;
	BYTE flag = pfiletable[dwOffset] & 0xfe;
	if(bDeleted)
		flag |= FILE_UNUSED;
	else
		flag |= FILE_USED;
	
	//更新标志位
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
//	功能：
//		获取CPU卡中可用的文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		WORD flag
//		DWORD dwSize
//		BYTE pPath[2]
//
//  说明：
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
	//查找dwSize小于文件表中记录的dwSize且最接近的文件，如果没有则创建
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

			//没有找到可以重用的空间，创建该文件
			//先在filetable中添加相应的条目
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
	//查找dwSize等于文件表中记录的dwSize的文件，如果没有则创建
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

			//没有找到可以重用的空间，创建该文件
			//先在filetable中添加相应的条目
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
	//对于私钥，则要查找FILETYPE_PRK、FILETYPE_PRKEX两种类型，且dwSize相等的文件，
	//如果两者没有或者其中一个没有，则创建相应的文件
	case FILETYPE_PRK:
	case FILETYPE_PRKEX:
		ulExPath = ulExPathStart -1;
		//先查找FILETYPE_PRKEX
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

			//没有找到可以重用的空间，创建该文件
			//先在filetable中添加相应的条目
			BYTE NewFilePath[2];
			NewFilePath[0] = BYTE(ulExPath>>8);
			NewFilePath[1] = BYTE(ulExPath);
			rv = cpuAddFatFileItem(NewFilePath, flag&0xff00|FILE_USED|FILETYPE_PRKEX, dwSize);
			if (rv != TRUE)
				return rv;

			//对于私钥扩展文件,将其读写权限放开
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

			//找到了可以重用的空间
			path = ulExPath - (g_cPathTable.prkexStarPath[0]<<8)
				- g_cPathTable.prkexStarPath[1]
				+ (g_cPathTable.prkStartPath[0] << 8)
				+ g_cPathTable.prkStartPath[1];
			byFlag = byFlag&0xf1|FILETYPE_PRK;

			//在文件表中查找有没有该项的记录
			for	( i=0; i<ulRecNum; i++)
			{
				ulOffset = g_cPathTable.fileTableHeadLen+i*g_cPathTable.fileTableRecLen;
				ULONG ulCurPath = (pfiletable[ulOffset]<<8) + pfiletable[ulOffset+1];
				if (ulCurPath == path)
				{
					break;
				}
			}

			//如果没有该项记录，则创建
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
		//查找dwSize等于文件表中记录的dwSize的文件，如果没有则创建
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

			//没有找到可以重用的空间，创建该文件
			//先在filetable中添加相应的条目
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
	//对于私钥，则要查找FILETYPE_PRK_ECC、FILETYPE_PRKEX_ECC两种类型，且dwSize相等的文件，
	//如果两者没有或者其中一个没有，则创建相应的文件
	case FILETYPE_PRK_ECC:
	case FILETYPE_PRKEX_ECC:
		ulExPath = ulExPathStart-1;
		//先查找FILETYPE_PRKEX
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

			//没有找到可以重用的空间，创建该文件
			//先在filetable中添加相应的条目
			BYTE NewFilePath[2];
			NewFilePath[0] = BYTE(ulExPath>>8);
			NewFilePath[1] = BYTE(ulExPath);
			rv = cpuAddFatFileItem(NewFilePath, flag&0xff00|FILE_USED|FILETYPE_PRKEX_ECC, dwSize);
			if (rv != TRUE)
				return rv;

			//对于私钥扩展文件,将其读写权限放开
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

			//找到了可以重用的空间
			path = ulExPath - (g_cPathTable.eccprkexStarPath[0]<<8)
				- g_cPathTable.eccprkexStarPath[1]
				+ (g_cPathTable.eccprkStartPath[0] << 8)
				+ g_cPathTable.eccprkStartPath[1];
			byFlag = byFlag&0xf1|FILETYPE_PRK_ECC;

			//在文件表中查找有没有该项的记录
			for	( i=0; i<ulRecNum; i++)
			{
				ulOffset = g_cPathTable.fileTableHeadLen+i*g_cPathTable.fileTableRecLen;
				ULONG ulCurPath = (pfiletable[ulOffset]<<8) + pfiletable[ulOffset+1];
				if (ulCurPath == path)
				{
					break;
				}
			}

			//如果没有该项记录，则创建
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

