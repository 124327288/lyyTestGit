//-------------------------------------------------------------------
//	本文件为 TY Cryptographic Service Provider 的组成部分
//
//
//	版权所有 天喻信息产业有限公司 (c) 1996 - 2005 保留一切权利
//-------------------------------------------------------------------
#include "stdafx.h"
#include "CSPObject.h"
#include "KeyContainer.h"
#include "CSPKey.h"
#include "DERCoding.h"
#include "DERTool.h"
#include "VerifyPin.h"
#include "OpenCardDlg.h"
#include "HelperFunc.h"
#include "atlbase.h"
#include "Modifier.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define PP_RESET_SEC_STAUS    1000

//所支持卡片的名字
#define PBOC_CARD_NAME					_T("Tianyu Smart Card (PBOC)")
#define PKI_CARD_NAME					_T("Tianyu Smart Card (PKI)")
#define PKI_SSF33_CARD_NAME				_T("Tianyu Smart Card (PKI-SSF33)")
#define PKI_UNIQUE_CARD_NAME			_T("Tianyu Smart Card (PKI-UNIQUE)")
	
TCHAR* g_szSupportCardName[] = {
	PBOC_CARD_NAME, PKI_CARD_NAME, PKI_SSF33_CARD_NAME, PKI_UNIQUE_CARD_NAME
};
DWORD g_dwSSF33Algid=0,g_dwSCB2Algid =0,g_dwEccSignAlgid =0,g_dwEccKeyxAlgid=0;
 
//typedef struct _PROV_ENUMALGS_EX 
//{
//    ALG_ID    aiAlgid;
//    DWORD     dwDefaultLen;
//    DWORD     dwMinLen;
//    DWORD     dwMaxLen;
//    DWORD     dwProtocols;
//    DWORD     dwNameLen;
//    CHAR      szName[20];
//    DWORD     dwLongNameLen;
//    CHAR      szLongName[40];
//} PROV_ENUMALGS_EX;
//
static PROV_ENUMALGS_EX g_cSupportAlgInfo[] = {
	{CALG_RC2, RC2_DEFAULT_LEN, RC2_MIN_LEN, RC2_MAX_LEN, RC2_PROTOCOLS, _tcslen(RC2_NAME), RC2_NAME, _tcslen(RC2_LONG_NAME), RC2_LONG_NAME},
	{CALG_RC4, RC4_DEFAULT_LEN, RC4_MIN_LEN, RC4_MAX_LEN, RC4_PROTOCOLS, _tcslen(RC4_NAME), RC4_NAME, _tcslen(RC4_LONG_NAME), RC4_LONG_NAME},
	{CALG_DES, DES_DEFAULT_LEN, DES_MIN_LEN, DES_MAX_LEN, DES_PROTOCOLS, _tcslen(DES_NAME), DES_NAME, _tcslen(DES_LONG_NAME), DES_LONG_NAME},
	{CALG_3DES_112,DES2_DEFAULT_LEN, DES2_MIN_LEN, DES2_MAX_LEN, DES2_PROTOCOLS, _tcslen(DES2_NAME), DES2_NAME, _tcslen(DES2_LONG_NAME), DES2_LONG_NAME},
	{CALG_3DES, DES3_DEFAULT_LEN, DES3_MIN_LEN, DES3_MAX_LEN, DES3_PROTOCOLS, _tcslen(DES3_NAME), DES3_NAME, _tcslen(DES3_LONG_NAME), DES3_LONG_NAME},
	{CALG_SSF33,SSF33_DEFAULT_LEN, SSF33_MIN_LEN, SSF33_MAX_LEN, SSF33_PROTOCOLS, _tcslen(SSF33_NAME), SSF33_NAME, _tcslen(SSF33_LONG_NAME), SSF33_LONG_NAME},
	{CALG_MD5, MD5_DEFAULT_LEN, MD5_MIN_LEN, MD5_MAX_LEN, MD5_PROTOCOLS, _tcslen(MD5_NAME), MD5_NAME, _tcslen(MD5_LONG_NAME), MD5_LONG_NAME},
	{CALG_SHA, SHA_DEFAULT_LEN, SHA_MIN_LEN, SHA_MAX_LEN, SHA_PROTOCOLS, _tcslen(SHA_NAME), SHA_NAME, _tcslen(SHA_LONG_NAME), SHA_LONG_NAME},
	{CALG_SSL3_SHAMD5, SSL3SHAMD5_DEFAULT_LEN, SSL3SHAMD5_MIN_LEN, SSL3SHAMD5_MAX_LEN, SSL3SHAMD5_PROTOCOLS, _tcslen(SSL3SHAMD5_NAME), SSL3SHAMD5_NAME, _tcslen(SSL3SHAMD5_LONG_NAME), SSL3SHAMD5_LONG_NAME},
	{CALG_RSA_SIGN, RSA_SIGN_DEFAULT_LEN, RSA_SIGN_MIN_LEN, RSA_SIGN_MAX_LEN, RSA_SIGN_PROTOCOLS, _tcslen(RSA_SIGN_NAME), RSA_SIGN_NAME, _tcslen(RSA_SIGN_LONG_NAME), RSA_SIGN_LONG_NAME},
	{CALG_RSA_KEYX, RSA_KEYX_DEFAULT_LEN, RSA_KEYX_MIN_LEN, RSA_KEYX_MAX_LEN, RSA_KEYX_PROTOCOLS, _tcslen(RSA_KEYX_NAME), RSA_KEYX_NAME, _tcslen(RSA_KEYX_LONG_NAME), RSA_KEYX_LONG_NAME},
	{CALG_ECC_SIGN, ECC_SIGN_DEFAULT_LEN, ECC_SIGN_MIN_LEN, ECC_SIGN_MAX_LEN, ECC_SIGN_PROTOCOLS, _tcslen(ECC_SIGN_NAME), ECC_SIGN_NAME, _tcslen(ECC_SIGN_LONG_NAME), ECC_SIGN_LONG_NAME},
	{CALG_ECC_KEYX, ECC_KEYX_DEFAULT_LEN, ECC_KEYX_MIN_LEN, ECC_KEYX_MAX_LEN, ECC_KEYX_PROTOCOLS, _tcslen(ECC_KEYX_NAME), ECC_KEYX_NAME, _tcslen(ECC_KEYX_LONG_NAME), ECC_KEYX_LONG_NAME},
	{CALG_SCB2,SCB2_DEFAULT_LEN, SCB2_MIN_LEN, SCB2_MAX_LEN, SCB2_PROTOCOLS, _tcslen(SCB2_NAME), SCB2_NAME, _tcslen(SCB2_LONG_NAME), SCB2_LONG_NAME},
};

CModifyManager g_ModifyManager;
//-------------------------------------------------------------------
//	功能：
//		获取指定算法的信息
//
//	返回：
//		TRUE:成功		FALSE:不支持该算法
//
//  参数：
//		PROV_ENUMALGS_EX& info	算法信息
//
//  说明：
//-------------------------------------------------------------------
BOOL GetAlgInfo(PROV_ENUMALGS_EX& info)
{

	CRegKey reg;
	LONG lResult = reg.Open(HKEY_LOCAL_MACHINE, 
		"SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Tianyu Cryptographic Service Provider"
		);
	if(lResult == ERROR_SUCCESS){
		DWORD dwValue;

		//sf33算法ID
		lResult = reg.QueryValue(dwValue, "SSF33_ALG");
		if(lResult == ERROR_SUCCESS)
		{
				g_dwSSF33Algid = dwValue;
//#ifdef CALG_SSF33
//#undef CALG_SSF33
//#define CALG_SSF33 g_dwSSF33Algid
//#endif		
		}

		//scb2算法ID
		lResult = reg.QueryValue(dwValue, "SCB2_ALG");
		if(lResult == ERROR_SUCCESS)
		{
				g_dwSCB2Algid = dwValue;
//#ifdef CALG_SCB2
//#undef CALG_SCB2
//#define CALG_SCB2 g_dwSCB2Algid
//#endif
		}

		//ECC Key Exchange算法ID
		lResult = reg.QueryValue(dwValue, "ECC_KEYX_ALG");
		if(lResult == ERROR_SUCCESS)
		{
				g_dwEccKeyxAlgid = dwValue;
//#ifdef CALG_ECC_KEYX
//#undef CALG_ECC_KEYX
//#define CALG_ECC_KEYX g_dwEccKeyxAlgid
//#endif
		}

		//ECC Sign算法ID
		lResult = reg.QueryValue(dwValue, "ECC_SIGN_ALG");
		if(lResult == ERROR_SUCCESS)
		{
				g_dwEccSignAlgid = dwValue;
//#ifdef CALG_ECC_SIGN
//#undef CALG_ECC_SIGN
//#define CALG_ECC_SIGN g_dwEccSignAlgid
//#endif
		}

		reg.Close();
	}
	
	int nSize = sizeof(g_cSupportAlgInfo)/sizeof(PROV_ENUMALGS_EX);
	for(int i = 0; i < nSize; i++){
		
		if(g_cSupportAlgInfo[i].aiAlgid == info.aiAlgid){
			info = g_cSupportAlgInfo[i];
			return TRUE;
		}
		else if (g_dwSCB2Algid == info.aiAlgid)
		{
			g_cSupportAlgInfo[13].aiAlgid = info.aiAlgid;
			info = g_cSupportAlgInfo[13];
			return TRUE;
		}
		else if (g_dwSSF33Algid == info.aiAlgid)
		{
			g_cSupportAlgInfo[5].aiAlgid = info.aiAlgid;
			info = g_cSupportAlgInfo[5];
			return TRUE;
		}
		else if (g_dwEccSignAlgid == info.aiAlgid)
		{
			g_cSupportAlgInfo[11].aiAlgid = info.aiAlgid;
			info = g_cSupportAlgInfo[11];
			return TRUE;
		}
		else if (g_dwEccKeyxAlgid == info.aiAlgid)
		{
			g_cSupportAlgInfo[12].aiAlgid = info.aiAlgid;
			info = g_cSupportAlgInfo[12];
			return TRUE;
		}		
	}

	return FALSE;
}

//-------------------------------------------------------------------
//	功能：
//		判断是否为支持的HASH的算法标识
//
//	返回：
//		TRUE:是		FALSE:不是
//
//  参数：
//		ALG_ID algId	算法标识
//
//  说明：
//-------------------------------------------------------------------
BOOL IsSupportHashAlgId(ALG_ID algId)
{
	return (algId == CALG_MD5 || algId == CALG_SHA || algId == CALG_SSL3_SHAMD5);
}

//-------------------------------------------------------------------
//	功能：
//		判断是否为支持的密钥对的算法标识
//
//	返回：
//		TRUE:是		FALSE:不是
//
//  参数：
//		ALG_ID algId	算法标识
//
//  说明：
//-------------------------------------------------------------------
BOOL IsSupportKeyPairAlgId(ALG_ID algId)
{
	return (algId == CALG_RSA_SIGN || algId == CALG_RSA_KEYX || algId == g_dwEccSignAlgid || algId == g_dwEccKeyxAlgid);
	//return (algId == CALG_RSA_SIGN || algId == CALG_RSA_KEYX || algId == CALG_ECC_SIGN || algId ==CALG_ECC_KEYX);
}

//-------------------------------------------------------------------
//	功能：
//		判断是否为支持的对称密钥算的法标识
//
//	返回：
//		TRUE:是		FALSE:不是
//
//  参数：
//		ALG_ID algId	算法标识
//
//  说明：
//-------------------------------------------------------------------
BOOL IsSupportSymmetricKeyAlgId(ALG_ID algId)
{
	//return (algId == CALG_RC2 || algId == CALG_RC4 || algId == CALG_DES || algId == CALG_3DES || algId == CALG_3DES_112 || algId == CALG_SSF33 || algId == CALG_SCB2);
	return (algId == CALG_RC2 || algId == CALG_RC4 || algId == CALG_DES || algId == CALG_3DES || algId == CALG_3DES_112 ||
		algId == g_dwSSF33Algid  || algId == g_dwSCB2Algid);
}

/////////////////////////////////////////////////////////////////////
//	class CTYCSP
//

#define	ENUM_INIT_INDEX		-1

//用一个GUID作为验证Key Container的名字
#define VERIFY_KEY_CONTAINER_NAME _T("4BACC318-2FA9-46C9-B355-22765E7B1AD5")
//用一个GUID作为一个在没有用户账号机器上的缺省Key Container的名字
#define DEFAULT_KEY_CONTAINER_NAME _T("02169438-4CB4-4C90-B74F-943FF7CF716B")

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
CTYCSP::CTYCSP(LPCTSTR lpszName /*=TYCSP_NAME*/)
{
	//CSP所属性
	ASSERT(lpszName != NULL);
	m_szName = lpszName;
	m_dwType = PROV_RSA_FULL;
	m_dwVersion = 0x00000108;
	m_dwImpType = CRYPT_IMPL_MIXED | CRYPT_IMPL_REMOVABLE;
	
	m_hHandle = -1;
	m_hNextKCHandle = 0;

	TCHAR szSysDir[MAX_PATH];
	GetSystemDirectory(szSysDir, sizeof(szSysDir));
	m_strLogFileName.Format(_T("%s\\tyCSPSSO.log"), szSysDir);

	//初始化数据
	DestroyResourceAndInitData();
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
CTYCSP::~CTYCSP()
{
	DestroyResourceAndInitData();
}

//-------------------------------------------------------------------
//	功能：
//		销毁资源并初始化数据
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
void
CTYCSP::DestroyResourceAndInitData()
{
	//释放KeyContainer列表
	int nCount = GetKeyContainerCount();
	for(int i = 0; i < nCount; i++){
		CCSPKeyContainer* pKeyContainer = m_arKeyContainers.GetAt(i);
		ASSERT(pKeyContainer != NULL);
		delete pKeyContainer;
	}
	m_arKeyContainers.RemoveAll();

	//数据初始化
	m_bReadedKeyContainer = FALSE;
	m_nEnumAlgIdIndex = ENUM_INIT_INDEX;
	m_nEnumKeyContainerIndex = ENUM_INIT_INDEX;
	memset(&m_xdfPrk, 0, sizeof(m_xdfPrk));
	
	m_bLogin = g_theTYCSPManager.IsSSO();

	m_bCalledLogin = FALSE;
	m_bSilent = FALSE;

	m_cryptMode = HARDWARE;
}

void
CTYCSP::RefreshCard()
{
	DestroyResourceAndInitData();
	m_reader.cpuRefreshFatFile();
}
//-------------------------------------------------------------------
//	功能：
//		CSP初始化
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
CTYCSP::Initialize()
{
	TRACE_FUNCTION("CTYCSP::Initialize");
	TRACE_LINE("\n\nCSP句柄 = %d\n", GetHandle());
	TRACE_LINE("读写器的名字 = %s\n\n", GetReaderName());

	//构造所支持的算法标识列表
	int nSize = sizeof(g_cSupportAlgInfo)/sizeof(PROV_ENUMALGS_EX);
	for(int i = 0; i < nSize; i++)
		m_arAlgIds.Add(g_cSupportAlgInfo[i].aiAlgid);

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		释放CSP的资源
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		BOOL bWriteCard		是否整理卡中的碎片
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::Finalize(BOOL bWriteCard)
{
	TRACE_FUNCTION("CTYCSP::Finalize");
	TRACE_LINE("\n\nCSP句柄 = %d\n\n", GetHandle());
	
	if(bWriteCard){
		//整理卡中的碎片
		if(m_xdfPrk.bHasFragment){
			//消除XDF文件中的碎片
			RemoveXdfFragment(&m_xdfPrk);

			//写入卡中
			FILEHANDLE hFile;
			if(OpenFile(g_cPathTable.prkdfPath, &hFile, NULL)){
				WriteFile(hFile, m_xdfPrk.cContent, m_xdfPrk.ulDataLen + 2, 0);
				CloseFile(hFile);
			}
		}
	}

	//销毁资源并初始化数据
	DestroyResourceAndInitData();

	//断开与智能卡的连接
	m_reader.DisconnectCard();

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		从卡中读出Key Container
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
CTYCSP::ReadKeyContainer()
{
	//判断是否已读
	if(m_bReadedKeyContainer)
		return TRUE;

	//读出卡中Key Container的DER编码
	CDERTool tool;
	if(!ReadObjectDERs(g_cPathTable.prkdfPath, &m_xdfPrk, tool))
		return FALSE;
	
	if(m_xdfPrk.bHasFragment){
		//清除碎片
		RemoveXdfFragment(&m_xdfPrk);
		FILEHANDLE hFile;
		if( OpenFile(g_cPathTable.prkdfPath, &hFile)){
			WriteFile(hFile, m_xdfPrk.cContent, m_xdfPrk.ulDataLen + 2, 0);
			CloseFile(hFile);
		}
	}
	
	//创建Key Container对象
	BYTE* pDERStr = NULL;
	ULONG ulLength = 0;
	for(int i = 0; i < tool.GetCount(); i++){
		if(tool.GetAt(i, pDERStr, ulLength) && pDERStr != NULL){
			//解码获取KeyContainer的名字
			ULONG ulTag = ::GetDERTag(pDERStr, ulLength);
			if(ulTag != 0x30) continue;

			ULONG ulTagLen, ulLenLen;
			::GetDERLen(pDERStr, ulLength, ulTagLen, ulLenLen);
			pDERStr += (ulTagLen + ulLenLen);
			ulLength -= (ulTagLen + ulLenLen);
			
			ulTag = ::GetDERTag(pDERStr, ulLength);
			ULONG ulValueLen = ::GetDERLen(pDERStr, ulLength, ulTagLen, ulLenLen);
			CHAR* pszName = (CHAR* )(pDERStr + ulTagLen + ulLenLen);

			//创建Key Container的对象
			CCSPKeyContainer* pKeyContainer = NULL;
			CreateKeyContainer(pszName, TRUE, pKeyContainer, FALSE);

			//载入Key Container中的密钥对
			if(pKeyContainer != NULL){
				pKeyContainer->SetTokenIndex(i);
				pDERStr += (ulTagLen + ulLenLen + ulValueLen);
				ulLength -= (ulTagLen + ulLenLen + ulValueLen);
				pKeyContainer->LoadKeyPairs(pDERStr, ulLength);
			}
		}
	}

	//
	CCSPKeyContainer* pVerifyKeyContainer = NULL;
	CreateKeyContainer(VERIFY_KEY_CONTAINER_NAME, FALSE, pVerifyKeyContainer, FALSE);

	//设置读取标记为TRUE
	m_bReadedKeyContainer = TRUE;

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		创建一个Key Container对象，并将其加入链表中
//
//	返回：
//		无
//
//  参数：
//		LPCTSTR lpszName						名字
//		BOOL bInitOpen							创建后是否打开
//		CCSPKeyContainer*& pCreatedKeyContainer	创建的Key Container对象
//		BOOL bCreateOnToken						是否在卡中创建
//
//  说明：
//-------------------------------------------------------------------
void
CTYCSP::CreateKeyContainer(
	LPCTSTR lpszName,
	BOOL bInitOpen,
	CCSPKeyContainer*& pCreatedKeyContainer,
	BOOL bCreateOnToken
	)
{
	//创建
	pCreatedKeyContainer = new CCSPKeyContainer(this, lpszName, bInitOpen);
	if(pCreatedKeyContainer == NULL)
		return;

	//在卡中创建
	if(bCreateOnToken){
		if(!pCreatedKeyContainer->CreateOnToken(GetKeyContainerCreateIndex()))
		{
			delete pCreatedKeyContainer;
			pCreatedKeyContainer = NULL;
			
			return;
		}
		AddModify();
	}

	//加入到链表中
	m_arKeyContainers.Add(pCreatedKeyContainer);
}

//-------------------------------------------------------------------
//	功能：
//		获取KeyContainer的创建索引
//
//	返回：
//		创建索引
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
int
CTYCSP::GetKeyContainerCreateIndex()
{
	int nCount = 0;
	CCSPKeyContainer* pKeyContainer = NULL;
	for(int i = 0; i < m_arKeyContainers.GetSize(); i++){
		pKeyContainer = m_arKeyContainers.GetAt(i);
		if(pKeyContainer->GetName().Compare(VERIFY_KEY_CONTAINER_NAME) != 0)
			nCount++;
	}

	return nCount;
}

//-------------------------------------------------------------------
//	功能：
//		销毁指定的Key Container对象，并将其从链表中去除
//
//	返回：
//		无
//
//  参数：
//		CCSPKeyContainer* pDestroyKeyContainer	待销毁的Key Container对象
//		BOOL bDestroyOnToken					是否从卡中销毁
//
//  说明：
//-------------------------------------------------------------------
void
CTYCSP::DestroyKeyContainer(
	CCSPKeyContainer* pDestroyKeyContainer,
	BOOL bDestroyOnToken /*=FALSE*/
	)
{
	if(pDestroyKeyContainer == NULL)
		return;

	//总数
	int nCount = GetKeyContainerCount();

	//先查找其在链表中的索引
	int nIdx = -1;
	for(int i = 0; i < nCount; i++){
		CCSPKeyContainer* pKeyContainer = m_arKeyContainers.GetAt(i);
		ASSERT(pKeyContainer != NULL);
		if(pDestroyKeyContainer == pKeyContainer){
			nIdx = i;
			break;
		}
	}

	//没有找到
	if(nIdx == -1)
		return;

	if(pDestroyKeyContainer->IsToken()){
		if(bDestroyOnToken){
			pDestroyKeyContainer->DestroyOnToken();
			//后面的索引减1
			for(i = nIdx + 1; i < nCount; i++){
				CCSPKeyContainer* pKeyContainer = m_arKeyContainers.GetAt(i);
				pKeyContainer->SetTokenIndex(pKeyContainer->GetTokenIndex() - 1);
			}
		}
		AddModify();
	}


	delete pDestroyKeyContainer;
	//从链表中删除
	m_arKeyContainers.RemoveAt(nIdx);
}

//-------------------------------------------------------------------
//	功能：
//		通过句柄获取一个Key Container对象
//
//	返回：
//		Key Container对象指针
//
//  参数：
//		HCRYPTPROV hKeyContainer	句柄	
//
//  说明：
//-------------------------------------------------------------------
CCSPKeyContainer* 
CTYCSP::GetKeyContainerByHandle(
	HCRYPTPROV hKeyContainer
	)
{
	int nCount = GetKeyContainerCount();
	for(int i = 0; i < nCount; i++){
		CCSPKeyContainer* pKeyContainer = m_arKeyContainers.GetAt(i);
		ASSERT(pKeyContainer != NULL);
		//判断是否是已被释放的Key Container
		if(pKeyContainer->IsReleased())
			continue;
		if(pKeyContainer->GetHandle() == hKeyContainer)
			return pKeyContainer;
	}

	return NULL;
}

//-------------------------------------------------------------------
//	功能：
//		通过名字获取一个Key Container对象
//
//	返回：
//		Key Container对象指针
//
//  参数：
//		LPCTSTR lpszName	名字	
//
//  说明：
//-------------------------------------------------------------------
CCSPKeyContainer* 
CTYCSP::GetKeyContainerByName(
	LPCTSTR lpszName
	)
{
	//先从卡中读取Key Container，如果已读将不会再读
	if(!ReadKeyContainer())
		return NULL;

	int nCount = GetKeyContainerCount();
	for(int i = 0; i < nCount; i++){
		CCSPKeyContainer* pKeyContainer = m_arKeyContainers.GetAt(i);
		ASSERT(pKeyContainer != NULL);
		if(pKeyContainer->GetName().Compare(lpszName) == 0)
			return pKeyContainer;
	}

	return NULL;
}

//-------------------------------------------------------------------
//	功能：
//		获取缺省的Key Container名字
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		CString& szDefaultName	名字	
//
//  说明：
//		用当前登录的用户名作为所要获取的Key Container对象的名字
//-------------------------------------------------------------------
BOOL 
CTYCSP::GetDefaultKeyContainerName(
	CString& szDefaultName
	)
{
	TCHAR szUserName[UNLEN + 1];
	DWORD dwSize = UNLEN + 1;
	BOOL bRetVal = ::GetUserName(szUserName, &dwSize);
	if(bRetVal == TRUE){ 
		szDefaultName = szUserName;
		TRACE_LINE("以用户登录名作为缺省密钥容器名\n");
	}
	else{
		szDefaultName = DEFAULT_KEY_CONTAINER_NAME;
		TRACE_LINE("以预设的GUID作为缺省密钥容器名\n");
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		获取XDF
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		XDF_TYPE dfType				XDF的类型(不用)
//		SHARE_XDF* pXdfRec			指向ODF记录的指针
//
//  说明：
//		XDF为卡中Key Container 对象ODF文件的映像
//-------------------------------------------------------------------
BOOL
CTYCSP::GetXdf(
	XDF_TYPE dfType, 
	SHARE_XDF* pXdfRec
	)
{
	if(pXdfRec == NULL)
		return FALSE;

	memcpy(pXdfRec, &m_xdfPrk, sizeof(SHARE_XDF));

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		设置XDF
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		XDF_TYPE dfType				XDF的类型(不用)
//		SHARE_XDF* pXdfRec			指向ODF记录的指针
//
//  说明：
//-------------------------------------------------------------------
BOOL
CTYCSP::SetXdf(
	XDF_TYPE dfType, 
	SHARE_XDF* pXdfRec
	)
{
	if(pXdfRec == NULL)
		return TRUE;

	memcpy(&m_xdfPrk, pXdfRec, sizeof(SHARE_XDF));

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		删除XDF中的碎片
//
//	返回：
//		无
//
//  参数：
//		SHARE_XDF* pXdfRec	指向ODF记录的指针
//
//  说明：
//-------------------------------------------------------------------
void 
CTYCSP::RemoveXdfFragment(
	SHARE_XDF* pXdfRec
	)
{
	if(pXdfRec == NULL)
		return;

	if(pXdfRec->bHasFragment == FALSE)
		return;

	//先开辟一临时缓存,存储有效数据
	BYTE* pTempMem = new BYTE[pXdfRec->ulTotalLen];
	if(pTempMem == NULL)
		return;

	//数据长度先置为0
	pXdfRec->ulDataLen = 0;

	//将XDF中的有效数据连续存储于临时缓存中
	LPBYTE pDERStr = NULL;
	ULONG ulDERLen = 0;
	ULONG ulOffset = 0;
	ULONG ulTag;
	while(ulOffset < pXdfRec->ulTotalLen){
		pDERStr = pXdfRec->cContent + ulOffset;
		ulDERLen = ::GetDERTotalStrLen(
			pDERStr, pXdfRec->ulTotalLen - ulOffset
			);
		ulTag = ::GetDERTag(pDERStr, ulDERLen);
		if(ulTag == 0) break;
		if(ulTag != DESTROIED_TAG){
			memcpy(pTempMem + pXdfRec->ulDataLen, pDERStr, ulDERLen);
			pXdfRec->ulDataLen += ulDERLen;
		}
		ulOffset += ulDERLen;
	}

	//清空XDF记录
	memset(pXdfRec->cContent, 0, pXdfRec->ulTotalLen);
	//将临时缓存中存放的连续数据拷回XDF中
	memcpy(pXdfRec->cContent, pTempMem, pXdfRec->ulDataLen);

	pXdfRec->bHasFragment = FALSE;

	//释放临时缓存空间
	delete pTempMem;
}

/////////////////////////////////////////////////////////////////////////
/*
功能：	从输入的文件内容中找出对于与本对象的偏移地址
输入：	pFileData——输入的文件内容
		ulFileDataLen——输入的文件内容的长度
		ulOffset----对象相对于起始位置的偏移
		ulLen----对象记录的长度

输出：	
说明：
*/
///////////////////////////////////////////////////////////////////////////
BOOL 
CTYCSP::GetOffsetFormIndex(
		SHARE_XDF *pXdfRec,
		/*BYTE* pFileData,
		ULONG ulFileDataLen,*/
		ULONG ulIndex,
		ULONG& ulOffset,
		ULONG& ulLen
		)
{
	BYTE* pFileData = pXdfRec->cContent;
	ULONG ulFileDataLen = pXdfRec->ulDataLen;
	ULONG  i = 0;
	ULONG ulDERTotalStrLen = 0;
	ulOffset = 0;
	ulLen = 0;

	for (;i<ulIndex;)
	{
		ulDERTotalStrLen = GetDERTotalStrLen(pFileData + ulOffset,
											ulFileDataLen - ulOffset);

		//如果发现tag是标识为被删除了的对象，不作计数
		if (GetDERTag(pFileData + ulOffset,ulDERTotalStrLen) != DESTROIED_TAG)
			i++;

		ulOffset += ulDERTotalStrLen;
		if (ulOffset >= pXdfRec->ulTotalLen)
		{
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
	}

	//继续向后搜索，直到没有连续的删除标记
	while (GetDERTag(pFileData + ulOffset,ulFileDataLen - ulOffset) == DESTROIED_TAG)
	{
		ulDERTotalStrLen = GetDERTotalStrLen(pFileData + ulOffset,
											ulFileDataLen - ulOffset);
		ulOffset += ulDERTotalStrLen;
		if (ulOffset >= pXdfRec->ulTotalLen)
		{
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
	}

	ulLen = GetDERTotalStrLen(pFileData + ulOffset,
							ulFileDataLen - ulOffset);
	return TRUE;
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
CTYCSP::BeginTransaction()
{
	return m_reader.BeginTransaction();
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
CTYCSP::EndTransaction(
	DWORD dwDisposition /*=SCARD_LEAVE_CARD*/
	)
{
	return m_reader.EndTransaction(dwDisposition);
}

//-------------------------------------------------------------------
//	功能：
//		向卡发送命令
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
CTYCSP::SendCommand(
	BYTE* pbCommand,
	DWORD dwCommandLen,
	BYTE* pbRespond, /*= NULL*/
	DWORD* pdwRespondLen, /*= NULL*/
	WORD* pwStatus /*= NULL*/
	)
{
	if(g_theTYCSPManager.IsSSO()){
		WORD wStatus;
		BOOL bRetVal = m_reader.SendCommand(pbCommand, dwCommandLen, pbRespond, pdwRespondLen, &wStatus);
		if(wStatus == 0x6982){
			m_bLogin = FALSE;
			if(Login())
				bRetVal = m_reader.SendCommand(pbCommand, dwCommandLen, pbRespond, pdwRespondLen, &wStatus);
		}
		if(pwStatus != NULL) 
			*pwStatus = wStatus;

		return bRetVal;
	}
	else
		return m_reader.SendCommand(pbCommand, dwCommandLen, pbRespond, pdwRespondLen, pwStatus);
}

//-------------------------------------------------------------------
//	功能：
//		与卡连接
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
CTYCSP::Connect()
{
	//
	//检测卡的连接状态
	//
	if(m_reader.CheckCardConnect())
		return TRUE;

	//
	//卡片未连接(首次连接或卡被抽出)，在新的连接之前释放旧的连接所建立
	//的资源及初始化
	//
	DestroyResourceAndInitData();

	//
	//建立与卡片的连接
	//
	BOOL bRetVal = m_reader.ConnectCard();
	if(bRetVal){
		CardType type = m_reader.GetCardType();
		m_cryptMode = HARDWARE;
	}

	return bRetVal;
}


//-------------------------------------------------------------------
//	功能：
//		断开到卡的连接
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
CTYCSP::DisConnect()
{
	return m_reader.DisconnectCard();
}

//-------------------------------------------------------------------
//	功能：
//		用户登录
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		BOOL bForce	是否强制执行
//
//  说明：
//-------------------------------------------------------------------
BOOL
CTYCSP::Login(BOOL bForce)
{
	//判断是否为SSO登录
	if(g_theTYCSPManager.IsSSO()){
		//获取最近一次校验PIN的时间
		CString strReaderName = GetReaderName();
		int nLoginTime = GetPrivateProfileInt(
			_T("TYCSP Login Time"), strReaderName, -1, m_strLogFileName
			);
		
		//如果为不大于0则需要重新校验PIN
		if(nLoginTime <= 0)
			m_bLogin = FALSE;
		
		//如果已处于登录状态且非强迫
		if(!bForce){
			if(m_bLogin)
				return TRUE;
		}
	}
	else{
		if(m_bLogin)
			return TRUE;
	}

	if(m_bSilent){
		SETLASTERROR(NTE_SILENT_CONTEXT);
		return FALSE;
	}
	
	m_bLogin = VerifyPassword(this);

	if(g_theTYCSPManager.IsSSO()){
		//对于SSO,记录本次登录时间
		if(m_bLogin){
			CTime t = CTime::GetCurrentTime();
			CString strTime;
			strTime.Format(_T("%ld"), t.GetTime());
			WritePrivateProfileString(_T("TYCSP Login Time"), GetReaderName(), strTime, m_strLogFileName);
		}
	}

	return m_bLogin;
}
//-------------------------------------------------------------------
//	功能：
//		校验用户PIN码
//
//	返回：
//		TRUE:成功		FALSE：失败
//
//  参数：
//		BYTE* pPassword		PIN码
//		DWORD dwLen			PIN码的长度
//		int& nRetryCount	重试次数
//
//  说明：
//-------------------------------------------------------------------
BOOL
CTYCSP::VerifyPin(BYTE* pPassword, DWORD dwLen, int& nRetryCount)
{
	BOOL bRetVal = m_reader.Login(pPassword, dwLen, (DWORD&)nRetryCount);
	if(!m_bCalledLogin) m_bCalledLogin = bRetVal;
	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		打开文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		BYTE path[2]			
//		FILEHANDLE* phFile
//		LPDWORD pdwFileSize
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::OpenFile(
	BYTE path[2],
	FILEHANDLE* phFile,
	LPDWORD pdwFileSize
	)
{
	return m_reader.OpenFile(path, phFile, pdwFileSize);
}

//-------------------------------------------------------------------
//	功能：
//		读取文件内容
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		FILEHANDLE hFile
//		DWORD dwReadLen
//		LPBYTE pReadBuffer
//		LPDWORD pdwRealReadLen
//		DWORD dwOffset
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::ReadFile(
	FILEHANDLE hFile,
	DWORD dwReadLen,
	LPBYTE pReadBuffer,
	LPDWORD pdwRealReadLen,
	DWORD dwOffset
	)
{
	return m_reader.ReadFile(hFile, dwReadLen, pReadBuffer, pdwRealReadLen, dwOffset);
}

//-------------------------------------------------------------------
//	功能：
//		写数据到文件中
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		FILEHANDLE hFile
//		LPBYTE pWriteBuffer
//		DWORD dwWriteBufferLen
//		DWORD dwOffset
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::WriteFile(
	FILEHANDLE hFile,
	LPBYTE pWriteBuffer,
	DWORD dwWriteBufferLen,
	DWORD dwOffset
	)
{
	return m_reader.WriteFile(hFile, pWriteBuffer, dwWriteBufferLen, dwOffset);
}

//-------------------------------------------------------------------
//	功能：
//		关闭文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		FILEHANDLE hFile
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::CloseFile(
	FILEHANDLE hFile
	)
{
	return m_reader.CloseFile(hFile);
}

//-------------------------------------------------------------------
//	功能：
//		删除文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		BYTE path[2]
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::DeleteFile(
	BYTE path[2]
	)
{
	return m_reader.DeleteFile(path);
}

//-------------------------------------------------------------------
//	功能：
//		获取可用的文件标识
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		WORD flag
//		DWORD dwSize
//		BYTE path[2]
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::GetWorkableFile(
	WORD flag,
	DWORD dwSize,
	BYTE path[2]
	)
{
	return m_reader.GetWorkableFile(flag, dwSize, path);
}

//-------------------------------------------------------------------
//	功能：
//		创建文件
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		BYTE path[2]
//		DWORD dwSize
//		FILEHANDLE* phFile
//		BYTE type
//		BYTE readAuth
//		BYTE writeAuth
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::CreateFile(
	BYTE path[2],
	DWORD dwSize,
	FILEHANDLE* phFile,
	BYTE type,
	BYTE readAuth,
	BYTE writeAuth
	)
{
	return m_reader.CreateFile(path, dwSize, phFile, type, readAuth, writeAuth);
}

//-------------------------------------------------------------------
//	功能：
//		读取指定文件中的DER编码
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		BYTE cPath[2],
//		SHARE_XDF* pXdfRec,
//		CDERTool& tool
//
//  说明：
//-------------------------------------------------------------------
BOOL
CTYCSP::ReadObjectDERs(
	BYTE cPath[2],
	SHARE_XDF* pXdfRec,
	CDERTool& tool
	)
{
	ASSERT(pXdfRec != NULL);
	
	tool.Clear();

	pXdfRec->ulDataLen = 0;
	if(pXdfRec->ulTotalLen == 0){
		BeginTransaction();

		DWORD dwFileSize;
		FILEHANDLE hFile = NULL;
		if(!OpenFile(cPath, &hFile, &dwFileSize)){
			EndTransaction();
			return FALSE;
		}

		if(dwFileSize > MAX_XDF_LEN)
			dwFileSize = MAX_XDF_LEN;
		pXdfRec->ulTotalLen = dwFileSize;

		//先置空
		memset(pXdfRec->cContent, 0, dwFileSize);

		//读出ODF中的内容
		BOOL bRetVal = ReadODF(hFile, pXdfRec->cContent, dwFileSize);

		//关闭文件
		CloseFile(hFile);

		EndTransaction();

		if(bRetVal != TRUE)
			return FALSE;
	}

	//读出各个对象的DER
	DWORD dwOffset = 0;
	BYTE* pDERStr = NULL;
	DWORD dwDERLen = 0;
	DWORD dwTag;
	while(dwOffset < pXdfRec->ulTotalLen){
		pDERStr = pXdfRec->cContent + dwOffset;
		dwDERLen = ::GetDERTotalStrLen(
			pDERStr, pXdfRec->ulTotalLen - dwOffset
			);
		dwTag = ::GetDERTag(pDERStr, dwDERLen);
		if(dwTag == 0) break;
		if(dwTag != DESTROIED_TAG)
			tool.Add(pDERStr, dwDERLen);
		else
			pXdfRec->bHasFragment = TRUE;
		dwOffset += dwDERLen;
		pXdfRec->ulDataLen += dwDERLen;
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		读取当前选中的ODF中记录
//
//	返回：
//		CK_RV，详见PKCS#11
//
//  参数：
//		BYTE* pBuffer			读出的数据 
//		DWORD dwBufferLen		数据空间的大小
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::ReadODF(
	FILEHANDLE hFile,
	BYTE* pBuffer, 
	DWORD dwBufferLen
	)
{
	ASSERT(pBuffer != NULL);

	#define SIZE_PER_READ	g_cPathTable.bufSize

	BOOL bRetVal;
	DWORD dwReadLen = SIZE_PER_READ;		//读取数据的长度
	DWORD dwReadOffset = 0;					//读取数据的偏移量
	DWORD dwDEROffset = 0;					//DER解码偏移量
	BOOL bNeedRead = TRUE;					//需要读标志
	BOOL bNeedDER = TRUE;					//需要解码标志
	BYTE* pDERStr = NULL;
	DWORD dwDERLen = 0;

	while(dwReadOffset < dwBufferLen){
		//需要读
		if(bNeedRead){
			if((dwReadOffset + dwReadLen) > dwBufferLen)
				dwReadLen = (dwBufferLen - dwReadOffset);
			DWORD dwRetReadSize;
			bRetVal = ReadFile(hFile, dwReadLen, pBuffer + dwReadOffset, &dwRetReadSize, dwReadOffset);
			if(bRetVal != TRUE)
				return bRetVal;
		}
		//需要解码
		if(bNeedDER){
			//剩余DER编码的长度
			DWORD dwLeftLen = dwReadLen - dwDEROffset;
			//如果小于2须读
			if(dwLeftLen < 2){
				bNeedDER = TRUE;
				bNeedRead = TRUE;
				//读偏移
				dwReadOffset += (dwReadLen - dwLeftLen);
				//解码偏移
				dwDEROffset = 0;
				//需读取的长度
				dwReadLen = (SIZE_PER_READ < (dwBufferLen - dwReadOffset)) ? SIZE_PER_READ : (dwBufferLen - dwReadOffset);

				continue;
			}

			//获取DER编码的首地址
			pDERStr = pBuffer + dwReadOffset+ dwDEROffset;

			//当前一条DER编码的长度
			dwDERLen = GetDERTotalStrLen(pDERStr, dwLeftLen);
			//下面已经没有对象了
			if(::GetDERTag(pDERStr, dwDERLen) == 0)
				break;

			//当前一条DER编码的长度小于剩余DER编码的长度
			if(dwDERLen < dwLeftLen){
				//只解码不读
				bNeedDER = TRUE;
				bNeedRead = FALSE;
				//解码偏移
				dwDEROffset += dwDERLen;
			}
			//当前一条DER编码的长度大于剩余DER编码的长度
			else if(dwDERLen > dwLeftLen){
				//只读不解码
				bNeedDER = FALSE;
				bNeedRead = TRUE;
				//读偏移
				dwReadOffset += dwReadLen;
				//需读取的长度
				dwReadLen = dwDEROffset + dwDERLen - dwReadLen;
			}
			else{
				//读且解码
				bNeedDER = TRUE;
				bNeedRead = TRUE;
				//读偏移
				dwReadOffset += dwReadLen;
				//解码偏移
				dwDEROffset = 0;
				//需读取的长度
				dwReadLen = (SIZE_PER_READ < (dwBufferLen - dwReadOffset)) ? SIZE_PER_READ : (dwBufferLen - dwReadOffset);
			}
		}
		else{
			//读且解码
			bNeedDER = TRUE;
			bNeedRead = TRUE;
			//读偏移
			dwReadOffset += dwReadLen;
			//解码偏移
			dwDEROffset = 0;
			//需读取的长度
			dwReadLen = (SIZE_PER_READ < (dwBufferLen - dwReadOffset)) ? SIZE_PER_READ : (dwBufferLen - dwReadOffset);
		}
	}

	return TRUE;
}

 

/////////////////////////////////////////////////////////////////////
// CryptSPI Functions
void CTYCSP::AddModify()
{
	//清理碎片
	RemoveXdfFragment(&m_xdfPrk);
	//写入卡中
	FILEHANDLE hFile;
	if(OpenFile(g_cPathTable.prkdfPath, &hFile, NULL)){
		WriteFile(hFile, m_xdfPrk.cContent, m_xdfPrk.ulDataLen + 2, 0);
		CloseFile(hFile);
	}
	
	g_ModifyManager.AddModify((LPCSTR)m_reader.GetName());
}

//-------------------------------------------------------------------
//	功能：
//		Acquires a handle to the key container specified by the 
//	pszContainer parameter.
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV *phProv
//		CHAR *pszContainer
//		DWORD dwFlags
//		PVTableProvStruc pVTable
//  
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::AcquireContext(
	HCRYPTPROV *phProv,
	CHAR *pszContainer,
	DWORD dwFlags,
	PVTableProvStruc pVTable
	)
{ 
	TRACE_LINE("\nCSP句柄 = %d\n", GetHandle());

	//与卡连接
	if(!Connect()){
		TRACE_LINE("\n与卡连接失败\n");
		SETLASTERROR(SCARD_E_NO_SMARTCARD);
		return FALSE;
	}

	//参数检测
	if(phProv == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//先赋予初值
	*phProv = NULL;

	//如果有辅助库(DLL),则需验证签名

	CString szName;
	if(pszContainer != NULL)
		szName = pszContainer;

	//如果传入的名字为NULL或长度为0,则用缺省的名字(用户的登录名)
	BOOL bUseDefault = FALSE;
	CString szContainerName;
	if(szName.GetLength() != 0)
		szContainerName = szName;
	else{
		if(!GetDefaultKeyContainerName(szContainerName)){
			SETLASTERROR(NTE_FAIL);
			return FALSE;
		}
		bUseDefault = TRUE;
	}
	TRACE_LINE("\nKeyContainer的名字为:%s ;dwFlags = %08x\n", szContainerName, dwFlags);

	//读取Key Container
	if(!ReadKeyContainer()){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}

	//打开一个Key Container
	if((dwFlags == 0) /*|| (dwFlags & CRYPT_SILENT)*/){
		TRACE_LINE("\n打开一个Key Container\n");

		//通过名字查找Key Container
		CCSPKeyContainer* pKeyContainer = GetKeyContainerByName(szContainerName);
		if(pKeyContainer == NULL){
			SETLASTERROR(NTE_BAD_KEYSET);
			return FALSE;
		}
		//增加引用计数
		pKeyContainer->AddRef();
		//打开Key Container
		pKeyContainer->Open();
		//获取句柄
		*phProv = pKeyContainer->GetHandle();
	}
	else if(dwFlags & CRYPT_SILENT){
		TRACE_LINE("\n以安静的方式打开一个Key Container\n");

		CCSPKeyContainer* pKeyContainer = NULL;
		if(bUseDefault){
			//获取第一个不为VERIFY_CONTEXT的密钥容器
			for(int i  = 0; i < m_arKeyContainers.GetSize(); i++){
				if(m_arKeyContainers.GetAt(i)->GetName().Compare(VERIFY_KEY_CONTAINER_NAME)){
					pKeyContainer = m_arKeyContainers.GetAt(i);
					break;
				}
			}
		}
		else{
			//通过名字查找密钥容器
			pKeyContainer = GetKeyContainerByName(szContainerName);
		}

		if(pKeyContainer == NULL){
			//看起来有点怪,但通过智能卡注册站下载证书需要这样做
			if(bUseDefault)
				CreateKeyContainer(szContainerName, FALSE, pKeyContainer, FALSE);
		}
		if(pKeyContainer == NULL){
			SETLASTERROR(NTE_BAD_KEYSET);
			return FALSE;
		}

		//增加引用计数
		pKeyContainer->AddRef();
		//打开Key Container
		pKeyContainer->Open();
		//获取句柄
		*phProv = pKeyContainer->GetHandle();

		m_bSilent = TRUE;
	}
	//The application has no access to the private keys 
	//and the return pszContainer parameter must be set 
	//to NULL. This option is used with applications that 
	//do not use private keys.
	else if(dwFlags & CRYPT_VERIFYCONTEXT){
		TRACE_LINE("\n获取一个Key Container(CRYPT_VERIFYCONTEXT)\n");

		CCSPKeyContainer* pVerifyKeyContainer = NULL;
		if(szName.IsEmpty())
			pVerifyKeyContainer = GetKeyContainerByName(VERIFY_KEY_CONTAINER_NAME);
		else
			pVerifyKeyContainer = GetKeyContainerByName(szContainerName);

		if(pVerifyKeyContainer == NULL){
			SETLASTERROR(NTE_BAD_KEYSET);
			return FALSE;
		}

		//增加引用计数
		pVerifyKeyContainer->AddRef();
		*phProv = pVerifyKeyContainer->GetHandle();
	}
	//新增一个Key Container
	else if(dwFlags & CRYPT_NEWKEYSET){
		TRACE_LINE("\n新增一个Key Container\n");
  
		CCSPKeyContainer* pKeyContainer = GetKeyContainerByName(szContainerName);
		if(pKeyContainer != NULL){
			SETLASTERROR(NTE_EXISTS);
			return FALSE;
		}
		CreateKeyContainer(szContainerName, TRUE, pKeyContainer, TRUE);
		if(pKeyContainer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
		//增加引用计数
		pKeyContainer->AddRef();
		*phProv = pKeyContainer->GetHandle();
	}
	//删除一个Key Container
	else if(dwFlags & CRYPT_DELETEKEYSET){
		TRACE_LINE("\n删除一个Key Container\n");

		CCSPKeyContainer* pKeyContainer = GetKeyContainerByName(szContainerName);
		if(pKeyContainer == NULL){
			SETLASTERROR(NTE_KEYSET_NOT_DEF);
			return FALSE;
		}

		//如果有受保护的密钥对，则须校验PIN
		if(pKeyContainer->HaveProtectedKeyPairs()){
			if(!Login()){
				SETLASTERROR(NTE_PERM);
				return FALSE;
			}
		}
		
		//删除
		DestroyKeyContainer(pKeyContainer, TRUE);
	}
	//未知Flags
	else{
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	} 

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		Releases a context created by AcquireContext.
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv
//		DWORD dwFlags
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::ReleaseContext(
	HCRYPTPROV hProv,
	DWORD dwFlags
	)
{
	CCSPKeyContainer* pKeyContainer = GetKeyContainerByHandle(hProv);
	if(pKeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	pKeyContainer->Release();

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		Returns data about a cryptographic service provider 
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv
//		DWORD dwParam
//		BYTE *pbData
//		DWORD *pdwDataLen
//		DWORD dwFlags
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::GetProvParam(
	HCRYPTPROV hProv,
	DWORD dwParam,
	BYTE *pbData,
	DWORD *pdwDataLen,
	DWORD dwFlags
	)
{
	TRACE_LINE("dwParam = %08x\n", dwParam);

	//参数检测
	CCSPKeyContainer* pkeyContainer = GetKeyContainerByHandle(hProv);
	if(pkeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}
	if(pdwDataLen == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	BOOL bQueryBufferLen = (pbData == NULL);
	if(bQueryBufferLen){
		TRACE_LINE("\n调用的目的是为了判断数据的长度\n");
	}

	//参数先放于此
	BYTE* pbBuffer = NULL;
	DWORD dwBufferLen = 0;

	//The name of the current key container as a 
	//NULL-terminated CHAR string.
	if(dwParam == PP_CONTAINER || dwParam == PP_UNIQUE_CONTAINER){
		TRACE_LINE("\n获取KeyContainer的名字\n");

		CString szName = pkeyContainer->GetName();
		//include NULL-terminated
		if(szName.IsEmpty())
			dwBufferLen = 1;
		else
			dwBufferLen = szName.GetLength() + 1;

		pbBuffer = new BYTE[dwBufferLen];
		if(pbBuffer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}

		if(dwBufferLen == 1)
			pbBuffer[0] = 0;
		else{
			memcpy(pbBuffer, szName.LockBuffer(), dwBufferLen);
			szName.UnlockBuffer();
		}
	}
	//Information about an algorithm supported by 
	//the CSP being queried
	else if(dwParam == PP_ENUMALGS){
		TRACE_LINE("\n枚举算法标识\n");

		if(dwFlags & CRYPT_FIRST)
			m_nEnumAlgIdIndex = ENUM_INIT_INDEX;
		m_nEnumAlgIdIndex++;
		if(m_nEnumAlgIdIndex >= m_arAlgIds.GetSize()){
			SETLASTERROR(ERROR_NO_MORE_ITEMS);
			return FALSE;
		}

		PROV_ENUMALGS algInfo;
		algInfo.aiAlgid = g_cSupportAlgInfo[m_nEnumAlgIdIndex].aiAlgid;
		algInfo.dwBitLen = g_cSupportAlgInfo[m_nEnumAlgIdIndex].dwDefaultLen;
		algInfo.dwNameLen = g_cSupportAlgInfo[m_nEnumAlgIdIndex].dwNameLen;
		memcpy(algInfo.szName, g_cSupportAlgInfo[m_nEnumAlgIdIndex].szName, sizeof(g_cSupportAlgInfo[m_nEnumAlgIdIndex].szName));

		dwBufferLen = sizeof(algInfo);
		pbBuffer = new BYTE[dwBufferLen];
		if(pbBuffer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
		memcpy(pbBuffer, &algInfo, dwBufferLen);
		
		if(bQueryBufferLen)
			m_nEnumAlgIdIndex--;
	}
	//Information about an algorithm supported by the CSP. 
	//The structure returned contains more information about 
	//the algorithm than the structure returned for PP_ENUMALGS
	else if(dwParam == PP_ENUMALGS_EX){
		TRACE_LINE("\n枚举算法标识\n");

		if(dwFlags & CRYPT_FIRST)
			m_nEnumAlgIdIndex = ENUM_INIT_INDEX;
		m_nEnumAlgIdIndex++;
		if(m_nEnumAlgIdIndex >= m_arAlgIds.GetSize()){
			SETLASTERROR(ERROR_NO_MORE_ITEMS);
			return FALSE;
		}

		PROV_ENUMALGS_EX algInfoEx = g_cSupportAlgInfo[m_nEnumAlgIdIndex];
		dwBufferLen = sizeof(algInfoEx);
		pbBuffer = new BYTE[dwBufferLen];
		if(pbBuffer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
		memcpy(pbBuffer, &algInfoEx, dwBufferLen);
		
		if(bQueryBufferLen)
			m_nEnumAlgIdIndex--;
	}
	//The name of one of the key containers maintained by 
	//the CSP in the form of a NULL-terminated CHAR string. 
	else if(dwParam == PP_ENUMCONTAINERS){
		TRACE_LINE("\n枚举KeyContainer\n");

		if(dwFlags & CRYPT_FIRST)
			m_nEnumKeyContainerIndex = ENUM_INIT_INDEX;
		m_nEnumKeyContainerIndex++;
		if(m_nEnumKeyContainerIndex >= m_arKeyContainers.GetSize()){
			SETLASTERROR(ERROR_NO_MORE_ITEMS);
			return FALSE;
		}

		CCSPKeyContainer* pIterKeyContainer = m_arKeyContainers.GetAt(m_nEnumKeyContainerIndex);
		ASSERT(pIterKeyContainer != NULL);

		CString szName = pIterKeyContainer->GetName();
		//include NULL-terminated
		if(szName.IsEmpty())
			dwBufferLen = 1;
		else
			dwBufferLen = szName.GetLength() + 1;

		pbBuffer = new BYTE[dwBufferLen];
		if(pbBuffer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}

		if(dwBufferLen == 1)
			pbBuffer[0] = 0;
		else{
			memcpy(pbBuffer, szName.LockBuffer(), dwBufferLen);
			szName.UnlockBuffer();
		}
		
		if(bQueryBufferLen)
			m_nEnumKeyContainerIndex--;
	}
	//The name of the CSP in the form of a NULL-terminated 
	//CHAR string. 
	else if(dwParam == PP_NAME){
		TRACE_LINE("\n获取CSP的名字\n");

		CString szName = GetName();
		//include NULL-terminated
		if(szName.IsEmpty())
			dwBufferLen = 1;
		else
			dwBufferLen = szName.GetLength() + 1;

		pbBuffer = new BYTE[dwBufferLen];
		if(pbBuffer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
 
		if(dwBufferLen == 1)
			pbBuffer[0] = 0;
		else{
			memcpy(pbBuffer, szName.LockBuffer(), dwBufferLen);
			szName.UnlockBuffer();
		}
	}
	//The version number of the CSP
	else if(dwParam == PP_VERSION){
		TRACE_LINE("\n获取CSP的版本号\n");

		dwBufferLen = sizeof(DWORD);

		pbBuffer = new BYTE[dwBufferLen];
		if(pbBuffer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}

		DWORD dwVersion = GetVersion();
		memcpy(pbBuffer, &dwVersion, dwBufferLen);
	}
	//indicating how the CSP is implemented. 
	else if(dwParam == PP_IMPTYPE){
		TRACE_LINE("\n获取CSP的实现类型\n");

		dwBufferLen = sizeof(DWORD);

		pbBuffer = new BYTE[dwBufferLen];
		if(pbBuffer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}

		DWORD dwImpType = GetImpType();
		memcpy(pbBuffer, &dwImpType, dwBufferLen);
	}
	//indicating the provider type of the CSP.
	else if(dwParam == PP_PROVTYPE){
		TRACE_LINE("\n获取CSP的类型\n");

		dwBufferLen = sizeof(DWORD);

		pbBuffer = new BYTE[dwBufferLen];
		if(pbBuffer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}

		DWORD dwType = GetType();
		memcpy(pbBuffer, &dwType, dwBufferLen);
	}
	else if(dwParam == PP_SIG_KEYSIZE_INC){
		TRACE_LINE("\n获取签名密钥对递增尺寸\n");

		dwBufferLen = sizeof(DWORD);
		pbBuffer = new BYTE[dwBufferLen];
		if(pbBuffer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
		DWORD dwValue = 1024;
		memcpy(pbBuffer, &dwValue, dwBufferLen);
	}
	else if(dwParam == PP_KEYX_KEYSIZE_INC){
		TRACE_LINE("\n获取加密密钥对递增尺寸\n");

		dwBufferLen = sizeof(DWORD);
		pbBuffer = new BYTE[dwBufferLen];
		if(pbBuffer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
		DWORD dwValue = 1024;
		memcpy(pbBuffer, &dwValue, dwBufferLen);
	}
	else if(dwParam == PP_KEYSET_SEC_DESCR){
		//忽略该参数
		TRACE_LINE("\n获取CSP的PP_KEYSET_SEC_DESCR\n");
	}
	else{
		SETLASTERROR(NTE_BAD_TYPE);
		return FALSE;
	}

	BOOL bRetVal = TRUE;
	if(pbData != NULL){
		if(*pdwDataLen < dwBufferLen){
			SETLASTERROR(ERROR_MORE_DATA);
			bRetVal = FALSE;
		}
		else{
			if(pbBuffer != NULL)
				memcpy(pbData, pbBuffer, dwBufferLen);
		}
	}

	*pdwDataLen = dwBufferLen;
	if(pbBuffer != NULL) delete pbBuffer;

	return bRetVal;
}

/* Smart card management error codes */
//#define SCARD_E_INVALID_CHV									0x8010002AL
#define SCARD_W_WRONG_CHV									0x8010006BL
#define SCARD_W_CHV_BLOCKED									0x8010006CL
#define SCARD_W_CARD_NOT_AUTHENTICATED						0x8010006FL

//-------------------------------------------------------------------
//	功能：
//		customizes the operations of a cryptographic service provider 
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv
//		DWORD dwParam
//		BYTE *pbData
//		DWORD dwFlags
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::SetProvParam(
	HCRYPTPROV hProv,
	DWORD dwParam,
	BYTE *pbData,
	DWORD dwFlags
	)
{
	TRACE_LINE("dwParam = %08x\n", dwParam);
	//参数检测
	CCSPKeyContainer* pkeyContainer = GetKeyContainerByHandle(hProv);
	BOOL bRet = TRUE;
	if(pkeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}
	
	if(dwParam == PP_KEYSET_SEC_DESCR){
		//忽略该参数
	}
	else if (dwParam == PP_RESET_SEC_STAUS){   
		//jit定义的复位安全状态
		m_reader.Logout();
		m_bLogin = FALSE;
	}
	else if(dwParam == PP_KEYEXCHANGE_PIN || dwParam == PP_SIGNATURE_PIN){
		//注销
		if(pbData == NULL){
			m_reader.Logout();
			m_bLogin = FALSE;
		}
		else{
			//校验
			if(!m_bLogin){
				int nRetry;
				m_bLogin = VerifyPin(pbData, lstrlen((CHAR* )pbData), nRetry);
				if(!m_bLogin){
					if(nRetry == 0){
						SETLASTERROR(SCARD_W_CHV_BLOCKED);
					}
					else{
						SETLASTERROR(SCARD_W_WRONG_CHV);
					}
					return FALSE;
				}
			}
		}
	}
	else if(dwParam == PP_CHANGE_PASSWORD){
		//更改用户PIN码
		if(!m_bLogin || pbData == NULL){
			SETLASTERROR(NTE_PERM);
			return FALSE;
		}
		else{
			return m_reader.ChangePIN(pbData, lstrlen((CHAR* )pbData));
		}
	}
	else{
		SETLASTERROR(NTE_BAD_TYPE);
		return FALSE;
	}
	
	if (!bRet)
		SETLASTERROR(NTE_FAIL);
	return bRet;
}

/////////////////////////////////////////////////////////////////////
// class CTYCSPManager
//

//-------------------------------------------------------------------
//	功能：
//		构造CTYCSPManager
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
CTYCSPManager::CTYCSPManager()
{
	m_hNextCSPHandle = 1;
}

//-------------------------------------------------------------------
//	功能：
//		析构CTYCSPManager
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
CTYCSPManager::~CTYCSPManager()
{
}

//-------------------------------------------------------------------
//	功能：
//		通过句柄获取CSP对象
//
//	返回：
//		CSP对象的指针
//
//  参数：
//		HCRYPTCSP hCSP	CSP对象的句柄
//
//  说明：
//-------------------------------------------------------------------
CTYCSP*
CTYCSPManager::GetCSPByHandle(
	HCRYPTCSP hCSP
	)
{
	int nCount = m_arCSPs.GetSize();
	CTYCSP* pCSPObject = NULL;
	for(int i = 0; i < nCount; i++){
		pCSPObject = m_arCSPs.GetAt(i);
		if(pCSPObject->GetHandle() == hCSP)
			return pCSPObject;
	}

	return NULL;
}

//-------------------------------------------------------------------
//	功能：
//		通过读写器的名字获取CSP对象
//
//	返回：
//		CSP对象的指针
//
//  参数：
//		LPCTSTR lpszName	读写器的名字
//
//  说明：
//-------------------------------------------------------------------
CTYCSP*
CTYCSPManager::GetCSPByReaderName(
	LPCTSTR lpszName
	)
{
	int nCount = m_arCSPs.GetSize();
	CTYCSP* pCSPObject = NULL;
	for(int i = 0; i < nCount; i++){
		pCSPObject = m_arCSPs.GetAt(i);
		if(pCSPObject->GetReaderName().CompareNoCase(lpszName) == 0)
			return pCSPObject;
	}

	return NULL;
}

//-------------------------------------------------------------------
//	功能：
//		通过读写器的索引和类型获取CSP对象
//
//	返回：
//		CSP对象的指针
//
//  参数：
//		int nIndex			读写器的索引
//		ReaderType rdType	读写器类型
//
//  说明：
//-------------------------------------------------------------------
CTYCSP*
CTYCSPManager::GetCSPByReaderIndex(
	int nIndex, 
	ReaderType rdType
	)
{
	int nCount = m_arCSPs.GetSize();
	CTYCSP* pCSPObject = NULL;
	for(int i = 0; i < nCount; i++){
		pCSPObject = m_arCSPs.GetAt(i);
		if(pCSPObject->GetReaderIndex() == nIndex &&
			pCSPObject->GetReaderType() == rdType)
			return pCSPObject;
	}

	return NULL;
}


//-------------------------------------------------------------------
//	功能：
//		初始化
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
BOOL
CTYCSPManager::Initialize()
{
	TRACE_FUNCTION("CTYCSPManager::Initialize");

	m_dwEnumReaderFlag = 0xFFFFFF;
	m_bFilterReader = TRUE;
	m_bSSO = FALSE;

	CRegKey reg;
	LONG lResult = reg.Open(HKEY_LOCAL_MACHINE, 
		"SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Tianyu Cryptographic Service Provider"
		);
	if(lResult == ERROR_SUCCESS){
		DWORD dwValue;

		//枚举读写器标志
		lResult = reg.QueryValue(dwValue, "ReaderEnumFlag");
		if(lResult == ERROR_SUCCESS)
			m_dwEnumReaderFlag = dwValue;

		//过滤读写器标志
		lResult = reg.QueryValue(dwValue, "FilterReader");
		if(lResult == ERROR_SUCCESS)
			m_bFilterReader = dwValue;

		//SSO标志
		lResult = reg.QueryValue(dwValue, "LoginSSO");
		if(lResult == ERROR_SUCCESS)
			m_bSSO = dwValue;

		reg.Close();
	}

	TRACE_LINE("m_dwEnumReaderFlag = %d; m_bFilterReader = %d; m_bSSO = %d\n", m_dwEnumReaderFlag, m_bFilterReader, m_bSSO);

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		释放资源
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
BOOL
CTYCSPManager::Finalize()
{
	TRACE_FUNCTION("CTYCSPManager::Finalize");

	ReleaseCSPs();

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		建立CSP对象
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
void CTYCSPManager::CreateCSPs()
{
	if(m_dwEnumReaderFlag & ENUM_USBPORT_READER)
		CreateUSBPortCSP();
	if(m_dwEnumReaderFlag & ENUM_PCSC_READER)
		CreatePCSCCSP();
	if(m_dwEnumReaderFlag & ENUM_SERIALPORT_READER)
		CreateSerialPortCSP();
}

//-------------------------------------------------------------------
//	功能：
//		建立机具为PCSC的CSP对象
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
void CTYCSPManager::CreatePCSCCSP()
{
	//载入PCSC库
	g_SCardFuncHolder.Load();
	if(g_SCardFuncHolder.m_listFunc.pfnSCardEstablishContext == NULL ||
		g_SCardFuncHolder.m_listFunc.pfnSCardReleaseContext == NULL ||
		g_SCardFuncHolder.m_listFunc.pfnSCardListReaders == NULL ||
		g_SCardFuncHolder.m_listFunc.pfnSCardFreeMemory == NULL)
	{
		return;
	}
	
	LONG lResult;
	LPTSTR mszReaderNames = NULL;
	SCARDCONTEXT hSC = NULL;

	//建立资源管理器的上下文
	lResult = g_SCardFuncHolder.m_listFunc.pfnSCardEstablishContext(
		SCARD_SCOPE_USER, NULL, NULL, &hSC
		);
	if (lResult != SCARD_S_SUCCESS)
		return;
	
	//查找读写器列表
	DWORD dwAutoAllocate = SCARD_AUTOALLOCATE;
	lResult = g_SCardFuncHolder.m_listFunc.pfnSCardListReaders(
		hSC, SCARD_DEFAULT_READERS, (LPTSTR)&mszReaderNames, &dwAutoAllocate
		);
	if (lResult != SCARD_S_SUCCESS){
		//清除所有的PCSC机具
		int pRemoveIndex[256];
		DWORD dwRemoveNum = 0;
		for(int i = 0; i < m_arCSPs.GetSize(); i++){
			CTYCSP* pCSPObject = m_arCSPs.GetAt(i);
			if(pCSPObject->GetReaderType() != RT_PCSC)
				continue;
			pCSPObject->DisConnect();
			pRemoveIndex[dwRemoveNum++] = i;
			delete pCSPObject;
		}
		for(DWORD dwI = 0; dwI < dwRemoveNum; dwI++)
			m_arCSPs.RemoveAt(pRemoveIndex[dwI] - dwI);

		g_SCardFuncHolder.m_listFunc.pfnSCardReleaseContext(hSC);
		return;
	}

	//获取读写器的数目和名称并构造CSP对象
	DWORD dwNumReaders;
	LPCTSTR szReaderName;

	//察看是否拨除了Reader
	int pRemoveIndex[256];
	DWORD dwRemoveNum = 0;
	for(int i = 0; i < m_arCSPs.GetSize(); i++){
		CTYCSP* pCSPObject = m_arCSPs.GetAt(i);
		if(pCSPObject->GetReaderType() != RT_PCSC)
			continue;
		LPCTSTR szIterName = pCSPObject->GetReaderName();
		for(dwNumReaders = 0, szReaderName = mszReaderNames;
		   *szReaderName != _T('\0');
		   dwNumReaders++)
		{
			if(lstrcmpi(szIterName, szReaderName) == 0)
				break;
			szReaderName += lstrlen(szReaderName) + 1;
		} 
	   if(*szReaderName == _T('\0')){
			pCSPObject->DisConnect();
			pRemoveIndex[dwRemoveNum++] = i;
			delete pCSPObject;
	   }
	}
	for(DWORD dwI = 0; dwI < dwRemoveNum; dwI++)
		m_arCSPs.RemoveAt(pRemoveIndex[dwI] - dwI);

	//检查是否有其他程序对现有的象进行了修改
	g_ModifyManager.FixModifies(&m_arCSPs);

	//察看是否插入了新的Reader
	for(dwNumReaders = 0, szReaderName = mszReaderNames;
	   *szReaderName != _T('\0');
	   dwNumReaders++)
	{
	   if(m_bFilterReader && !IsContainSubString(szReaderName, "tianyu")){
			szReaderName += lstrlen(szReaderName) + 1;
		   continue;
	   }
	   
		//插入了新的Reader
	   if(GetCSPByReaderName(szReaderName) == NULL){
			//创建CSP对象
			CTYCSP* pCSPObject = new CTYCSP;
			if(pCSPObject == NULL)
				break;

			//设置CSP句柄
			pCSPObject->SetHandle(m_hNextCSPHandle++);
			//设置CSP对应的读写器的名字
			pCSPObject->SetReaderName(szReaderName);
			//设置读写器类型
			pCSPObject->SetReaderType(RT_PCSC);
			//初始化
			pCSPObject->Initialize();

			//加入链表
			m_arCSPs.Add(pCSPObject);
	   }
		szReaderName += lstrlen(szReaderName) + 1;
	}

	g_SCardFuncHolder.m_listFunc.pfnSCardFreeMemory(hSC, (LPVOID)mszReaderNames);
	g_SCardFuncHolder.m_listFunc.pfnSCardReleaseContext(hSC);
}

//-------------------------------------------------------------------
//	功能：
//		建立机具为TYKEY的CSP对象
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
void CTYCSPManager::CreateUSBPortCSP()
{
	//载入TYKEY接口
	g_TYKeyFuncHolder.Load();
	try{
		if(g_TYKeyFuncHolder.m_listFunc.pfnTYKey_Change)
			g_TYKeyFuncHolder.m_listFunc.pfnTYKey_Change();
		else
			return;
	}
	catch(...)
	{
		TRACE_LINE("TYKey_Change error\n");
	}

	//列举TYKEY的状态
	UCHAR state[16];
	try{
		if(g_TYKeyFuncHolder.m_listFunc.pfnTYKey_Status)
			g_TYKeyFuncHolder.m_listFunc.pfnTYKey_Status(state);
		else
			return;
	}
	catch(...)
	{
		TRACE_LINE("TYKey_Status error\n");
	}

	//察看是否拨除了TYKEY
	int pRemoveIndex[16];
	DWORD dwRemoveNum = 0;
	for(int i = 0; i < m_arCSPs.GetSize(); i++){
		CTYCSP* pCSPObject = m_arCSPs.GetAt(i);
		if(pCSPObject->GetReaderType() != RT_USBPORT)
			continue;
		if(state[pCSPObject->GetReaderIndex()] == 0){
			pCSPObject->DisConnect();
			pRemoveIndex[dwRemoveNum++] = i;
			delete pCSPObject;
	   }
	}
	for(DWORD dwI = 0; dwI < dwRemoveNum; dwI++)
		m_arCSPs.RemoveAt(pRemoveIndex[dwI] - dwI);

	//检查是否有其他程序对现有的象进行了修改
	g_ModifyManager.FixModifies(&m_arCSPs);

	//察看是否插入了新的TYKEY
	for(i = 0; i < sizeof(state)/sizeof(UCHAR); i++){
		if(state[i] == 0)
			continue;

		//不是新插入了的TYKEY
		if(GetCSPByReaderIndex(i, RT_USBPORT))
			continue;

		//创建CSP对象
		CTYCSP* pCSPObject = new CTYCSP;
		if(pCSPObject == NULL)
			break;

		//设置CSP句柄
		pCSPObject->SetHandle(m_hNextCSPHandle++);
		//设置读写器类型
		pCSPObject->SetReaderType(RT_USBPORT);
		//设置读写器的索引
		pCSPObject->SetReaderIndex(i);
		//初始化
		pCSPObject->Initialize();

		//加入链表
		m_arCSPs.Add(pCSPObject);
	}
}

//-------------------------------------------------------------------
//	功能：
//		建立串口读卡器的CSP对象
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
void CTYCSPManager::CreateSerialPortCSP()
{
	g_TYReaderFuncHolder.Load();

	if(g_TYReaderFuncHolder.m_listFunc.pfnTY_Status == NULL)
		return;

	BYTE status[MAX_COMPORT_NUM] = {0};
	g_TYReaderFuncHolder.m_listFunc.pfnTY_Status(status);
	
	//察看是否拨除了读卡器
	int pRemoveIndex[MAX_COMPORT_NUM];
	DWORD dwRemoveNum = 0;
	for(int i = 0; i < m_arCSPs.GetSize(); i++){
		CTYCSP* pCSPObject = m_arCSPs.GetAt(i);
		if(pCSPObject->GetReaderType() != RT_COMPORT)
			continue;
		if(status[pCSPObject->GetReaderIndex()] == 0){
			pCSPObject->DisConnect();
			pRemoveIndex[dwRemoveNum++] = i;
			delete pCSPObject;
	   }
	}
	for(DWORD dwI = 0; dwI < dwRemoveNum; dwI++)
		m_arCSPs.RemoveAt(pRemoveIndex[dwI] - dwI);

	//察看是否插入了新的读卡器
	for(i = 0; i < sizeof(status); i++){
		if(status[i] == 0)
			continue;

		//不是新插入了的读卡器
		if(GetCSPByReaderIndex(i, RT_COMPORT))
			continue;

		//创建CSP对象
		CTYCSP* pCSPObject = new CTYCSP;
		if(pCSPObject == NULL)
			break;

		//设置CSP句柄
		pCSPObject->SetHandle(m_hNextCSPHandle++);
		//设置读写器类型
		pCSPObject->SetReaderType(RT_COMPORT);
		//设置读写器的索引
		pCSPObject->SetReaderIndex(i);
		//初始化
		pCSPObject->Initialize();

		//加入链表
		m_arCSPs.Add(pCSPObject);
	}
}

//-------------------------------------------------------------------
//	功能：
//		获取CSP对象的数目
//
//	返回：
//		数目
//
//  参数：
//
//  说明：
//-------------------------------------------------------------------
DWORD
CTYCSPManager::GetCSPCount()
{
	return m_arCSPs.GetSize();
}

//-------------------------------------------------------------------
//	功能：
//		通过索引获取CSP对象
//
//	返回：
//		CSP对象的指针
//
//  参数：
//		int nIndex	索引
//
//  说明：
//-------------------------------------------------------------------
CTYCSP*
CTYCSPManager::GetCSPAt(
	int nIndex
	)
{
	int nCount = m_arCSPs.GetSize();
	if(nIndex < 0 || nIndex >= nCount)
		return NULL;

	return m_arCSPs.GetAt(nIndex);
}

//-------------------------------------------------------------------
//	功能：
//		释放CSP对象
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
void CTYCSPManager::ReleaseCSPs()
{
	int nCount = m_arCSPs.GetSize();
	CTYCSP* pCSPObject = NULL;
	for(int i = 0; i < nCount; i++){
		pCSPObject = m_arCSPs.GetAt(i);
		delete pCSPObject;
	}
	
	m_arCSPs.RemoveAll();
}


//-------------------------------------------------------------------
//	功能：
//		Acquires a handle to the key container specified by the 
//	pszContainer parameter.
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTPROV *phProv
//		CHAR *pszContainer
//		DWORD dwFlags
//		PVTableProvStruc pVTable
//  
//  说明：
//-------------------------------------------------------------------
SCARDHANDLE WINAPI Connect(IN SCARDCONTEXT, IN LPSTR, IN LPSTR, IN PVOID)
{
	return NULL;
}
BOOL 
CTYCSPManager::AcquireContext(
	HCRYPTPROV *phProv,
	CHAR *pszContainer,
	DWORD dwFlags,
	PVTableProvStruc pVTable
	)
{
	//先创建CSP列表
	CreateCSPs();

	//判断容器名中是否已包含读写器的路径
	BOOL bHaveReaderPath = FALSE;
	CString szReaderPath = _T("");
	CString szContainerName = _T("");
	if(pszContainer != NULL) szContainerName = pszContainer;
	if(szContainerName.Find(_T("\\\\.\\")) == 0){
		TRACE_LINE("\n初始容器名 %s 包含读写器路径\n", szContainerName);
		szContainerName.TrimLeft(_T("\\\\.\\"));

		//分离读写器与容器的名字
		bHaveReaderPath = TRUE;
		int pos = szContainerName.Find(_T("\\"));
		if(pos < 0){
			szReaderPath = szContainerName;
			szContainerName = _T("");
		}
		else{
			szReaderPath = szContainerName.Mid(0, pos);
			szContainerName = szContainerName.Mid(pos + 1);
		}
		TRACE_LINE("读写器的名字: %s;容器名字 %s\n", szReaderPath, szContainerName);
	}
	
	//判断是否要显示读写器选择框
	BOOL bOpenCardName = FALSE;
	if(bHaveReaderPath) 
		bOpenCardName = FALSE;
	else if(dwFlags & CRYPT_SILENT)
		bOpenCardName = FALSE;
	else{
		if((dwFlags & CRYPT_VERIFYCONTEXT) || (dwFlags & CRYPT_NEWKEYSET))
			bOpenCardName = TRUE;
	}
 
	if(bOpenCardName){
		TCHAR szReader[MAX_PATH] = {0}, szCard[MAX_PATH] = {0};
		TCHAR szSearchCard[MAX_PATH];
		//卡片的名字
		int nOffset = 0;
		for(int i = 0; i < sizeof(g_szSupportCardName) / sizeof(TCHAR*); i++){
			lstrcpy(szSearchCard + nOffset, g_szSupportCardName[i]);
			nOffset += (lstrlen(g_szSupportCardName[i]) + 1);
		}
		//以双'\0'结尾，故加上第二个
		szSearchCard[nOffset] = (TCHAR)0x00;

		OPENCARDNAME dlgStruct;
		//初始化
		memset(&dlgStruct, 0, sizeof(dlgStruct)); 
		CString szDlgTitle;
		szDlgTitle.LoadString(IDS_CS_SELECTCARDDLG_TITLE + g_nRscOffset);
		dlgStruct.dwStructSize = sizeof(dlgStruct);
		dlgStruct.hSCardContext = NULL;
		dlgStruct.dwFlags = SC_DLG_MINIMAL_UI;
		dlgStruct.lpstrRdr = szReader;
		dlgStruct.nMaxRdr = MAX_PATH;
		dlgStruct.lpstrCard = szCard;
		dlgStruct.nMaxCard = MAX_PATH;
		dlgStruct.lpstrTitle = szDlgTitle;
		dlgStruct.lpstrCardNames = szSearchCard;
		dlgStruct.nMaxCardNames = MAX_PATH;
		dlgStruct.dwShareMode = SCARD_SHARE_SHARED;
		dlgStruct.dwPreferredProtocols = SCARD_PROTOCOL_T0;
		//不连接卡
		dlgStruct.lpfnConnect = Connect;

		LONG lResult = GetOpenCard(&dlgStruct, m_bFilterReader);
		if(lResult == SCARD_S_SUCCESS){
			CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByReaderName(dlgStruct.lpstrRdr);
			if(pCSPObject)
				return pCSPObject->AcquireContext(phProv, (CHAR* )(LPCTSTR)szContainerName, dwFlags, pVTable);
		}
	}
	else{
		CTYCSP* pCSPObject = NULL;

		if(bHaveReaderPath){
			pCSPObject = g_theTYCSPManager.GetCSPByReaderName(szReaderPath);
			if(pCSPObject)
				return pCSPObject->AcquireContext(phProv, (CHAR* )(LPCTSTR)szContainerName, dwFlags, pVTable);
		}
		else{
			int nCount = m_arCSPs.GetSize();
			for(int i = 0; i < nCount; i++){
				pCSPObject = m_arCSPs.GetAt(i);
				if(pCSPObject->AcquireContext(phProv, (CHAR* )(LPCTSTR)szContainerName, dwFlags, pVTable))
					return TRUE;
			}
		}
	}

	SETLASTERROR(NTE_FAIL);
	return FALSE;
}


/////////////////////////////////////////////////////////////////////
//	定义唯一的TYCSPManager实例
//
CTYCSPManager g_theTYCSPManager;


/////////////////////////////////////////////////////////////////////
// class CCSPRandomNumberGenerator

//-------------------------------------------------------------------
//	功能：
//		初始化
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
void 
CCSPRandomNumberGenerator::init()
{
	srand((unsigned int)time(NULL));
}

//-------------------------------------------------------------------
//	功能：
//		返回一个字节的随机数
//
//	返回：
//		一个字节的随机数
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
byte 
CCSPRandomNumberGenerator::GetByte()
{
	return ((byte)rand());
}

/////////////////////////////////////////////////////////////////////
//	定义唯一的 CCSPRandomNumberGenerator 实例
CCSPRandomNumberGenerator g_rng;
