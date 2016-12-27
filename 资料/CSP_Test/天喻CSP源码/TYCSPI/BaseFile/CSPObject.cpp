#include "Stdafx.h"
#include "time.h"
#include "CSPObject.h"
#include "KeyContainer.h"
#include "CSPKey.h"
#include "DERCoding.h"
#include "DERTool.h"
#include "UserFile.h"
#include "HelperFunc.h"
#include "atlbase.h"
#include "Modifier.h"
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
	return (algId == CALG_RC2 || algId == CALG_RC4 || algId == CALG_DES || algId == CALG_3DES || algId == CALG_3DES_112 ||
		algId == g_dwSSF33Algid  || algId == g_dwSCB2Algid);
}

//-------------------------------------------------------------------
//	功能：
//		判断一个字符串中是否包含一个子串
//
//	返回：
//		TRUE：包含		FALSE：不包含
//
//  参数：
//		LPCTSTR lpszSource		源串
//		LPCTSTR lpszSub			子串
//
//  说明：
//-------------------------------------------------------------------
BOOL IsContainSubString(LPCTSTR lpszSource, LPCTSTR lpszSub)
{
	if(lpszSource == NULL || lpszSub == NULL)
		return FALSE;

	TCHAR* szSourceDup = _tcsdup(lpszSource);
	TCHAR* szSubDup = _tcsdup(lpszSub);
	if(szSourceDup == NULL || szSubDup == NULL){
		if(szSourceDup != NULL) free(szSourceDup);
		if(szSubDup != NULL) free(szSubDup);
		return FALSE;
	}
	TCHAR* szSourceUp = _tcsupr(szSourceDup);
	TCHAR* szSubUp = _tcsupr(szSubDup);
	BOOL bRetVal = (_tcsstr(szSourceDup, szSubUp) != NULL);

	free(szSourceDup);
	free(szSubDup);

	return bRetVal;
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
	int nLen = lstrlen(lpszName) + 1;
	m_szName = new TCHAR[nLen];
	if(m_szName != NULL) lstrcpy(m_szName, lpszName);
	m_dwType = PROV_RSA_FULL;
	m_dwVersion = 0x00000105;
	m_dwImpType = CRYPT_IMPL_MIXED | CRYPT_IMPL_REMOVABLE;
	
	m_hHandle = -1;
	m_hNextKCHandle = 0;
	
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
	
	if(m_szName != NULL){
		delete m_szName;
		m_szName = NULL;
	}
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
		delete pKeyContainer;
	}
	m_arKeyContainers.RemoveAll();

	//释放UserFile列表
	nCount = m_arUserFiles.GetSize();
	for(i = 0; i < nCount; i++){
		CUserFile* pUserFile = m_arUserFiles.GetAt(i);
		delete pUserFile;
	}
	m_arUserFiles.RemoveAll();

	//数据初始化
	m_nReadFlag = 0;
	m_nEnumAlgIdIndex = ENUM_INIT_INDEX;
	m_nEnumKeyContainerIndex = ENUM_INIT_INDEX;
	m_nUserType = UT_PUBLIC;
	memset(&m_xdfPrk, 0, sizeof(m_xdfPrk));
	memset(&m_xdfData, 0, sizeof(m_xdfData));

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
	TRACE_LINE("读卡器的名字 = %s\n\n", GetReaderName());

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
//		无
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::Finalize(BOOL bWrite)
{
	TRACE_FUNCTION("CTYCSP::Finalize");
	TRACE_LINE("\n\nCSP句柄 = %d\n\n", GetHandle());

	if(bWrite){
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

		//整理卡中的碎片
		if(m_xdfData.bHasFragment){
			//消除XDF文件中的碎片
			RemoveXdfFragment(&m_xdfData);

			//写入卡中
			FILEHANDLE hFile;
			if(OpenFile(g_cPathTable.dodfPath, &hFile, NULL)){
				WriteFile(hFile, m_xdfData.cContent, m_xdfData.ulDataLen + 2, 0);
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
//		从卡中读出文件索引
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
CTYCSP::ReadFileIndex()
{
	//判断是否已读
	if(m_nReadFlag & READED_FILEINDEX)
		return TRUE;

	//判断是否存在UserFile的索引文件,没有则创建
	FILEHANDLE hUserFileIndex = NULL;
	if(!OpenFile(g_cPathTable.dodfPath, &hUserFileIndex)){
		BOOL bRetVal = CreateFile(
			g_cPathTable.dodfPath, 0x200, &hUserFileIndex, 
			0x00, g_cPathTable.free, g_cPathTable.free
			);
		if(!bRetVal)
			return FALSE;
		//写入初始数据
		bRetVal = OpenFile(g_cPathTable.dodfPath, &hUserFileIndex);
		if(!bRetVal)
			return FALSE;
		BYTE pbData[] = {0x00, 0x00};
		bRetVal = WriteFile(hUserFileIndex, pbData, sizeof(pbData));
		CloseFile(hUserFileIndex);
		if(!bRetVal)
			return FALSE;

		//设置读取标记为TRUE
		m_nReadFlag |= READED_FILEINDEX;

		return TRUE;
	}

	//读出卡中UserFile的DER编码
	CDERTool tool;
	if(!ReadObjectDERs(g_cPathTable.dodfPath, &m_xdfData, tool))
		return FALSE;
	
	//整理卡中的碎片
	if(m_xdfData.bHasFragment){
		//消除XDF文件中的碎片
		RemoveXdfFragment(&m_xdfData);

		//写入卡中
		FILEHANDLE hFile;
		if(OpenFile(g_cPathTable.dodfPath, &hFile, NULL)){
			WriteFile(hFile, m_xdfData.cContent, m_xdfData.ulDataLen + 2, 0);
			CloseFile(hFile);
		}
	}

	//创建UserFile对象
	LPBYTE derString = NULL;
	DWORD dwDerStringLen = 0;
	for(int i = 0; i < tool.GetCount(); i++){
		if(tool.GetAt(i, derString, dwDerStringLen) && derString != NULL){
			CUserFile* pUserFile = new CUserFile(this);
			if(pUserFile != NULL){
				pUserFile->LoadFromToken(derString, dwDerStringLen, i);
				m_arUserFiles.Add(pUserFile);
			}
		}
	}

	//设置读取标记为TRUE
	m_nReadFlag |= READED_FILEINDEX;

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		销毁指定的UserFile对象，并将其从链表中去除
//
//	返回：
//		无
//
//  参数：
//		CUserFile* pDestroyUserFile				待销毁的UserFile对象
//		BOOL bDestroyOnToken					是否从卡中销毁
//
//  说明：
//-------------------------------------------------------------------
void
CTYCSP::DestroyUserFile(
	CUserFile* pDestroyUserFile,
	BOOL bDestroyOnToken /*=FALSE*/
	)
{
	if(pDestroyUserFile == NULL)
		return;

	//总数
	int nCount = m_arUserFiles.GetSize();

	//先查找其在链表中的索引
	int nIdx = -1;
	for(int i = 0; i < nCount; i++){
		CUserFile* pUserFile = m_arUserFiles.GetAt(i);
		if(pDestroyUserFile == pUserFile){
			nIdx = i;
			break;
		}
	}

	//没有找到
	if(nIdx == -1)
		return;

	if(bDestroyOnToken){
		pDestroyUserFile->DestroyOnToken();
		//后面的索引减1
		for(i = nIdx + 1; i < nCount; i++){
			CUserFile* pUserFile = m_arUserFiles.GetAt(i);
			pUserFile->SetTokenIndex(pUserFile->GetTokenIndex() - 1);
		}
	}

	delete pDestroyUserFile;
	//从链表中删除
	m_arUserFiles.RemoveAt(nIdx);
}

//-------------------------------------------------------------------
//	功能：
//		通过句柄获取一个UserFile对象
//
//	返回：
//		UserFile对象指针
//
//  参数：
//		HCRYPTPROV hUserFile	句柄	
//
//  说明：
//-------------------------------------------------------------------
CUserFile* 
CTYCSP::GetUserFileByHandle(
	HCRYPTPROV hUserFile
	)
{
	int nCount = m_arUserFiles.GetSize();
	for(int i = 0; i < nCount; i++){
		CUserFile* pUserFile = m_arUserFiles.GetAt(i);
		if(!pUserFile->IsOpened())
			continue;
		if(pUserFile->GetHandle() == hUserFile)
			return pUserFile;
	}

	return NULL;
}

//-------------------------------------------------------------------
//	功能：
//		通过名字获取一个UserFile对象
//
//	返回：
//		UserFile对象指针
//
//  参数：
//		LPCTSTR lpszName	名字	
//
//  说明：
//-------------------------------------------------------------------
CUserFile* 
CTYCSP::GetUserFileByName(
	LPCTSTR lpszName
	)
{
	//先从卡中读取文件索引
	if(!ReadFileIndex())
		return NULL;

	int nCount = m_arUserFiles.GetSize();
	for(int i = 0; i < nCount; i++){
		CUserFile* pUserFile = m_arUserFiles.GetAt(i);
		if(lstrcmp(pUserFile->GetName(), lpszName) == 0)
			return pUserFile;
	}

	return NULL;
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
	if(m_nReadFlag & READED_KEYCONTAINER)
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
	m_nReadFlag |= READED_KEYCONTAINER;

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
		if(lstrcmp(pKeyContainer->GetName(), VERIFY_KEY_CONTAINER_NAME) != 0)
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
		if(lstrcmp(pKeyContainer->GetName(), lpszName) == 0)
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
//		TCHAR szDefaultName[UNLEN + 1]	名字	
//
//  说明：
//		用当前登录的用户名作为所要获取的Key Container对象的名字
//-------------------------------------------------------------------
BOOL 
CTYCSP::GetDefaultKeyContainerName(
	TCHAR szDefaultName[UNLEN + 1]
	)
{
//	DWORD dwSize = sizeof(szDefaultName);
//	BOOL bRetVal = ::GetUserName(szDefaultName, &dwSize);
//	if(!bRetVal) 
		lstrcpy(szDefaultName, DEFAULT_KEY_CONTAINER_NAME); 

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
//		XDF_TYPE dfType				XDF的类型
//		SHARE_XDF* pXdfRec			指向ODF记录的指针
//
//  说明：
//-------------------------------------------------------------------
BOOL
CTYCSP::GetXdf(
	XDF_TYPE dfType, 
	SHARE_XDF* pXdfRec
	)
{
	if(pXdfRec == NULL)
		return FALSE;

	if(dfType == DFTYPE_PRK)
		memcpy(pXdfRec, &m_xdfPrk, sizeof(SHARE_XDF));
	else if(dfType == DFTYPE_DATA)
		memcpy(pXdfRec, &m_xdfData, sizeof(SHARE_XDF));
	else
		return FALSE;

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

	if(dfType == DFTYPE_PRK)
		memcpy(&m_xdfPrk, pXdfRec, sizeof(SHARE_XDF));
	else if(dfType == DFTYPE_DATA)
		memcpy(&m_xdfData, pXdfRec, sizeof(SHARE_XDF));
	else
		return FALSE;

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
//		BOOL bNoUI
//
//  说明：
//-------------------------------------------------------------------
BOOL
CTYCSP::Connect(BOOL bCheckCardValid)
{
	//检测卡的连接状态
	if(m_reader.CheckCardConnect())
		return TRUE;

	//卡片未连接(首次连接或卡被抽出)，在新的连接之前释放旧的连接所建立
	//的资源及初始化
	DestroyResourceAndInitData();

	//建立与卡片的连接
	if(m_reader.ConnectCard(bCheckCardValid)){
		CardType type = m_reader.GetCardType();
			m_cryptMode = HARDWARE;

		return TRUE;
	}
	else
		return FALSE;
}

//-------------------------------------------------------------------
//	功能：
//		复位卡片
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		BYTE* pbATR			ATR命令
//		DWORD* pdwATR		ATR的长度
//		ResetMode mode		复位模式
//
//  说明：
//-------------------------------------------------------------------
BOOL
CTYCSP::ResetCard(
	BYTE* pbATR,
	DWORD* pdwATR,
	ResetMode mode /*=WARM*/
)
{
	return m_reader.Reset(pbATR, pdwATR, mode);
}

//-------------------------------------------------------------------
//	功能：
//		断开与智能卡的连接
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
CTYCSP::Login(
	int nUserType,
	LPBYTE pPIN,
	DWORD dwPINLen,
	DWORD& dwRetryCount
	)
{
	if(m_reader.Login(nUserType, pPIN, dwPINLen, dwRetryCount)){
		m_nUserType = nUserType;
		return TRUE;
	}
	else
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
CTYCSP::Logout()
{
	if(m_reader.Logout()){
		m_nUserType = UT_PUBLIC;
		return TRUE;
	}
	else
		return FALSE;
}
	
//-------------------------------------------------------------------
//	功能：
//		更改PIN码
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		LPBYTE pOldPIN			旧PIN
//		DWORD dwOldPINLen		旧PIN的长度
//		LPBYTE pNewPIN			新PIN
//		DWORD dwNewPINLen		新PIN的长度
//
//  说明：
//		改变当前用户的PIN
//-------------------------------------------------------------------
BOOL 
CTYCSP::ChangePIN(
	LPBYTE pOldPIN,
	DWORD dwOldPINLen,
	LPBYTE pNewPIN,
	DWORD dwNewPINLen
	)
{
	//用户未登录
	if(m_nUserType == UT_PUBLIC)
		return FALSE;

	return m_reader.ChangePIN(m_nUserType, pOldPIN, dwOldPINLen, pNewPIN, dwNewPINLen);
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
CTYCSP::UnlockPIN(
	LPBYTE pUserDefaultPIN,
	DWORD dwUserDefaultPINLen
	)
{
	//当前用户身份必须为安全员
	if(m_nUserType != UT_SO)
		return FALSE;

	return m_reader.UnlockPIN(pUserDefaultPIN, dwUserDefaultPINLen);
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
//		BYTE flag
//		DWORD dwSize
//		BYTE path[2]
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::GetWorkableFile(
	BYTE flag,
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
//		产生随机数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		DWORD dwLen				随机数的长度
//		BYTE *pbBuffer			随机数
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::GenRandom(
	DWORD dwLen,
	BYTE *pbBuffer
	)
{
	if(pbBuffer == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if(GetCryptMode() == SOFTWARE){
		for(DWORD i = 0; i < dwLen; i++)
			pbBuffer[i] = g_rng.GetByte();
	}
	else{
		//每次产生随机数的个数
		BYTE bPer = 8;
		DWORD dwDataLen = (dwLen + (bPer - 1))/bPer*bPer;
		//创建随机数的存放空间
		BYTE* pData = new BYTE[dwDataLen];
		if(pData == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}

		//生成命令报文(无LC、DATA)
		BYTE cCommand[5];
		cCommand[0] = 0x00;			//CLA
		cCommand[1] = 0x84;			//INS
		cCommand[2] = 0x00;			//P1
		cCommand[3] = 0x00;			//P2
		cCommand[4] = bPer;			//LE

		//获取随机数
		DWORD dwRespLen;
		BOOL bRetVal;
		for(DWORD i = 0; i < dwDataLen/bPer; i++){
			bRetVal = SendCommand(cCommand, sizeof(cCommand), pData + i*bPer, &dwRespLen);
			if(bRetVal != TRUE){
				delete pData;
				SETLASTERROR(NTE_FAIL);
				return FALSE;
			}
		}

		//将随机数返回给用户
		memcpy(pbBuffer, pData, dwLen);
		//释放空间
		delete pData;
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		读取指定文件中的DER编码
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		BYTE cPath[2]
//		SHARE_XDF* pXdfRec
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
	BOOL bCheckCardValid = TRUE;
	if(!Connect(bCheckCardValid)){
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

	TCHAR szDefKCName[UNLEN + 1];
	TCHAR* szName = NULL;
	if(pszContainer != NULL && _tcslen(pszContainer) != 0)
		szName = pszContainer;
	else{
		//如果传入的名字为NULL或长度为0,则用缺省的名字(用户的登录名)
		if(!GetDefaultKeyContainerName(szDefKCName)){
			SETLASTERROR(NTE_FAIL);
			return FALSE;
		}
		szName = szDefKCName;
	}
	TRACE_LINE("\nKeyContainer的名字为:%s\n", szName);

	//读取Key Container
	if(!ReadKeyContainer()){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}

	//打开一个Key Container
	if(dwFlags == 0){
		TRACE_LINE("\n打开一个Key Container\n");

		//通过名字查找Key Container
		CCSPKeyContainer* pKeyContainer = GetKeyContainerByName(szName);
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
	//The application has no access to the private keys 
	//and the return pszContainer parameter must be set 
	//to NULL. This option is used with applications that 
	//do not use private keys.
	else if(dwFlags == CRYPT_VERIFYCONTEXT){
		TRACE_LINE("\n获取一个Key Container(CRYPT_VERIFYCONTEXT)\n");

		if(pszContainer != NULL)
			pszContainer[0] = '\0';

		//创建一个Key Container用于CRYPT_VERIFYCONTEXT
		CCSPKeyContainer* pVerifyKeyContainer = GetKeyContainerByName(
			VERIFY_KEY_CONTAINER_NAME
			);
		
		if(pVerifyKeyContainer == NULL){
			CreateKeyContainer(VERIFY_KEY_CONTAINER_NAME, FALSE, pVerifyKeyContainer, FALSE);
			if(pVerifyKeyContainer == NULL){
				SETLASTERROR(NTE_NO_MEMORY);
				return FALSE;
			}
		}

		//增加引用计数
		pVerifyKeyContainer->AddRef();
		*phProv = pVerifyKeyContainer->GetHandle();
	}
	//新增一个Key Container
	else if(dwFlags == CRYPT_NEWKEYSET){
		TRACE_LINE("\n新增一个Key Container\n");
  
		CCSPKeyContainer* pKeyContainer = GetKeyContainerByName(szName);
		if(pKeyContainer != NULL){
			SETLASTERROR(NTE_EXISTS);
			return FALSE;
		}
		CreateKeyContainer(szName, TRUE, pKeyContainer, TRUE);
		if(pKeyContainer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
		//增加引用计数
		pKeyContainer->AddRef();
		*phProv = pKeyContainer->GetHandle();
	}
	//删除一个Key Container
	else if(dwFlags == CRYPT_DELETEKEYSET){
		TRACE_LINE("\n删除一个Key Container\n");

		CCSPKeyContainer* pKeyContainer = GetKeyContainerByName(szName);
		if(pKeyContainer == NULL){
			SETLASTERROR(NTE_KEYSET_NOT_DEF);
			return FALSE;
		}

		//如果有受保护的密钥对，则须校验PIN
		if(pKeyContainer->HaveProtectedKeyPairs()){
			if(!IsLogin()){
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
	if(pKeyContainer != NULL){
		pKeyContainer->Release();
		return TRUE;
	}

	SETLASTERROR(NTE_BAD_UID);
	return FALSE;
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
	//参数检测
	if(pdwDataLen == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	CCSPKeyContainer* pkeyContainer = GetKeyContainerByHandle(hProv);
	if(pkeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
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
	if(dwParam == PP_CONTAINER /*|| dwParam == PP_UNIQUE_CONTAINER*/){
		TRACE_LINE("\n获取KeyContainer的名字\n");

		LPCTSTR szName = pkeyContainer->GetName();

		//include NULL-terminated
		dwBufferLen = lstrlen(szName) + 1;
		pbBuffer = new BYTE[dwBufferLen];
		if(pbBuffer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
		if(dwBufferLen == 1)
			pbBuffer[0] = 0;
		else
			memcpy(pbBuffer, (LPBYTE)szName, dwBufferLen);
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

		LPCTSTR szName = pIterKeyContainer->GetName();

		//include NULL-terminated
		dwBufferLen = lstrlen(szName) + 1;
		pbBuffer = new BYTE[dwBufferLen];
		if(pbBuffer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
		if(dwBufferLen == 1)
			pbBuffer[0] = 0;
		else
			memcpy(pbBuffer, (LPBYTE)szName, dwBufferLen);
		
		if(bQueryBufferLen)
			m_nEnumKeyContainerIndex--;
	}
	//The name of the CSP in the form of a NULL-terminated 
	//CHAR string. 
	else if(dwParam == PP_NAME){
		TRACE_LINE("\n获取CSP的名字\n");

		LPCTSTR szName = GetName();

		//include NULL-terminated
		dwBufferLen = lstrlen(szName) + 1;
		pbBuffer = new BYTE[dwBufferLen];
		if(pbBuffer == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
		if(dwBufferLen == 1)
			pbBuffer[0] = 0;
		else
			memcpy(pbBuffer, (LPBYTE)szName, dwBufferLen);
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
/*	
	else if(dwParam == PP_SIG_KEYSIZE_INC){
	}
	else if(dwParam == PP_KEYX_KEYSIZE_INC){
	}
*/
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
	//参数检测
	if(pbData == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	CCSPKeyContainer* pkeyContainer = GetKeyContainerByHandle(hProv);
	if(pkeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}

	if(dwParam == PP_KEYSET_SEC_DESCR){
		//忽略该参数
	}
	else{
		SETLASTERROR(NTE_BAD_TYPE);
		return FALSE;
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		获取用户文件
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		HCRYPTPROV *phProv		返回的文件句柄(删除时不用)
//		CHAR* szFileName		文件名
//		DWORD dwFileSize		文件尺寸(创建时使用)
//		DWORD dwFlags			操作标志位
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::AcquireUserFile(
	HCRYPTPROV *phProv,
	CHAR* szFileName,
	DWORD dwFileSize,
	DWORD dwFlags
	)
{
	//与卡连接
	BOOL bCheckCardValid = TRUE;
	if(!Connect(bCheckCardValid)){
		TRACE_LINE("\n与卡连接失败\n");
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}
	
	if(szFileName == NULL){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}
	TRACE_LINE("\nUserFile的名字为:%s\n", szFileName);

	LPCTSTR szName = szFileName;

	//读取File Index
	if(!ReadFileIndex()){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}

	WORD dwOp = LOWORD(dwFlags);
	WORD dwMode = HIWORD(dwFlags);

	//创建一个User File
	if(dwOp == USERFILE_NEW){
		TRACE_LINE("\n新建一个UserFile\n");

		CUserFile* pUserFile = GetUserFileByName(szName);
		if(pUserFile != NULL){
			SETLASTERROR(NTE_EXISTS);
			return FALSE;
		}

		pUserFile = new CUserFile(this);
		if(pUserFile == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
		
		int nIndexOnToken = m_arUserFiles.GetSize();
		if(pUserFile->CreateOnToken(nIndexOnToken, szName, dwFileSize, (dwMode & USERFILE_AUTH_READ), (dwMode & USERFILE_AUTH_WRITE))){
			pUserFile->Open();
			m_arUserFiles.Add(pUserFile);
			*phProv = pUserFile->GetHandle();
			return TRUE;
		}
		else{
			delete pUserFile;
			*phProv = NULL;
			
			SETLASTERROR(NTE_FAIL);
			return FALSE;
		}
	}
	//打开一个User File
	else if(dwOp == USERFILE_OPEN){
		TRACE_LINE("\n打开一个User File\n");

		CUserFile* pUserFile = GetUserFileByName(szName);
		if(pUserFile == NULL){
			SETLASTERROR(NTE_BAD_KEYSET);
			return FALSE;
		}

		pUserFile->Open();
		*phProv = pUserFile->GetHandle();
	}
	//删除一个User File
	else if(dwOp == USERFILE_DELETE){
		TRACE_LINE("\n删除一个UserFile\n");

		CUserFile* pUserFile = GetUserFileByName(szName);
		if(pUserFile == NULL){
			SETLASTERROR(NTE_KEYSET_NOT_DEF);
			return FALSE;
		}
		
		//删除
		DestroyUserFile(pUserFile, TRUE);
	}
	else{
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		关闭用户文件
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv	文件句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::ReleaseUserFile(
	HCRYPTPROV hProv
	)
{
	CUserFile* pUserFile = GetUserFileByHandle(hProv);
	if(pUserFile != NULL){
		pUserFile->Close();
		return TRUE;
	}

	SETLASTERROR(NTE_BAD_UID);
	return FALSE;
}

//-------------------------------------------------------------------
//	功能：
//		获取所有用户文件名的列表
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		CHAR* szFileNameList	所有用户文件名字的列表,以0分隔,双0结束
//		LPDWORD pcchSize		[IN]接收区大小/[OUT]实际大小				
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CTYCSP::GetUserFileNameList(
	CHAR* szFileNameList,
	LPDWORD pcchSize
	)
{
	//读取File Index
	if(!ReadFileIndex()){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}

	DWORD dwSize = 0;
	for(int i = 0; i < m_arUserFiles.GetSize(); i++){
		CUserFile* pFile = m_arUserFiles.GetAt(i);
		dwSize += (lstrlen(pFile->GetName()) + 1);
	}
	if(dwSize) dwSize++;

	if(szFileNameList == NULL){
		*pcchSize = dwSize;
		return TRUE;
	}
	else{
		if(*pcchSize < dwSize){
			*pcchSize = dwSize;
			SETLASTERROR(ERROR_MORE_DATA);
			return FALSE;
		}

		*pcchSize = dwSize;
		dwSize = 0;
		for(int i = 0; i < m_arUserFiles.GetSize(); i++){
			CUserFile* pFile = m_arUserFiles.GetAt(i);
			LPCTSTR szName = pFile->GetName();
			memcpy(szFileNameList + dwSize, szName, lstrlen(szName) + 1);
			dwSize += (lstrlen(szName) + 1);
		}
		szFileNameList[dwSize] = 0;
	}

	return TRUE;
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
CTYCSP::GetTokenInfo(
	LPTOKENINFO pTokenInfo,
	BOOL bReload
	)
{
	return m_reader.GetTokenInfo(pTokenInfo, bReload);
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
CTYCSP::SetTokenInfo(
	LPTOKENINFO pTokenInfo
	)
{
	return m_reader.SetTokenInfo(pTokenInfo);
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
CTYCSP::GetE2Size(
	DWORD& dwTotalSize,
	DWORD& dwTotalSize2,
	DWORD& dwUnusedSize
	)
{
	if(!Connect(FALSE))
		return FALSE;

	return m_reader.GetE2Size(dwTotalSize, dwTotalSize2, dwUnusedSize);
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
CTYCSP::GetCosVer(
	DWORD& dwVersion
	)
{
	if(!Connect(FALSE))
		return FALSE;

	return m_reader.GetCosVer(dwVersion);
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
CTYCSP::IsSSF33Support()
{
	if(!Connect(FALSE))
		return FALSE;

	return m_reader.IsSSF33Support();
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
CTYCSP::GetPinRetryInfo(
	int nUserType,
	int& nMaxRetry,
	int& nLeftRetry
	)
{
	return m_reader.GetPinRetryInfo(nUserType, nMaxRetry, nLeftRetry);
}

//-------------------------------------------------------------------
//	功能：
//		格式化
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		LPFORMATINFO pFormatInfo	格式化信息
//
//  说明：
//-------------------------------------------------------------------
BOOL CTYCSP::Format(LPFORMATINFO pFormatInfo)
{
	if(!Connect(FALSE))
		return FALSE;

	if(m_reader.FormatCard(pFormatInfo)){
		g_ModifyManager.AddModify((LPCSTR)m_reader.GetName());
		DisConnect();
		return Connect(TRUE);
	}
	else
		return FALSE;
}

//-------------------------------------------------------------------
//	功能：
//		擦除EEPROM
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
BOOL CTYCSP::EraseE2()
{
	if(!Connect(FALSE))
		return FALSE;

	return m_reader.EraseE2();
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
	Finalize();
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
	m_bFilterReader = FALSE;
	m_dwEnumReaderFlag = 0xFFFFFFFF;

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

		reg.Close();
	}

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
	ReleaseCSPs();
	
	g_TYKeyFuncHolder.Unload();
	g_SCardFuncHolder.Unload();

	return TRUE;
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
	CreateCSPs();
	return m_arCSPs.GetSize();
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
//		通过读卡器的名字获取CSP对象
//
//	返回：
//		CSP对象的指针
//
//  参数：
//		LPCTSTR lpszName	读卡器的名字
//
//  说明：
//-------------------------------------------------------------------
CTYCSP*
CTYCSPManager::GetCSPByReaderName(
	LPCTSTR lpszName
	)
{
	if(lpszName == NULL)
		return NULL;
	
	int nCount = m_arCSPs.GetSize();
	CTYCSP* pCSPObject = NULL;
	for(int i = 0; i < nCount; i++){
		pCSPObject = m_arCSPs.GetAt(i);
		if(lstrcmpi(pCSPObject->GetReaderName(), lpszName) == 0)
			return pCSPObject;
	}

	return NULL;
}

//-------------------------------------------------------------------
//	功能：
//		通过读卡器的索引获取CSP对象
//
//	返回：
//		CSP对象的指针
//
//  参数：
//		int nIndex			读卡器的索引
//
//  说明：
//-------------------------------------------------------------------
CTYCSP*
CTYCSPManager::GetCSPByReaderIndex(
	int nIndex
	)
{
	int nCount = m_arCSPs.GetSize();
	CTYCSP* pCSPObject = NULL;
	for(int i = 0; i < nCount; i++){
		pCSPObject = m_arCSPs.GetAt(i);
		if(pCSPObject->GetReaderIndex() == nIndex)
			return pCSPObject;
	}

	return NULL;
}

CTYCSP*
CTYCSPManager::GetCPSByRealIndex(
	int nIndex
	)
{
	int nCount = m_arCSPs.GetSize();
	CTYCSP* pCSPObject = NULL;
	for(int i = 0; i < nCount; i++){
		pCSPObject = m_arCSPs.GetAt(i);
		if(pCSPObject->GetRealIndex() == nIndex)
			return pCSPObject;
	}

	return NULL;
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
		CreateUSBPortCSPs();
	if(m_dwEnumReaderFlag & ENUM_SERIALPORT_READER)
		CreateCOMPortCSPs();
	if(m_dwEnumReaderFlag & ENUM_PCSC_READER)
		CreatePCSCCSPs();
}

//-------------------------------------------------------------------
//	功能：
//		建立PCSC读卡器的CSP对象
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
void CTYCSPManager::CreatePCSCCSPs()
{
	TRACE_FUNCTION("CreatePCSCCSPs");
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
	
	//查找读卡器列表
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

	//获取读卡器的数目和名称并构造CSP对象
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
	DWORD dwTYPCSCNum = 0;
	for(dwNumReaders = 0, szReaderName = mszReaderNames;
	   *szReaderName != _T('\0');
	   dwNumReaders++)
	{
	   if(m_bFilterReader && !IsContainSubString(szReaderName, "tianyu")){
			TRACE_LINE("Reader: %s is filtered!\n", szReaderName);
			szReaderName += lstrlen(szReaderName) + 1;
			continue;
	   }

	   TRACE_LINE("Tianyu PCSC Count = %d\n", dwTYPCSCNum);
	   
		//插入了新的Reader
	   if(GetCSPByReaderName(szReaderName) == NULL){
			//创建CSP对象
			CTYCSP* pCSPObject = new CTYCSP;
			if(pCSPObject == NULL)
				break;

			//设置CSP句柄
			pCSPObject->SetHandle(m_hNextCSPHandle++);
			//设置CSP对应的读卡器的名字
			pCSPObject->SetReaderName(szReaderName);
			//设置读卡器类型
			pCSPObject->SetReaderType(RT_PCSC);
			//设置读卡器索引
			pCSPObject->SetReaderIndex(((int)RT_PCSC)*1000 + dwTYPCSCNum);
			//初始化
			pCSPObject->Initialize();

			//加入链表
			m_arCSPs.Add(pCSPObject);
	   }
		szReaderName += lstrlen(szReaderName) + 1;
		dwTYPCSCNum++;
	}

	g_SCardFuncHolder.m_listFunc.pfnSCardFreeMemory(hSC, (LPVOID)mszReaderNames);
	g_SCardFuncHolder.m_listFunc.pfnSCardReleaseContext(hSC);
}

//-------------------------------------------------------------------
//	功能：
//		建立USB读卡器的CSP对象
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
void CTYCSPManager::CreateUSBPortCSPs()
{
	TRACE_FUNCTION("CreateUSBPortCSPs");
	
	//载入USB读卡器接口
	g_TYKeyFuncHolder.Load();
	if(g_TYKeyFuncHolder.m_listFunc.pfnTYKey_Change == NULL ||
		g_TYKeyFuncHolder.m_listFunc.pfnTYKey_Status == NULL)
	{
		return;
	}

	#define MAX_USBPORT	16

	//列举USB读卡器的状态
	UCHAR state[MAX_USBPORT];
	try{
		TRACE_LINE("pfnTYKey_Change\n");
		g_TYKeyFuncHolder.m_listFunc.pfnTYKey_Change();
		TRACE_LINE("pfnTYKey_Status\n");
		g_TYKeyFuncHolder.m_listFunc.pfnTYKey_Status(state);
	}
	catch(...){
	}

	//察看是否拨除了USB读卡器
	int pRemoveIndex[MAX_USBPORT];
	DWORD dwRemoveNum = 0;
	for(int i = 0; i < m_arCSPs.GetSize(); i++){
		CTYCSP* pCSPObject = m_arCSPs.GetAt(i);
		if(pCSPObject->GetReaderType() != RT_USBPORT)
			continue;
		
		//从USB读卡器索引中获取对应的USB口
		int usbPort = pCSPObject->GetReaderIndex() - ((int)RT_USBPORT)*1000; 

		//判断读卡器是否还存在
		if(state[usbPort] == 0){
			pCSPObject->DisConnect();
			pRemoveIndex[dwRemoveNum++] = i;
			delete pCSPObject;
	   }
	}
	for(DWORD dwI = 0; dwI < dwRemoveNum; dwI++)
		m_arCSPs.RemoveAt(pRemoveIndex[dwI] - dwI);

	//检查是否有其他程序对现有的象进行了修改
	g_ModifyManager.FixModifies(&m_arCSPs);

	//察看是否插入了新的USB读卡器
	for(i = 0; i < sizeof(state)/sizeof(UCHAR); i++){
		if(state[i] == 0)
			continue;

		//从USB口生成USB读卡器索引
		int rdIdx = ((int)RT_USBPORT)*1000 + i;

		//判断是否为新插入了的USB读卡器
		if(GetCSPByReaderIndex(rdIdx))
			continue;

		//创建CSP对象
		CTYCSP* pCSPObject = new CTYCSP;
		if(pCSPObject == NULL)
			break;

		//设置CSP句柄
		pCSPObject->SetHandle(m_hNextCSPHandle++);
		//设置读卡器类型
		pCSPObject->SetReaderType(RT_USBPORT);
		//设置读卡器的索引
		pCSPObject->SetReaderIndex(rdIdx);
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
void CTYCSPManager::CreateCOMPortCSPs()
{
	TRACE_FUNCTION("CreateCOMPortCSPs");
	//载入串口读卡器接口
	g_TYReaderFuncHolder.Load();
	if(g_TYReaderFuncHolder.m_listFunc.pfnTY_Status == NULL)
		return;

	//列举串口读卡器状态
	BYTE state[MAX_COMPORT_NUM] = {0};
	g_TYReaderFuncHolder.m_listFunc.pfnTY_Status(state);
	
	//察看是否拨除了串口读卡器
	int pRemoveIndex[MAX_COMPORT_NUM];
	DWORD dwRemoveNum = 0;
	for(int i = 0; i < m_arCSPs.GetSize(); i++){
		CTYCSP* pCSPObject = m_arCSPs.GetAt(i);
		if(pCSPObject->GetReaderType() != RT_COMPORT)
			continue;

		//从串口读卡器索引中获取对应的串口
		int comPort = pCSPObject->GetReaderIndex() - ((int)RT_COMPORT)*1000; 

		//判定串口读卡器是否还存在
		if(state[comPort] == 0){
			pCSPObject->DisConnect();
			pRemoveIndex[dwRemoveNum++] = i;
			delete pCSPObject;
	   }
	}
	for(DWORD dwI = 0; dwI < dwRemoveNum; dwI++)
		m_arCSPs.RemoveAt(pRemoveIndex[dwI] - dwI);

	//察看是否插入了新的串口读卡器
	for(i = 0; i < sizeof(state); i++){
		if(state[i] == 0)
			continue;

		//从串口生成串口读卡器索引
		int rdIdx = ((int)RT_COMPORT)*1000 + i;

		//判断是否为新插入了的串口读卡器
		if(GetCSPByReaderIndex(rdIdx))
			continue;

		//创建CSP对象
		CTYCSP* pCSPObject = new CTYCSP;
		if(pCSPObject == NULL)
			break;

		//设置CSP句柄
		pCSPObject->SetHandle(m_hNextCSPHandle++);
		//设置读卡器类型
		pCSPObject->SetReaderType(RT_COMPORT);
		//设置读卡器的索引
		pCSPObject->SetReaderIndex(rdIdx);
		//初始化
		pCSPObject->Initialize();

		//加入链表
		m_arCSPs.Add(pCSPObject);
	}
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

BOOL CTYCSPManager::Connect(
	HCRYPTPROV* phProv, 
	DWORD dwIndex
	)
{
	if(phProv == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	CreateCSPs();

	int nCount = m_arCSPs.GetSize();
	if(dwIndex >= (DWORD)nCount){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}

	CTYCSP* pCSPObject = NULL;
	if(g_bUseReaderIndex){
		pCSPObject = GetCPSByRealIndex(dwIndex);
	}
	else{
		pCSPObject = GetCSPAt(dwIndex);
	}
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_FAIL);
		return FALSE;

	}

	if(pCSPObject->Connect(TRUE)){
		if(pCSPObject->AcquireContext(phProv, NULL, CRYPT_VERIFYCONTEXT, NULL))
			return TRUE;
	}

	if(!pCSPObject->Connect(FALSE))
		return FALSE;
	*phProv = MAKE_HCRYPTPROV(pCSPObject->GetHandle(), 0);		


	return TRUE;
}

BOOL CTYCSPManager::Connect(
	HCRYPTPROV* phProv, 
	CHAR* szReaderName
	)
{
	if(phProv == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	CreateCSPs();

	CTYCSP* pCSPObject = GetCSPByReaderName(szReaderName);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_FAIL);
		return FALSE;

	}

	if(pCSPObject->Connect(TRUE)){
		if(pCSPObject->AcquireContext(phProv, NULL, CRYPT_VERIFYCONTEXT, NULL))
			return TRUE;
	}

	if(!pCSPObject->Connect(FALSE))
		return FALSE;
	*phProv = MAKE_HCRYPTPROV(pCSPObject->GetHandle(), 0);		

	return TRUE;
}

BOOL 
CTYCSPManager::AcquireContext(
	HCRYPTPROV *phProv,
	CHAR *pszContainer,
	DWORD dwFlags,
	DWORD dwIndex
	)
{
	CreateCSPs();

	int nCount = m_arCSPs.GetSize();
	if(dwIndex >= (DWORD)nCount){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}

	CTYCSP* pCSPObject = NULL;
	if(g_bUseReaderIndex){
		pCSPObject = GetCPSByRealIndex(dwIndex);
	}
	else{
		pCSPObject = GetCSPAt(dwIndex);
	}
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_FAIL);
		return FALSE;

	}

	return pCSPObject->AcquireContext(phProv, pszContainer, dwFlags, NULL);
}

BOOL 
CTYCSPManager::AcquireContext(
	HCRYPTPROV *phProv,
	CHAR *pszContainer,
	DWORD dwFlags,
	CHAR* szReaderName
	)
{
	CreateCSPs();

	CTYCSP* pCSPObject = GetCSPByReaderName(szReaderName);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_FAIL);
		return FALSE;

	}

	return pCSPObject->AcquireContext(phProv, pszContainer, dwFlags, NULL);
}


BOOL 
CTYCSPManager::AcquireUserFile(
	HCRYPTPROV *phProv,
	CHAR* szFileName,
	DWORD dwFileSize,
	DWORD dwFlags,
	DWORD dwIndex
	)
{
	CreateCSPs();

	int nCount = m_arCSPs.GetSize();
	if(dwIndex >= (DWORD)nCount){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}

	CTYCSP* pCSPObject = NULL;
	if(g_bUseReaderIndex)
		pCSPObject = GetCPSByRealIndex(dwIndex);
	else
		pCSPObject = GetCSPAt(dwIndex);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_FAIL);
		return FALSE;

	}

	return pCSPObject->AcquireUserFile(phProv, szFileName, dwFileSize, dwFlags);
}

BOOL 
CTYCSPManager::AcquireUserFile(
	HCRYPTPROV *phProv,
	CHAR* szFileName,
	DWORD dwFileSize,
	DWORD dwFlags,
	CHAR* szReaderName
	)
{
	CreateCSPs();

	CTYCSP* pCSPObject = GetCSPByReaderName(szReaderName);
	if(pCSPObject == NULL){
		SETLASTERROR(NTE_FAIL);
		return FALSE;

	}

	return pCSPObject->AcquireUserFile(phProv, szFileName, dwFileSize, dwFlags);
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
