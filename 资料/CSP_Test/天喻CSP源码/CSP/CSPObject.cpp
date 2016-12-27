//-------------------------------------------------------------------
//	���ļ�Ϊ TY Cryptographic Service Provider ����ɲ���
//
//
//	��Ȩ���� ������Ϣ��ҵ���޹�˾ (c) 1996 - 2005 ����һ��Ȩ��
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

//��֧�ֿ�Ƭ������
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
//	���ܣ�
//		��ȡָ���㷨����Ϣ
//
//	���أ�
//		TRUE:�ɹ�		FALSE:��֧�ָ��㷨
//
//  ������
//		PROV_ENUMALGS_EX& info	�㷨��Ϣ
//
//  ˵����
//-------------------------------------------------------------------
BOOL GetAlgInfo(PROV_ENUMALGS_EX& info)
{

	CRegKey reg;
	LONG lResult = reg.Open(HKEY_LOCAL_MACHINE, 
		"SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Tianyu Cryptographic Service Provider"
		);
	if(lResult == ERROR_SUCCESS){
		DWORD dwValue;

		//sf33�㷨ID
		lResult = reg.QueryValue(dwValue, "SSF33_ALG");
		if(lResult == ERROR_SUCCESS)
		{
				g_dwSSF33Algid = dwValue;
//#ifdef CALG_SSF33
//#undef CALG_SSF33
//#define CALG_SSF33 g_dwSSF33Algid
//#endif		
		}

		//scb2�㷨ID
		lResult = reg.QueryValue(dwValue, "SCB2_ALG");
		if(lResult == ERROR_SUCCESS)
		{
				g_dwSCB2Algid = dwValue;
//#ifdef CALG_SCB2
//#undef CALG_SCB2
//#define CALG_SCB2 g_dwSCB2Algid
//#endif
		}

		//ECC Key Exchange�㷨ID
		lResult = reg.QueryValue(dwValue, "ECC_KEYX_ALG");
		if(lResult == ERROR_SUCCESS)
		{
				g_dwEccKeyxAlgid = dwValue;
//#ifdef CALG_ECC_KEYX
//#undef CALG_ECC_KEYX
//#define CALG_ECC_KEYX g_dwEccKeyxAlgid
//#endif
		}

		//ECC Sign�㷨ID
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
//	���ܣ�
//		�ж��Ƿ�Ϊ֧�ֵ�HASH���㷨��ʶ
//
//	���أ�
//		TRUE:��		FALSE:����
//
//  ������
//		ALG_ID algId	�㷨��ʶ
//
//  ˵����
//-------------------------------------------------------------------
BOOL IsSupportHashAlgId(ALG_ID algId)
{
	return (algId == CALG_MD5 || algId == CALG_SHA || algId == CALG_SSL3_SHAMD5);
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ж��Ƿ�Ϊ֧�ֵ���Կ�Ե��㷨��ʶ
//
//	���أ�
//		TRUE:��		FALSE:����
//
//  ������
//		ALG_ID algId	�㷨��ʶ
//
//  ˵����
//-------------------------------------------------------------------
BOOL IsSupportKeyPairAlgId(ALG_ID algId)
{
	return (algId == CALG_RSA_SIGN || algId == CALG_RSA_KEYX || algId == g_dwEccSignAlgid || algId == g_dwEccKeyxAlgid);
	//return (algId == CALG_RSA_SIGN || algId == CALG_RSA_KEYX || algId == CALG_ECC_SIGN || algId ==CALG_ECC_KEYX);
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ж��Ƿ�Ϊ֧�ֵĶԳ���Կ��ķ���ʶ
//
//	���أ�
//		TRUE:��		FALSE:����
//
//  ������
//		ALG_ID algId	�㷨��ʶ
//
//  ˵����
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

//��һ��GUID��Ϊ��֤Key Container������
#define VERIFY_KEY_CONTAINER_NAME _T("4BACC318-2FA9-46C9-B355-22765E7B1AD5")
//��һ��GUID��Ϊһ����û���û��˺Ż����ϵ�ȱʡKey Container������
#define DEFAULT_KEY_CONTAINER_NAME _T("02169438-4CB4-4C90-B74F-943FF7CF716B")

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
CTYCSP::CTYCSP(LPCTSTR lpszName /*=TYCSP_NAME*/)
{
	//CSP������
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

	//��ʼ������
	DestroyResourceAndInitData();
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
CTYCSP::~CTYCSP()
{
	DestroyResourceAndInitData();
}

//-------------------------------------------------------------------
//	���ܣ�
//		������Դ����ʼ������
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
void
CTYCSP::DestroyResourceAndInitData()
{
	//�ͷ�KeyContainer�б�
	int nCount = GetKeyContainerCount();
	for(int i = 0; i < nCount; i++){
		CCSPKeyContainer* pKeyContainer = m_arKeyContainers.GetAt(i);
		ASSERT(pKeyContainer != NULL);
		delete pKeyContainer;
	}
	m_arKeyContainers.RemoveAll();

	//���ݳ�ʼ��
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
//	���ܣ�
//		CSP��ʼ��
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
CTYCSP::Initialize()
{
	TRACE_FUNCTION("CTYCSP::Initialize");
	TRACE_LINE("\n\nCSP��� = %d\n", GetHandle());
	TRACE_LINE("��д�������� = %s\n\n", GetReaderName());

	//������֧�ֵ��㷨��ʶ�б�
	int nSize = sizeof(g_cSupportAlgInfo)/sizeof(PROV_ENUMALGS_EX);
	for(int i = 0; i < nSize; i++)
		m_arAlgIds.Add(g_cSupportAlgInfo[i].aiAlgid);

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ͷ�CSP����Դ
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		BOOL bWriteCard		�Ƿ������е���Ƭ
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CTYCSP::Finalize(BOOL bWriteCard)
{
	TRACE_FUNCTION("CTYCSP::Finalize");
	TRACE_LINE("\n\nCSP��� = %d\n\n", GetHandle());
	
	if(bWriteCard){
		//�����е���Ƭ
		if(m_xdfPrk.bHasFragment){
			//����XDF�ļ��е���Ƭ
			RemoveXdfFragment(&m_xdfPrk);

			//д�뿨��
			FILEHANDLE hFile;
			if(OpenFile(g_cPathTable.prkdfPath, &hFile, NULL)){
				WriteFile(hFile, m_xdfPrk.cContent, m_xdfPrk.ulDataLen + 2, 0);
				CloseFile(hFile);
			}
		}
	}

	//������Դ����ʼ������
	DestroyResourceAndInitData();

	//�Ͽ������ܿ�������
	m_reader.DisconnectCard();

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ӿ��ж���Key Container
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
CTYCSP::ReadKeyContainer()
{
	//�ж��Ƿ��Ѷ�
	if(m_bReadedKeyContainer)
		return TRUE;

	//��������Key Container��DER����
	CDERTool tool;
	if(!ReadObjectDERs(g_cPathTable.prkdfPath, &m_xdfPrk, tool))
		return FALSE;
	
	if(m_xdfPrk.bHasFragment){
		//�����Ƭ
		RemoveXdfFragment(&m_xdfPrk);
		FILEHANDLE hFile;
		if( OpenFile(g_cPathTable.prkdfPath, &hFile)){
			WriteFile(hFile, m_xdfPrk.cContent, m_xdfPrk.ulDataLen + 2, 0);
			CloseFile(hFile);
		}
	}
	
	//����Key Container����
	BYTE* pDERStr = NULL;
	ULONG ulLength = 0;
	for(int i = 0; i < tool.GetCount(); i++){
		if(tool.GetAt(i, pDERStr, ulLength) && pDERStr != NULL){
			//�����ȡKeyContainer������
			ULONG ulTag = ::GetDERTag(pDERStr, ulLength);
			if(ulTag != 0x30) continue;

			ULONG ulTagLen, ulLenLen;
			::GetDERLen(pDERStr, ulLength, ulTagLen, ulLenLen);
			pDERStr += (ulTagLen + ulLenLen);
			ulLength -= (ulTagLen + ulLenLen);
			
			ulTag = ::GetDERTag(pDERStr, ulLength);
			ULONG ulValueLen = ::GetDERLen(pDERStr, ulLength, ulTagLen, ulLenLen);
			CHAR* pszName = (CHAR* )(pDERStr + ulTagLen + ulLenLen);

			//����Key Container�Ķ���
			CCSPKeyContainer* pKeyContainer = NULL;
			CreateKeyContainer(pszName, TRUE, pKeyContainer, FALSE);

			//����Key Container�е���Կ��
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

	//���ö�ȡ���ΪTRUE
	m_bReadedKeyContainer = TRUE;

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		����һ��Key Container���󣬲��������������
//
//	���أ�
//		��
//
//  ������
//		LPCTSTR lpszName						����
//		BOOL bInitOpen							�������Ƿ��
//		CCSPKeyContainer*& pCreatedKeyContainer	������Key Container����
//		BOOL bCreateOnToken						�Ƿ��ڿ��д���
//
//  ˵����
//-------------------------------------------------------------------
void
CTYCSP::CreateKeyContainer(
	LPCTSTR lpszName,
	BOOL bInitOpen,
	CCSPKeyContainer*& pCreatedKeyContainer,
	BOOL bCreateOnToken
	)
{
	//����
	pCreatedKeyContainer = new CCSPKeyContainer(this, lpszName, bInitOpen);
	if(pCreatedKeyContainer == NULL)
		return;

	//�ڿ��д���
	if(bCreateOnToken){
		if(!pCreatedKeyContainer->CreateOnToken(GetKeyContainerCreateIndex()))
		{
			delete pCreatedKeyContainer;
			pCreatedKeyContainer = NULL;
			
			return;
		}
		AddModify();
	}

	//���뵽������
	m_arKeyContainers.Add(pCreatedKeyContainer);
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡKeyContainer�Ĵ�������
//
//	���أ�
//		��������
//
//  ������
//		��
//
//  ˵����
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
//	���ܣ�
//		����ָ����Key Container���󣬲������������ȥ��
//
//	���أ�
//		��
//
//  ������
//		CCSPKeyContainer* pDestroyKeyContainer	�����ٵ�Key Container����
//		BOOL bDestroyOnToken					�Ƿ�ӿ�������
//
//  ˵����
//-------------------------------------------------------------------
void
CTYCSP::DestroyKeyContainer(
	CCSPKeyContainer* pDestroyKeyContainer,
	BOOL bDestroyOnToken /*=FALSE*/
	)
{
	if(pDestroyKeyContainer == NULL)
		return;

	//����
	int nCount = GetKeyContainerCount();

	//�Ȳ������������е�����
	int nIdx = -1;
	for(int i = 0; i < nCount; i++){
		CCSPKeyContainer* pKeyContainer = m_arKeyContainers.GetAt(i);
		ASSERT(pKeyContainer != NULL);
		if(pDestroyKeyContainer == pKeyContainer){
			nIdx = i;
			break;
		}
	}

	//û���ҵ�
	if(nIdx == -1)
		return;

	if(pDestroyKeyContainer->IsToken()){
		if(bDestroyOnToken){
			pDestroyKeyContainer->DestroyOnToken();
			//�����������1
			for(i = nIdx + 1; i < nCount; i++){
				CCSPKeyContainer* pKeyContainer = m_arKeyContainers.GetAt(i);
				pKeyContainer->SetTokenIndex(pKeyContainer->GetTokenIndex() - 1);
			}
		}
		AddModify();
	}


	delete pDestroyKeyContainer;
	//��������ɾ��
	m_arKeyContainers.RemoveAt(nIdx);
}

//-------------------------------------------------------------------
//	���ܣ�
//		ͨ�������ȡһ��Key Container����
//
//	���أ�
//		Key Container����ָ��
//
//  ������
//		HCRYPTPROV hKeyContainer	���	
//
//  ˵����
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
		//�ж��Ƿ����ѱ��ͷŵ�Key Container
		if(pKeyContainer->IsReleased())
			continue;
		if(pKeyContainer->GetHandle() == hKeyContainer)
			return pKeyContainer;
	}

	return NULL;
}

//-------------------------------------------------------------------
//	���ܣ�
//		ͨ�����ֻ�ȡһ��Key Container����
//
//	���أ�
//		Key Container����ָ��
//
//  ������
//		LPCTSTR lpszName	����	
//
//  ˵����
//-------------------------------------------------------------------
CCSPKeyContainer* 
CTYCSP::GetKeyContainerByName(
	LPCTSTR lpszName
	)
{
	//�ȴӿ��ж�ȡKey Container������Ѷ��������ٶ�
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
//	���ܣ�
//		��ȡȱʡ��Key Container����
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		CString& szDefaultName	����	
//
//  ˵����
//		�õ�ǰ��¼���û�����Ϊ��Ҫ��ȡ��Key Container���������
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
		TRACE_LINE("���û���¼����Ϊȱʡ��Կ������\n");
	}
	else{
		szDefaultName = DEFAULT_KEY_CONTAINER_NAME;
		TRACE_LINE("��Ԥ���GUID��Ϊȱʡ��Կ������\n");
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡXDF
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		XDF_TYPE dfType				XDF������(����)
//		SHARE_XDF* pXdfRec			ָ��ODF��¼��ָ��
//
//  ˵����
//		XDFΪ����Key Container ����ODF�ļ���ӳ��
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
//	���ܣ�
//		����XDF
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		XDF_TYPE dfType				XDF������(����)
//		SHARE_XDF* pXdfRec			ָ��ODF��¼��ָ��
//
//  ˵����
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
//	���ܣ�
//		ɾ��XDF�е���Ƭ
//
//	���أ�
//		��
//
//  ������
//		SHARE_XDF* pXdfRec	ָ��ODF��¼��ָ��
//
//  ˵����
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

	//�ȿ���һ��ʱ����,�洢��Ч����
	BYTE* pTempMem = new BYTE[pXdfRec->ulTotalLen];
	if(pTempMem == NULL)
		return;

	//���ݳ�������Ϊ0
	pXdfRec->ulDataLen = 0;

	//��XDF�е���Ч���������洢����ʱ������
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

	//���XDF��¼
	memset(pXdfRec->cContent, 0, pXdfRec->ulTotalLen);
	//����ʱ�����д�ŵ��������ݿ���XDF��
	memcpy(pXdfRec->cContent, pTempMem, pXdfRec->ulDataLen);

	pXdfRec->bHasFragment = FALSE;

	//�ͷ���ʱ����ռ�
	delete pTempMem;
}

/////////////////////////////////////////////////////////////////////////
/*
���ܣ�	��������ļ��������ҳ������뱾�����ƫ�Ƶ�ַ
���룺	pFileData����������ļ�����
		ulFileDataLen����������ļ����ݵĳ���
		ulOffset----�����������ʼλ�õ�ƫ��
		ulLen----�����¼�ĳ���

�����	
˵����
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

		//�������tag�Ǳ�ʶΪ��ɾ���˵Ķ��󣬲�������
		if (GetDERTag(pFileData + ulOffset,ulDERTotalStrLen) != DESTROIED_TAG)
			i++;

		ulOffset += ulDERTotalStrLen;
		if (ulOffset >= pXdfRec->ulTotalLen)
		{
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}
	}

	//�������������ֱ��û��������ɾ�����
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
CTYCSP::BeginTransaction()
{
	return m_reader.BeginTransaction();
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
CTYCSP::EndTransaction(
	DWORD dwDisposition /*=SCARD_LEAVE_CARD*/
	)
{
	return m_reader.EndTransaction(dwDisposition);
}

//-------------------------------------------------------------------
//	���ܣ�
//		�򿨷�������
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
//	���ܣ�
//		�뿨����
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
CTYCSP::Connect()
{
	//
	//��⿨������״̬
	//
	if(m_reader.CheckCardConnect())
		return TRUE;

	//
	//��Ƭδ����(�״����ӻ򿨱����)�����µ�����֮ǰ�ͷžɵ�����������
	//����Դ����ʼ��
	//
	DestroyResourceAndInitData();

	//
	//�����뿨Ƭ������
	//
	BOOL bRetVal = m_reader.ConnectCard();
	if(bRetVal){
		CardType type = m_reader.GetCardType();
		m_cryptMode = HARDWARE;
	}

	return bRetVal;
}


//-------------------------------------------------------------------
//	���ܣ�
//		�Ͽ�����������
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
CTYCSP::DisConnect()
{
	return m_reader.DisconnectCard();
}

//-------------------------------------------------------------------
//	���ܣ�
//		�û���¼
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		BOOL bForce	�Ƿ�ǿ��ִ��
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CTYCSP::Login(BOOL bForce)
{
	//�ж��Ƿ�ΪSSO��¼
	if(g_theTYCSPManager.IsSSO()){
		//��ȡ���һ��У��PIN��ʱ��
		CString strReaderName = GetReaderName();
		int nLoginTime = GetPrivateProfileInt(
			_T("TYCSP Login Time"), strReaderName, -1, m_strLogFileName
			);
		
		//���Ϊ������0����Ҫ����У��PIN
		if(nLoginTime <= 0)
			m_bLogin = FALSE;
		
		//����Ѵ��ڵ�¼״̬�ҷ�ǿ��
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
		//����SSO,��¼���ε�¼ʱ��
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
//	���ܣ�
//		У���û�PIN��
//
//	���أ�
//		TRUE:�ɹ�		FALSE��ʧ��
//
//  ������
//		BYTE* pPassword		PIN��
//		DWORD dwLen			PIN��ĳ���
//		int& nRetryCount	���Դ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CTYCSP::VerifyPin(BYTE* pPassword, DWORD dwLen, int& nRetryCount)
{
	BOOL bRetVal = m_reader.Login(pPassword, dwLen, (DWORD&)nRetryCount);
	if(!m_bCalledLogin) m_bCalledLogin = bRetVal;
	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		���ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		BYTE path[2]			
//		FILEHANDLE* phFile
//		LPDWORD pdwFileSize
//
//  ˵����
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
//	���ܣ�
//		��ȡ�ļ�����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		FILEHANDLE hFile
//		DWORD dwReadLen
//		LPBYTE pReadBuffer
//		LPDWORD pdwRealReadLen
//		DWORD dwOffset
//
//  ˵����
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
//	���ܣ�
//		д���ݵ��ļ���
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		FILEHANDLE hFile
//		LPBYTE pWriteBuffer
//		DWORD dwWriteBufferLen
//		DWORD dwOffset
//
//  ˵����
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
//	���ܣ�
//		�ر��ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		FILEHANDLE hFile
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CTYCSP::CloseFile(
	FILEHANDLE hFile
	)
{
	return m_reader.CloseFile(hFile);
}

//-------------------------------------------------------------------
//	���ܣ�
//		ɾ���ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		BYTE path[2]
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CTYCSP::DeleteFile(
	BYTE path[2]
	)
{
	return m_reader.DeleteFile(path);
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ���õ��ļ���ʶ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		WORD flag
//		DWORD dwSize
//		BYTE path[2]
//
//  ˵����
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
//	���ܣ�
//		�����ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		BYTE path[2]
//		DWORD dwSize
//		FILEHANDLE* phFile
//		BYTE type
//		BYTE readAuth
//		BYTE writeAuth
//
//  ˵����
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
//	���ܣ�
//		��ȡָ���ļ��е�DER����
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		BYTE cPath[2],
//		SHARE_XDF* pXdfRec,
//		CDERTool& tool
//
//  ˵����
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

		//���ÿ�
		memset(pXdfRec->cContent, 0, dwFileSize);

		//����ODF�е�����
		BOOL bRetVal = ReadODF(hFile, pXdfRec->cContent, dwFileSize);

		//�ر��ļ�
		CloseFile(hFile);

		EndTransaction();

		if(bRetVal != TRUE)
			return FALSE;
	}

	//�������������DER
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
//	���ܣ�
//		��ȡ��ǰѡ�е�ODF�м�¼
//
//	���أ�
//		CK_RV�����PKCS#11
//
//  ������
//		BYTE* pBuffer			���������� 
//		DWORD dwBufferLen		���ݿռ�Ĵ�С
//
//  ˵����
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
	DWORD dwReadLen = SIZE_PER_READ;		//��ȡ���ݵĳ���
	DWORD dwReadOffset = 0;					//��ȡ���ݵ�ƫ����
	DWORD dwDEROffset = 0;					//DER����ƫ����
	BOOL bNeedRead = TRUE;					//��Ҫ����־
	BOOL bNeedDER = TRUE;					//��Ҫ�����־
	BYTE* pDERStr = NULL;
	DWORD dwDERLen = 0;

	while(dwReadOffset < dwBufferLen){
		//��Ҫ��
		if(bNeedRead){
			if((dwReadOffset + dwReadLen) > dwBufferLen)
				dwReadLen = (dwBufferLen - dwReadOffset);
			DWORD dwRetReadSize;
			bRetVal = ReadFile(hFile, dwReadLen, pBuffer + dwReadOffset, &dwRetReadSize, dwReadOffset);
			if(bRetVal != TRUE)
				return bRetVal;
		}
		//��Ҫ����
		if(bNeedDER){
			//ʣ��DER����ĳ���
			DWORD dwLeftLen = dwReadLen - dwDEROffset;
			//���С��2���
			if(dwLeftLen < 2){
				bNeedDER = TRUE;
				bNeedRead = TRUE;
				//��ƫ��
				dwReadOffset += (dwReadLen - dwLeftLen);
				//����ƫ��
				dwDEROffset = 0;
				//���ȡ�ĳ���
				dwReadLen = (SIZE_PER_READ < (dwBufferLen - dwReadOffset)) ? SIZE_PER_READ : (dwBufferLen - dwReadOffset);

				continue;
			}

			//��ȡDER������׵�ַ
			pDERStr = pBuffer + dwReadOffset+ dwDEROffset;

			//��ǰһ��DER����ĳ���
			dwDERLen = GetDERTotalStrLen(pDERStr, dwLeftLen);
			//�����Ѿ�û�ж�����
			if(::GetDERTag(pDERStr, dwDERLen) == 0)
				break;

			//��ǰһ��DER����ĳ���С��ʣ��DER����ĳ���
			if(dwDERLen < dwLeftLen){
				//ֻ���벻��
				bNeedDER = TRUE;
				bNeedRead = FALSE;
				//����ƫ��
				dwDEROffset += dwDERLen;
			}
			//��ǰһ��DER����ĳ��ȴ���ʣ��DER����ĳ���
			else if(dwDERLen > dwLeftLen){
				//ֻ��������
				bNeedDER = FALSE;
				bNeedRead = TRUE;
				//��ƫ��
				dwReadOffset += dwReadLen;
				//���ȡ�ĳ���
				dwReadLen = dwDEROffset + dwDERLen - dwReadLen;
			}
			else{
				//���ҽ���
				bNeedDER = TRUE;
				bNeedRead = TRUE;
				//��ƫ��
				dwReadOffset += dwReadLen;
				//����ƫ��
				dwDEROffset = 0;
				//���ȡ�ĳ���
				dwReadLen = (SIZE_PER_READ < (dwBufferLen - dwReadOffset)) ? SIZE_PER_READ : (dwBufferLen - dwReadOffset);
			}
		}
		else{
			//���ҽ���
			bNeedDER = TRUE;
			bNeedRead = TRUE;
			//��ƫ��
			dwReadOffset += dwReadLen;
			//����ƫ��
			dwDEROffset = 0;
			//���ȡ�ĳ���
			dwReadLen = (SIZE_PER_READ < (dwBufferLen - dwReadOffset)) ? SIZE_PER_READ : (dwBufferLen - dwReadOffset);
		}
	}

	return TRUE;
}

 

/////////////////////////////////////////////////////////////////////
// CryptSPI Functions
void CTYCSP::AddModify()
{
	//������Ƭ
	RemoveXdfFragment(&m_xdfPrk);
	//д�뿨��
	FILEHANDLE hFile;
	if(OpenFile(g_cPathTable.prkdfPath, &hFile, NULL)){
		WriteFile(hFile, m_xdfPrk.cContent, m_xdfPrk.ulDataLen + 2, 0);
		CloseFile(hFile);
	}
	
	g_ModifyManager.AddModify((LPCSTR)m_reader.GetName());
}

//-------------------------------------------------------------------
//	���ܣ�
//		Acquires a handle to the key container specified by the 
//	pszContainer parameter.
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV *phProv
//		CHAR *pszContainer
//		DWORD dwFlags
//		PVTableProvStruc pVTable
//  
//  ˵����
//-------------------------------------------------------------------
BOOL 
CTYCSP::AcquireContext(
	HCRYPTPROV *phProv,
	CHAR *pszContainer,
	DWORD dwFlags,
	PVTableProvStruc pVTable
	)
{ 
	TRACE_LINE("\nCSP��� = %d\n", GetHandle());

	//�뿨����
	if(!Connect()){
		TRACE_LINE("\n�뿨����ʧ��\n");
		SETLASTERROR(SCARD_E_NO_SMARTCARD);
		return FALSE;
	}

	//�������
	if(phProv == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//�ȸ����ֵ
	*phProv = NULL;

	//����и�����(DLL),������֤ǩ��

	CString szName;
	if(pszContainer != NULL)
		szName = pszContainer;

	//������������ΪNULL�򳤶�Ϊ0,����ȱʡ������(�û��ĵ�¼��)
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
	TRACE_LINE("\nKeyContainer������Ϊ:%s ;dwFlags = %08x\n", szContainerName, dwFlags);

	//��ȡKey Container
	if(!ReadKeyContainer()){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}

	//��һ��Key Container
	if((dwFlags == 0) /*|| (dwFlags & CRYPT_SILENT)*/){
		TRACE_LINE("\n��һ��Key Container\n");

		//ͨ�����ֲ���Key Container
		CCSPKeyContainer* pKeyContainer = GetKeyContainerByName(szContainerName);
		if(pKeyContainer == NULL){
			SETLASTERROR(NTE_BAD_KEYSET);
			return FALSE;
		}
		//�������ü���
		pKeyContainer->AddRef();
		//��Key Container
		pKeyContainer->Open();
		//��ȡ���
		*phProv = pKeyContainer->GetHandle();
	}
	else if(dwFlags & CRYPT_SILENT){
		TRACE_LINE("\n�԰����ķ�ʽ��һ��Key Container\n");

		CCSPKeyContainer* pKeyContainer = NULL;
		if(bUseDefault){
			//��ȡ��һ����ΪVERIFY_CONTEXT����Կ����
			for(int i  = 0; i < m_arKeyContainers.GetSize(); i++){
				if(m_arKeyContainers.GetAt(i)->GetName().Compare(VERIFY_KEY_CONTAINER_NAME)){
					pKeyContainer = m_arKeyContainers.GetAt(i);
					break;
				}
			}
		}
		else{
			//ͨ�����ֲ�����Կ����
			pKeyContainer = GetKeyContainerByName(szContainerName);
		}

		if(pKeyContainer == NULL){
			//�������е��,��ͨ�����ܿ�ע��վ����֤����Ҫ������
			if(bUseDefault)
				CreateKeyContainer(szContainerName, FALSE, pKeyContainer, FALSE);
		}
		if(pKeyContainer == NULL){
			SETLASTERROR(NTE_BAD_KEYSET);
			return FALSE;
		}

		//�������ü���
		pKeyContainer->AddRef();
		//��Key Container
		pKeyContainer->Open();
		//��ȡ���
		*phProv = pKeyContainer->GetHandle();

		m_bSilent = TRUE;
	}
	//The application has no access to the private keys 
	//and the return pszContainer parameter must be set 
	//to NULL. This option is used with applications that 
	//do not use private keys.
	else if(dwFlags & CRYPT_VERIFYCONTEXT){
		TRACE_LINE("\n��ȡһ��Key Container(CRYPT_VERIFYCONTEXT)\n");

		CCSPKeyContainer* pVerifyKeyContainer = NULL;
		if(szName.IsEmpty())
			pVerifyKeyContainer = GetKeyContainerByName(VERIFY_KEY_CONTAINER_NAME);
		else
			pVerifyKeyContainer = GetKeyContainerByName(szContainerName);

		if(pVerifyKeyContainer == NULL){
			SETLASTERROR(NTE_BAD_KEYSET);
			return FALSE;
		}

		//�������ü���
		pVerifyKeyContainer->AddRef();
		*phProv = pVerifyKeyContainer->GetHandle();
	}
	//����һ��Key Container
	else if(dwFlags & CRYPT_NEWKEYSET){
		TRACE_LINE("\n����һ��Key Container\n");
  
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
		//�������ü���
		pKeyContainer->AddRef();
		*phProv = pKeyContainer->GetHandle();
	}
	//ɾ��һ��Key Container
	else if(dwFlags & CRYPT_DELETEKEYSET){
		TRACE_LINE("\nɾ��һ��Key Container\n");

		CCSPKeyContainer* pKeyContainer = GetKeyContainerByName(szContainerName);
		if(pKeyContainer == NULL){
			SETLASTERROR(NTE_KEYSET_NOT_DEF);
			return FALSE;
		}

		//������ܱ�������Կ�ԣ�����У��PIN
		if(pKeyContainer->HaveProtectedKeyPairs()){
			if(!Login()){
				SETLASTERROR(NTE_PERM);
				return FALSE;
			}
		}
		
		//ɾ��
		DestroyKeyContainer(pKeyContainer, TRUE);
	}
	//δ֪Flags
	else{
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	} 

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		Releases a context created by AcquireContext.
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv
//		DWORD dwFlags
//
//  ˵����
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
//	���ܣ�
//		Returns data about a cryptographic service provider 
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv
//		DWORD dwParam
//		BYTE *pbData
//		DWORD *pdwDataLen
//		DWORD dwFlags
//
//  ˵����
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

	//�������
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
		TRACE_LINE("\n���õ�Ŀ����Ϊ���ж����ݵĳ���\n");
	}

	//�����ȷ��ڴ�
	BYTE* pbBuffer = NULL;
	DWORD dwBufferLen = 0;

	//The name of the current key container as a 
	//NULL-terminated CHAR string.
	if(dwParam == PP_CONTAINER || dwParam == PP_UNIQUE_CONTAINER){
		TRACE_LINE("\n��ȡKeyContainer������\n");

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
		TRACE_LINE("\nö���㷨��ʶ\n");

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
		TRACE_LINE("\nö���㷨��ʶ\n");

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
		TRACE_LINE("\nö��KeyContainer\n");

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
		TRACE_LINE("\n��ȡCSP������\n");

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
		TRACE_LINE("\n��ȡCSP�İ汾��\n");

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
		TRACE_LINE("\n��ȡCSP��ʵ������\n");

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
		TRACE_LINE("\n��ȡCSP������\n");

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
		TRACE_LINE("\n��ȡǩ����Կ�Ե����ߴ�\n");

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
		TRACE_LINE("\n��ȡ������Կ�Ե����ߴ�\n");

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
		//���Ըò���
		TRACE_LINE("\n��ȡCSP��PP_KEYSET_SEC_DESCR\n");
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
//	���ܣ�
//		customizes the operations of a cryptographic service provider 
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv
//		DWORD dwParam
//		BYTE *pbData
//		DWORD dwFlags
//
//  ˵����
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
	//�������
	CCSPKeyContainer* pkeyContainer = GetKeyContainerByHandle(hProv);
	BOOL bRet = TRUE;
	if(pkeyContainer == NULL){
		SETLASTERROR(NTE_BAD_UID);
		return FALSE;
	}
	
	if(dwParam == PP_KEYSET_SEC_DESCR){
		//���Ըò���
	}
	else if (dwParam == PP_RESET_SEC_STAUS){   
		//jit����ĸ�λ��ȫ״̬
		m_reader.Logout();
		m_bLogin = FALSE;
	}
	else if(dwParam == PP_KEYEXCHANGE_PIN || dwParam == PP_SIGNATURE_PIN){
		//ע��
		if(pbData == NULL){
			m_reader.Logout();
			m_bLogin = FALSE;
		}
		else{
			//У��
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
		//�����û�PIN��
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
//	���ܣ�
//		����CTYCSPManager
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
CTYCSPManager::CTYCSPManager()
{
	m_hNextCSPHandle = 1;
}

//-------------------------------------------------------------------
//	���ܣ�
//		����CTYCSPManager
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
CTYCSPManager::~CTYCSPManager()
{
}

//-------------------------------------------------------------------
//	���ܣ�
//		ͨ�������ȡCSP����
//
//	���أ�
//		CSP�����ָ��
//
//  ������
//		HCRYPTCSP hCSP	CSP����ľ��
//
//  ˵����
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
//	���ܣ�
//		ͨ����д�������ֻ�ȡCSP����
//
//	���أ�
//		CSP�����ָ��
//
//  ������
//		LPCTSTR lpszName	��д��������
//
//  ˵����
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
//	���ܣ�
//		ͨ����д�������������ͻ�ȡCSP����
//
//	���أ�
//		CSP�����ָ��
//
//  ������
//		int nIndex			��д��������
//		ReaderType rdType	��д������
//
//  ˵����
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
//	���ܣ�
//		��ʼ��
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		��
//
//  ˵����
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

		//ö�ٶ�д����־
		lResult = reg.QueryValue(dwValue, "ReaderEnumFlag");
		if(lResult == ERROR_SUCCESS)
			m_dwEnumReaderFlag = dwValue;

		//���˶�д����־
		lResult = reg.QueryValue(dwValue, "FilterReader");
		if(lResult == ERROR_SUCCESS)
			m_bFilterReader = dwValue;

		//SSO��־
		lResult = reg.QueryValue(dwValue, "LoginSSO");
		if(lResult == ERROR_SUCCESS)
			m_bSSO = dwValue;

		reg.Close();
	}

	TRACE_LINE("m_dwEnumReaderFlag = %d; m_bFilterReader = %d; m_bSSO = %d\n", m_dwEnumReaderFlag, m_bFilterReader, m_bSSO);

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ͷ���Դ
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CTYCSPManager::Finalize()
{
	TRACE_FUNCTION("CTYCSPManager::Finalize");

	ReleaseCSPs();

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		����CSP����
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
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
//	���ܣ�
//		��������ΪPCSC��CSP����
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
void CTYCSPManager::CreatePCSCCSP()
{
	//����PCSC��
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

	//������Դ��������������
	lResult = g_SCardFuncHolder.m_listFunc.pfnSCardEstablishContext(
		SCARD_SCOPE_USER, NULL, NULL, &hSC
		);
	if (lResult != SCARD_S_SUCCESS)
		return;
	
	//���Ҷ�д���б�
	DWORD dwAutoAllocate = SCARD_AUTOALLOCATE;
	lResult = g_SCardFuncHolder.m_listFunc.pfnSCardListReaders(
		hSC, SCARD_DEFAULT_READERS, (LPTSTR)&mszReaderNames, &dwAutoAllocate
		);
	if (lResult != SCARD_S_SUCCESS){
		//������е�PCSC����
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

	//��ȡ��д������Ŀ�����Ʋ�����CSP����
	DWORD dwNumReaders;
	LPCTSTR szReaderName;

	//�쿴�Ƿ񲦳���Reader
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

	//����Ƿ���������������е���������޸�
	g_ModifyManager.FixModifies(&m_arCSPs);

	//�쿴�Ƿ�������µ�Reader
	for(dwNumReaders = 0, szReaderName = mszReaderNames;
	   *szReaderName != _T('\0');
	   dwNumReaders++)
	{
	   if(m_bFilterReader && !IsContainSubString(szReaderName, "tianyu")){
			szReaderName += lstrlen(szReaderName) + 1;
		   continue;
	   }
	   
		//�������µ�Reader
	   if(GetCSPByReaderName(szReaderName) == NULL){
			//����CSP����
			CTYCSP* pCSPObject = new CTYCSP;
			if(pCSPObject == NULL)
				break;

			//����CSP���
			pCSPObject->SetHandle(m_hNextCSPHandle++);
			//����CSP��Ӧ�Ķ�д��������
			pCSPObject->SetReaderName(szReaderName);
			//���ö�д������
			pCSPObject->SetReaderType(RT_PCSC);
			//��ʼ��
			pCSPObject->Initialize();

			//��������
			m_arCSPs.Add(pCSPObject);
	   }
		szReaderName += lstrlen(szReaderName) + 1;
	}

	g_SCardFuncHolder.m_listFunc.pfnSCardFreeMemory(hSC, (LPVOID)mszReaderNames);
	g_SCardFuncHolder.m_listFunc.pfnSCardReleaseContext(hSC);
}

//-------------------------------------------------------------------
//	���ܣ�
//		��������ΪTYKEY��CSP����
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
void CTYCSPManager::CreateUSBPortCSP()
{
	//����TYKEY�ӿ�
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

	//�о�TYKEY��״̬
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

	//�쿴�Ƿ񲦳���TYKEY
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

	//����Ƿ���������������е���������޸�
	g_ModifyManager.FixModifies(&m_arCSPs);

	//�쿴�Ƿ�������µ�TYKEY
	for(i = 0; i < sizeof(state)/sizeof(UCHAR); i++){
		if(state[i] == 0)
			continue;

		//�����²����˵�TYKEY
		if(GetCSPByReaderIndex(i, RT_USBPORT))
			continue;

		//����CSP����
		CTYCSP* pCSPObject = new CTYCSP;
		if(pCSPObject == NULL)
			break;

		//����CSP���
		pCSPObject->SetHandle(m_hNextCSPHandle++);
		//���ö�д������
		pCSPObject->SetReaderType(RT_USBPORT);
		//���ö�д��������
		pCSPObject->SetReaderIndex(i);
		//��ʼ��
		pCSPObject->Initialize();

		//��������
		m_arCSPs.Add(pCSPObject);
	}
}

//-------------------------------------------------------------------
//	���ܣ�
//		�������ڶ�������CSP����
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
void CTYCSPManager::CreateSerialPortCSP()
{
	g_TYReaderFuncHolder.Load();

	if(g_TYReaderFuncHolder.m_listFunc.pfnTY_Status == NULL)
		return;

	BYTE status[MAX_COMPORT_NUM] = {0};
	g_TYReaderFuncHolder.m_listFunc.pfnTY_Status(status);
	
	//�쿴�Ƿ񲦳��˶�����
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

	//�쿴�Ƿ�������µĶ�����
	for(i = 0; i < sizeof(status); i++){
		if(status[i] == 0)
			continue;

		//�����²����˵Ķ�����
		if(GetCSPByReaderIndex(i, RT_COMPORT))
			continue;

		//����CSP����
		CTYCSP* pCSPObject = new CTYCSP;
		if(pCSPObject == NULL)
			break;

		//����CSP���
		pCSPObject->SetHandle(m_hNextCSPHandle++);
		//���ö�д������
		pCSPObject->SetReaderType(RT_COMPORT);
		//���ö�д��������
		pCSPObject->SetReaderIndex(i);
		//��ʼ��
		pCSPObject->Initialize();

		//��������
		m_arCSPs.Add(pCSPObject);
	}
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡCSP�������Ŀ
//
//	���أ�
//		��Ŀ
//
//  ������
//
//  ˵����
//-------------------------------------------------------------------
DWORD
CTYCSPManager::GetCSPCount()
{
	return m_arCSPs.GetSize();
}

//-------------------------------------------------------------------
//	���ܣ�
//		ͨ��������ȡCSP����
//
//	���أ�
//		CSP�����ָ��
//
//  ������
//		int nIndex	����
//
//  ˵����
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
//	���ܣ�
//		�ͷ�CSP����
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
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
//	���ܣ�
//		Acquires a handle to the key container specified by the 
//	pszContainer parameter.
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV *phProv
//		CHAR *pszContainer
//		DWORD dwFlags
//		PVTableProvStruc pVTable
//  
//  ˵����
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
	//�ȴ���CSP�б�
	CreateCSPs();

	//�ж����������Ƿ��Ѱ�����д����·��
	BOOL bHaveReaderPath = FALSE;
	CString szReaderPath = _T("");
	CString szContainerName = _T("");
	if(pszContainer != NULL) szContainerName = pszContainer;
	if(szContainerName.Find(_T("\\\\.\\")) == 0){
		TRACE_LINE("\n��ʼ������ %s ������д��·��\n", szContainerName);
		szContainerName.TrimLeft(_T("\\\\.\\"));

		//�����д��������������
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
		TRACE_LINE("��д��������: %s;�������� %s\n", szReaderPath, szContainerName);
	}
	
	//�ж��Ƿ�Ҫ��ʾ��д��ѡ���
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
		//��Ƭ������
		int nOffset = 0;
		for(int i = 0; i < sizeof(g_szSupportCardName) / sizeof(TCHAR*); i++){
			lstrcpy(szSearchCard + nOffset, g_szSupportCardName[i]);
			nOffset += (lstrlen(g_szSupportCardName[i]) + 1);
		}
		//��˫'\0'��β���ʼ��ϵڶ���
		szSearchCard[nOffset] = (TCHAR)0x00;

		OPENCARDNAME dlgStruct;
		//��ʼ��
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
		//�����ӿ�
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
//	����Ψһ��TYCSPManagerʵ��
//
CTYCSPManager g_theTYCSPManager;


/////////////////////////////////////////////////////////////////////
// class CCSPRandomNumberGenerator

//-------------------------------------------------------------------
//	���ܣ�
//		��ʼ��
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
void 
CCSPRandomNumberGenerator::init()
{
	srand((unsigned int)time(NULL));
}

//-------------------------------------------------------------------
//	���ܣ�
//		����һ���ֽڵ������
//
//	���أ�
//		һ���ֽڵ������
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
byte 
CCSPRandomNumberGenerator::GetByte()
{
	return ((byte)rand());
}

/////////////////////////////////////////////////////////////////////
//	����Ψһ�� CCSPRandomNumberGenerator ʵ��
CCSPRandomNumberGenerator g_rng;
