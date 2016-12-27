#include "stdafx.h"
#include "CSPObject.h"
#include "KeyContainer.h"
#include "CSPKey.h"
#include "HashObject.h"
#include "HelperFunc.h"
#include "DERCoding.h"

#define	NOT_EXIST_ON_TOKEN		-1
extern DWORD g_dwSSF33Algid,g_dwSCB2Algid,g_dwEccSignAlgid,g_dwEccKeyxAlgid;
/////////////////////////////////////////////////////////////////////
//	class CCSPKeyContainer
//
//-------------------------------------------------------------------
//	���ܣ�
//		���캯��
//
//	���أ�
//		��
//
//  ������
//		CTYCSP* pCSPObject		CSP����
//		LPCTSTR lpszName		����
//		BOOL bInitOpen			����ʱ�Ƿ��
//
//  ˵����
//-------------------------------------------------------------------
CCSPKeyContainer::CCSPKeyContainer(
	CTYCSP* pCSPObject,
	LPCTSTR lpszName,
	BOOL bInitOpen /*=TRUE*/
	)
{
	ASSERT(pCSPObject != NULL);
	m_pCSPObject = pCSPObject;
	m_szName = new TCHAR[lstrlen(lpszName) + 1];
	if(m_szName) lstrcpy(m_szName, lpszName);
	m_bOpened = FALSE;
	m_bReleased = FALSE;
	m_hHandle = MAKE_HCRYPTPROV(pCSPObject->GetHandle(), pCSPObject->GetNextKCHandle());
	m_nIndexOnToken = NOT_EXIST_ON_TOKEN;
	m_dwRefCount = 0;

	if(bInitOpen) Open();
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
CCSPKeyContainer::~CCSPKeyContainer()
{
	if(m_szName != NULL){
		delete m_szName;
		m_szName = NULL;
	}
	DeleteAllObjects();	
}

//-------------------------------------------------------------------
//	���ܣ�
//		��Key Container
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
CCSPKeyContainer::Open()
{
	m_bOpened = TRUE;
	m_bReleased = FALSE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�������ü���
//
//	���أ�
//		��ǰ���ü���
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
DWORD
CCSPKeyContainer::AddRef()
{
	//�ͷű������ΪFALSE
	m_bReleased = FALSE;

	m_dwRefCount++;
	return m_dwRefCount;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ͷ�Key Container
//
//	���أ�
//		��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
DWORD
CCSPKeyContainer::Release()
{
	m_dwRefCount--;
	if(0 == m_dwRefCount){
		//ɾ��������Կ��HASH���󣬵�������Կ��
		DeleteHashObjects();
		DeleteSessionKeyObjects();

		m_bOpened = FALSE;
		m_bReleased = TRUE;
	}

	return m_dwRefCount;
}

//-------------------------------------------------------------------
//	���ܣ�
//		ɾ�����еĶ���
//
//	���أ�
//		��
//
//  ������
//		BOOL bDestroyOnToken	�Ƿ�ӿ�������
//
//  ˵����
//		������ӿ���ɾ������
//-------------------------------------------------------------------
void
CCSPKeyContainer::DeleteAllObjects(
	BOOL bDestroyOnToken /*= FALSE*/
	)
{
	DeleteHashObjects(bDestroyOnToken);
	DeleteSessionKeyObjects(bDestroyOnToken);
	DeleteKeyPairObjects(bDestroyOnToken);
}

//-------------------------------------------------------------------
//	���ܣ�
//		ɾ��HASH����
//
//	���أ�
//		��
//
//  ������
//		BOOL bDestroyOnToken	�Ƿ�ӿ�������
//
//  ˵����
//-------------------------------------------------------------------
void
CCSPKeyContainer::DeleteHashObjects(
	BOOL bDestroyOnToken /*= FALSE*/
	)
{
	CCSPHashObject* pHashObject = NULL;
	for(int i = 0; i < m_arHashObjects.GetSize(); i++){
		pHashObject = m_arHashObjects.GetAt(i);
		ASSERT(pHashObject != NULL);
		delete pHashObject;
	}
	m_arHashObjects.RemoveAll();
}

//-------------------------------------------------------------------
//	���ܣ�
//		ɾ��������Կ����
//
//	���أ�
//		��
//
//  ������
//		BOOL bDestroyOnToken	�Ƿ�ӿ�������
//
//  ˵����
//-------------------------------------------------------------------
void
CCSPKeyContainer::DeleteSessionKeyObjects(
	BOOL bDestroyOnToken /*= FALSE*/
	)
{
	CCSPKey* pKeyObject = NULL;
	for(int i = 0; i < m_arSessionKeys.GetSize(); i++){
		pKeyObject = m_arSessionKeys.GetAt(i);
		ASSERT(pKeyObject != NULL);
		delete pKeyObject;
	}
	m_arSessionKeys.RemoveAll();
}

//-------------------------------------------------------------------
//	���ܣ�
//		ɾ����Կ�Զ���
//
//	���أ�
//		��
//
//  ������
//		BOOL bDestroyOnToken	�Ƿ�ӿ�������
//
//  ˵����
//-------------------------------------------------------------------
void
CCSPKeyContainer::DeleteKeyPairObjects(
	BOOL bDestroyOnToken /*= FALSE*/
	)
{
	CCSPKey* pKeyObject = NULL;
	for(int i = 0; i < m_arKeyPair.GetSize(); i++){
		pKeyObject = m_arKeyPair.GetAt(i);
		ASSERT(pKeyObject != NULL);
		if(bDestroyOnToken)
			pKeyObject->DestroyOnToken();
		delete pKeyObject;
	}
	m_arKeyPair.RemoveAll();
}

//-------------------------------------------------------------------
//	���ܣ�
//		����ָ���㷨��ʶ����Կ��
//
//	���أ�
//		��
//
//  ������
//		ALG_ID algId		�㷨��ʶ
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPKeyContainer::DestroyKeyPair(
	ALG_ID algId
	)
{
	if(algId == AT_SIGNATURE)
		algId = CALG_RSA_SIGN;
	else if(algId == AT_KEYEXCHANGE)
		algId = CALG_RSA_KEYX;
	
	CCSPKey* pKeyPair = NULL;
	for(int i = 0; i < m_arKeyPair.GetSize(); i++){
		pKeyPair = m_arKeyPair.GetAt(i);
		ASSERT(pKeyPair != NULL);
		if(pKeyPair->GetAlgId() == algId){
//			if(pKeyPair->IsPrivate()){
//				if(!m_pCSPObject->IsLogin()){
//					SETLASTERROR(NTE_PERM);
//					return FALSE;;
//				}
//			}

			pKeyPair->DestroyOnToken();
			m_arKeyPair.RemoveAt(i);
			delete pKeyPair;

			return TRUE;
		}
	}

	SETLASTERROR(NTE_NO_KEY);
	return FALSE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		ͨ�������ȡHASH����
//
//	���أ�
//		HASH����ָ��
//
//  ������
//		HCRYPTHASH hHash	HASH����
//
//  ˵����
//-------------------------------------------------------------------
CCSPHashObject*
CCSPKeyContainer::GetHashObjectByHandle(
	HCRYPTHASH hHash
	)
{
	CCSPHashObject* pHashObject = NULL;
	for(int i = 0; i < m_arHashObjects.GetSize(); i++){
		pHashObject = m_arHashObjects.GetAt(i);
		if(pHashObject->GetHandle() == hHash)
			return pHashObject;
	}

	return NULL;
}

//-------------------------------------------------------------------
//	���ܣ�
//		ͨ�������ȡ��Կ�Զ���
//
//	���أ�
//		KEY����ָ��
//
//  ������
//		HCRYPTKEY hKey		KEY����
//
//  ˵����
//-------------------------------------------------------------------
CCSPKey*
CCSPKeyContainer::GetKeyPairObjectByHandle(
	HCRYPTKEY hKey
	)
{
	CCSPKey* pKeyPair = NULL;
	for(int i = 0; i < m_arKeyPair.GetSize(); i++){
		pKeyPair = m_arKeyPair.GetAt(i);
		if(pKeyPair->GetHandle() == hKey){
			//�ж���Կ����Ƿ�Ϊ�Ƿ���                                                         
			if(!pKeyPair->IsHandleValid())
				return NULL;

			return pKeyPair;
		}
	}

	return NULL;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡָ�����͵���Կ��
//
//	���أ�
//		KEY ����ָ��
//
//  ������
//		ALG_ID algId	��Կ������
//
//  ˵����
//-------------------------------------------------------------------
CCSPKey* 
CCSPKeyContainer::GetKeyPairObjectByAlgId(
	ALG_ID algId
	)
{
	CCSPKey* pKeyPair = NULL;
	for(int i = 0; i < m_arKeyPair.GetSize(); i++){
		pKeyPair = m_arKeyPair.GetAt(i);
		if(pKeyPair->GetAlgId() == algId){
			return pKeyPair;
		}
	}

	return NULL;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ж��Ƿ��Ѵ���ָ���㷨��ʶ����Կ��
//
//	���أ�
//		TRUE:����		FALSE:������
//
//  ������
//		ALG_ID algId	�㷨��ʶ
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::IsKeyPairExist(
	ALG_ID algId
	)
{
	if(GetKeyPairObjectByAlgId(algId) != NULL)
		return TRUE;
	else
		return FALSE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ж��Ƿ����ܱ�������Կ��
//
//	���أ�
//		TRUE����		FALSE��û��
//
//  ������
//		��
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPKeyContainer::HaveProtectedKeyPairs()
{
	CCSPKey* pKeyPair = NULL;
	for(int i = 0; i < m_arKeyPair.GetSize(); i++){
		pKeyPair = m_arKeyPair.GetAt(i);
		if(pKeyPair->IsPrivate())
			return TRUE;
	}

	return FALSE;
}


//-------------------------------------------------------------------
//	���ܣ�
//		ͨ�������ȡ������Կ����
//
//	���أ�
//		KEY����ָ��
//
//  ������
//		HCRYPTKEY hKey		KEY����
//
//  ˵����
//-------------------------------------------------------------------
CCSPKey*
CCSPKeyContainer::GetSessionKeyObjectByHandle(
	HCRYPTKEY hKey
	)
{
	CCSPKey* pKeyObject = NULL;
	for(int i = 0; i < m_arSessionKeys.GetSize(); i++){
		pKeyObject = m_arSessionKeys.GetAt(i);
		if(pKeyObject->GetHandle() == hKey)
			return pKeyObject;
	}

	return NULL;
}


//-------------------------------------------------------------------
//	���ܣ�
//		ͨ�������ȡ��Կ�Զ���
//
//	���أ�
//		KEY����ָ��
//
//  ������
//		HCRYPTKEY hKey		KEY����
//
//  ˵����
//-------------------------------------------------------------------
CCSPKey*
CCSPKeyContainer::GetKeyObjectByHandle(
	HCRYPTKEY hKey
	)
{
	CCSPKey* pKeyObject = GetSessionKeyObjectByHandle(hKey);
	if(pKeyObject != NULL)
		return pKeyObject;
	return GetKeyPairObjectByHandle(hKey);
}

//-------------------------------------------------------------------
//	���ܣ�
//		�����㷨��ʶ������Կ����
//
//	���أ�
//		��Կ����ָ��
//
//  ������
//		ALG_ID	algId		�㷨��ʶ
//		BOOL bIsPublicKey	�Ƿ�Ϊ��Կ����
//
//  ˵����
//-------------------------------------------------------------------
CCSPKey*
CCSPKeyContainer::CreateKeyObjectByAlgId(
	ALG_ID algId,
	BOOL bIsPublicKey /*=FALSE*/
	)
{
	CCSPKey* pKeyObject = NULL;

	switch(algId){
	case CALG_RC2:
		TRACE_LINE("\n����RC2��Կ\n");
		pKeyObject = new CCSPRc2Key(this, algId, FALSE);
		break;
	case CALG_RC4:
		TRACE_LINE("\n����RC4��Կ\n");
		pKeyObject = new CCSPRc4Key(this, algId, FALSE);
		break;
	case CALG_DES:
		TRACE_LINE("\n����DES��Կ\n");
		pKeyObject = new CCSPDesKey(this, algId, FALSE);
		break;
	case CALG_3DES_112:
		TRACE_LINE("\n����2DES��Կ\n");
		pKeyObject = new CCSP2DesKey(this, algId, FALSE);
		break;
	case CALG_3DES:
		TRACE_LINE("\n����3DES��Կ\n");
		pKeyObject = new CCSP3DesKey(this, algId, FALSE);
		break;
	case CALG_RSA_SIGN:
	case CALG_RSA_KEYX:
		if(bIsPublicKey){
			if(algId == CALG_RSA_SIGN)
				TRACE_LINE("\n����RSAǩ����Կ��\n");
			else
				TRACE_LINE("\n����RSAǩ����Կ\n");

			pKeyObject = new CCSPRsaPuk(this, algId, FALSE);
		}
		else{
			if(algId == CALG_RSA_SIGN)
				TRACE_LINE("\n����RSA������Կ��\n");
			else
				TRACE_LINE("\n����RSA������Կ\n");

			pKeyObject = new CCSPRsaPrk(this, algId, TRUE);
		}
		break;
	}
	////////////////////////////////////////////////////////
	//������㷨ID wincrypt.h��û�ж��塣
	if (algId == g_dwSSF33Algid)//CALG_SSF33
	{	
		TRACE_LINE("\n����SSF33��Կ\n");
		pKeyObject = new CCSPSSF33Key(this, algId, FALSE);
	}
	else if (algId == g_dwSCB2Algid)//CALG_SCB2
	{
		TRACE_LINE("\n����SCB2��Կ\n");
		pKeyObject = new CCSPSCB2Key(this, algId, FALSE);
	} 
	else if (algId == g_dwEccSignAlgid)//
	{
		if (bIsPublicKey)
		{
			pKeyObject = new CCSPEccPuk(this, algId, FALSE);
		}
		else
		{
			pKeyObject = new CCSPEccPrk(this, algId, TRUE);
		}
		
	}
	else if(algId == g_dwEccKeyxAlgid)//
	{
		if (bIsPublicKey)
		{
			pKeyObject = new CCSPEccPuk(this, algId, FALSE);
		}
		else
		{
			pKeyObject = new CCSPEccPrk(this, algId, TRUE);
		}
		
	}
	return pKeyObject;
}

//-------------------------------------------------------------------
//	���ܣ�
//		���Ʋ��½�һ��������Կ����
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		CCSPKey* pSource		Դ����
//		CCSPKey*& pDuplicate	Ŀ�����
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPKeyContainer::DuplicateSessionKeyObject(
	CCSPKey* pSource,
	CCSPKey*& pDuplicate
	)
{
	if(pSource == NULL)
		return FALSE;

	pDuplicate = NULL;
	switch(pSource->GetAlgId()){
		case CALG_RC2:
			pDuplicate = new CCSPRc2Key(*((CCSPRc2Key* )pSource));
			break;
		case CALG_RC4:
			pDuplicate = new CCSPRc4Key(*((CCSPRc4Key* )pSource));
			break;
		case CALG_DES:
			pDuplicate = new CCSPDesKey(*((CCSPDesKey* )pSource));
			break;
		case CALG_3DES_112:
			pDuplicate = new CCSP2DesKey(*((CCSP2DesKey* )pSource));
			break;
		case CALG_3DES:
			pDuplicate = new CCSP3DesKey(*((CCSP3DesKey* )pSource));
			break;
		case CALG_SSF33:
			pDuplicate = new CCSPSSF33Key(*((CCSPSSF33Key* )pSource));
			break;
		case CALG_RSA_SIGN:
		case CALG_RSA_KEYX:
			pDuplicate = new CCSPRsaPuk(*((CCSPRsaPuk* )pSource));
			break;
	}

	if(pSource->GetAlgId() == g_dwSSF33Algid)
	{
		pDuplicate = new CCSPSSF33Key(*((CCSPSSF33Key* )pSource));
	}
	else if (pSource->GetAlgId() == g_dwSCB2Algid)
	{
		pDuplicate = new CCSPSCB2Key(*((CCSPSCB2Key* )pSource));
	}
	else if (pSource->GetAlgId() == g_dwEccKeyxAlgid || pSource->GetAlgId() == g_dwEccSignAlgid)
	{
		pDuplicate = new CCSPEccPuk(*((CCSPEccPuk* )pSource));
	}
	return (pDuplicate != NULL);//??return (pDuplicate == NULL);
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ӿ���������Կ��
//
//	���أ�
//		��
//
//  ������
//		CONST BYTE* pDERStr		��Կ�Ե�DER���� 
//		DWORD dwDERLen			DER����ĳ���
//
//  ˵����
//-------------------------------------------------------------------
void
CCSPKeyContainer::LoadKeyPairs(
	BYTE* pDERStr, 
	ULONG ulDERLen
	)
{
	if(pDERStr == NULL)
		return;

	//��һ���ǽ�����Կ��
	ULONG ulTag = ::GetDERTag(pDERStr, ulDERLen);
	if(ulTag == 0x30){
		DWORD algid = MAKELONG(MAKEWORD(pDERStr[7],pDERStr[8]),MAKEWORD(pDERStr[9],pDERStr[10]));
		if (algid == CALG_RSA_KEYX) {
		CCSPKey* pExchangeKeyPair = new CCSPRsaPrk(this, CALG_RSA_KEYX, TRUE);
		if(pExchangeKeyPair != NULL){
			pExchangeKeyPair->LoadFromToken(GetTokenIndex());
			m_arKeyPair.Add(pExchangeKeyPair);
			}
		}
		else if (algid == g_dwEccKeyxAlgid) {
			CCSPKey* pExchangeKeyPair = new CCSPEccPrk(this, g_dwEccKeyxAlgid, TRUE);
			if(pExchangeKeyPair != NULL){
				pExchangeKeyPair->LoadFromToken(GetTokenIndex());
				m_arKeyPair.Add(pExchangeKeyPair);
			}
		}		
	}

	//�ڶ�����ǩ����Կ��
	ULONG ulTagLen, ulLenLen, ulValueLen;
	ulValueLen = ::GetDERLen(pDERStr, ulDERLen, ulTagLen, ulLenLen);
	pDERStr += (ulTagLen + ulLenLen + ulValueLen);
	ulDERLen -= (ulTagLen + ulLenLen + ulValueLen);
	ulTag = ::GetDERTag(pDERStr, ulDERLen); 
	if(ulTag == 0x30){
		DWORD algid = MAKELONG(MAKEWORD(pDERStr[7],pDERStr[8]),MAKEWORD(pDERStr[9],pDERStr[10]));
		if (algid == CALG_RSA_KEYX) {
		CCSPKey* pSignKeyPair = new CCSPRsaPrk(this, CALG_RSA_SIGN, TRUE);
		if(pSignKeyPair != NULL){
			pSignKeyPair->LoadFromToken(GetTokenIndex());
			m_arKeyPair.Add(pSignKeyPair);
			}
		}
		else if (algid == g_dwEccSignAlgid) {
			CCSPKey* pSignKeyPair = new CCSPEccPrk(this, g_dwEccSignAlgid, TRUE);
			if(pSignKeyPair != NULL){
				pSignKeyPair->LoadFromToken(GetTokenIndex());
				m_arKeyPair.Add(pSignKeyPair);
			}
		}
	}
}

//-------------------------------------------------------------------
//	���ܣ�
//		����Key Container������ڿ�Ƭ�ϵĴ�������
//
//	���أ�
//		��
//
//  ������
//		int nIndex	����ֵ
//
//  ˵����
//-------------------------------------------------------------------
void 
CCSPKeyContainer::SetTokenIndex(
	int nIndex
	)
{
	m_nIndexOnToken = nIndex; 

	//ͬ�Ǹ���������Կ������
	CCSPKey* pKeyObject = NULL;
	for(int i = 0; i < m_arKeyPair.GetSize(); i++){
		pKeyObject = m_arKeyPair.GetAt(i);
		pKeyObject->SetIndex(m_nIndexOnToken);
	}

	for(i = 0; i < m_arSessionKeys.GetSize(); i++){
		pKeyObject = m_arSessionKeys.GetAt(i);
		pKeyObject->SetIndex(m_nIndexOnToken);
	}
}


//-------------------------------------------------------------------
//	���ܣ�
//		�ڿ��ϴ���
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		int nIndex		�ڿ��еĴ�������
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::CreateOnToken(
	int nIndex
	)
{
	m_nIndexOnToken = nIndex;

	m_pCSPObject->BeginTransaction();

	DWORD dwFileSize;
	FILEHANDLE hFile = NULL;
	if(!m_pCSPObject->OpenFile(g_cPathTable.prkdfPath, &hFile, &dwFileSize)){
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	SHARE_XDF XdfRec;
	if(!m_pCSPObject->GetXdf(DFTYPE_PRK,&XdfRec)){
		m_pCSPObject->CloseFile(hFile);
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	ULONG ulOffset,ulLen;
	byteArray encodeArray;
	if (!m_pCSPObject->GetOffsetFormIndex(&XdfRec,m_nIndexOnToken,ulOffset,ulLen)){
		m_pCSPObject->CloseFile(hFile);
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	//encode the name
	CopyToByteArray((LPBYTE)m_szName, lstrlen(m_szName), encodeArray);
	encodeArray.Add(0x00);
	TLVEncoding(0x30,encodeArray.GetSize(),encodeArray);
	//����������Կ�Ŀյ�
	encodeArray.Add(0xff);
	encodeArray.Add(BYTE(g_cPathTable.prkAttrLen));
	for (int i = 0; i<BYTE(g_cPathTable.prkAttrLen); i++)
	{
		encodeArray.Add(0x00);
	}
	encodeArray.Add(0xff);
	encodeArray.Add(BYTE(g_cPathTable.prkAttrLen));
	for (i = 0; i<BYTE(g_cPathTable.prkAttrLen); i++)
	{
		encodeArray.Add(0x00);
	}

	TLVEncoding(0x30,encodeArray.GetSize(),encodeArray);
	//��д�����ֽ�00 00��Ϊ��β��־
	encodeArray.Add(0x00);
	encodeArray.Add(0x00);

	if(!m_pCSPObject->WriteFile(
		hFile, encodeArray.GetData(), encodeArray.GetSize(), ulOffset
		))
	{
		m_pCSPObject->CloseFile(hFile);
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	//change the xdf in the memory
	XdfRec.ulDataLen += (encodeArray.GetSize() - 2);
	memcpy(XdfRec.cContent+ulOffset,encodeArray.GetData(),encodeArray.GetSize());
	m_pCSPObject->SetXdf(DFTYPE_PRK,&XdfRec);
	m_pCSPObject->CloseFile(hFile);
	m_pCSPObject->EndTransaction();

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ڿ���ɾ��
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
CCSPKeyContainer::DestroyOnToken()
{
	DeleteKeyPairObjects(TRUE);
	
	m_pCSPObject->BeginTransaction();

	DWORD dwFileSize;
	FILEHANDLE hFile = NULL;
	if(!m_pCSPObject->OpenFile(g_cPathTable.prkdfPath, &hFile, &dwFileSize)){
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	SHARE_XDF XdfRec;
	if(!m_pCSPObject->GetXdf(DFTYPE_PRK,&XdfRec)){
		m_pCSPObject->CloseFile(hFile);
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	ULONG ulOffset,ulLen;
	if (!m_pCSPObject->GetOffsetFormIndex(&XdfRec,m_nIndexOnToken,ulOffset,ulLen)){
		m_pCSPObject->CloseFile(hFile);
		m_pCSPObject->EndTransaction();
		return FALSE;
	}
	
	//ֱ����ɾ�����
	BYTE data = DESTROIED_TAG;
	if(!m_pCSPObject->WriteFile(hFile, &data, 1, ulOffset)){
		m_pCSPObject->CloseFile(hFile);
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	//change the xdf in memory
	XdfRec.cContent[ulOffset] = data;
	XdfRec.bHasFragment = TRUE;
	m_pCSPObject->SetXdf(DFTYPE_PRK, &XdfRec);
	m_pCSPObject->CloseFile(hFile);
	m_pCSPObject->EndTransaction();

	return TRUE;
}

/////////////////////////////////////////////////////////////////////
//	CryptSPI Functions
//
//-------------------------------------------------------------------
//	���ܣ�
//		Generates a random cryptographic key or key pair.
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		ALG_ID Algid			�㷨��ʶ
//		DWORD dwFlags			��־
//		HCRYPTKEY* phKey		��������Կ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL
CCSPKeyContainer::GenKey(
	ALG_ID Algid,
	DWORD dwFlags,
	HCRYPTKEY* phKey
	)
{
	ALG_ID idAlg;
	if(Algid == AT_SIGNATURE)
		idAlg = CALG_RSA_SIGN;
	else if(Algid == AT_KEYEXCHANGE)
		idAlg = CALG_RSA_KEYX;
	else
		idAlg = Algid;

	//�������
	if(phKey == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//�����ʼֵ
	*phKey = NULL;

	//�Ƿ�֧�ָ��㷨
	PROV_ENUMALGS_EX info;
	info.aiAlgid = idAlg;
	if(!::GetAlgInfo(info)){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}

	//�����Կ����
	DWORD dwKeyBitLen = HIWORD(dwFlags);
	//δָ������ȱʡֵ,�����ж��Ƿ��ڷ�Χ��
	if(dwKeyBitLen == 0)
		dwKeyBitLen = info.dwDefaultLen;
	else{
		if(dwKeyBitLen < info.dwMinLen || dwKeyBitLen > info.dwMaxLen){
			SETLASTERROR(NTE_BAD_FLAGS );
			return FALSE;
		}
		//������8��������
		if(dwKeyBitLen%8 != 0){
			SETLASTERROR(NTE_BAD_FLAGS);
			return FALSE;
		}
	}
	TRACE_LINE("\n��Կ����Ϊ %d\n", dwKeyBitLen);
	
	//������HASH�㷨��ID
	if(GET_ALG_CLASS(idAlg) == ALG_CLASS_HASH){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}

	//�Ƿ������Կ��
	BOOL bIsKeyPair = ::IsSupportKeyPairAlgId(idAlg);
	//������Կ����������
	if(bIsKeyPair){
		//An application cannot create new key pairs if no key container 
		//is currently open. This can happen if CRYPT_VERIFYCONTEXT was set 
		//in the CPAcquireContext call. If a key cannot be created, the 
		//NTE_PERM error code is returned.
		if(!IsOpened()){
			SETLASTERROR(NTE_PERM);
			return FALSE;
		}

/*		//��ÿһ�����͵���Կ��,ֻ�ܴ洢һ��
		if(IsKeyPairExist(idAlg)){
			SETLASTERROR(NTE_EXISTS);
			return FALSE;
		}
*/
		DestroyKeyPair(idAlg);

		//�����Ҫ����,������֤PIN��
		if(dwFlags & CRYPT_USER_PROTECTED){
			if(!m_pCSPObject->IsLogin()){
				SETLASTERROR(NTE_PERM);
				return FALSE;
			}
		}
	}

	//�����յ���Կ����
	CCSPKey* pKeyObject = CreateKeyObjectByAlgId(idAlg);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}
	//������Կ����
	BOOL bRetVal = pKeyObject->Create(dwKeyBitLen, dwFlags);

	//�ɹ������������
	if(bRetVal){
		if(bIsKeyPair){
			bRetVal = pKeyObject->CreateOnToken(GetKeyPairCreateIndex());
			if(!bRetVal){
				delete pKeyObject;
				SETLASTERROR(NTE_FAIL);
			}
			else
				m_arKeyPair.Add(pKeyObject);
		}
		else
			m_arSessionKeys.Add(pKeyObject);

		//������Կ���
		*phKey = pKeyObject->GetHandle();
	}
	//����ɾ��
	else{
		delete pKeyObject;
		SETLASTERROR(NTE_FAIL);
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		Generates a cryptographic session key using a hash of base data
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		ALG_ID Algid				�㷨��ʶ
//		HCRYPTHASH hBaseData		������
//		DWORD dwFlags				��־
//		HCRYPTKEY *phKey			��������Կ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::DeriveKey(
	ALG_ID Algid,
	HCRYPTHASH hBaseData,
	DWORD dwFlags,
	HCRYPTKEY *phKey
	)
{
	//�������
	if(phKey == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//�����ʼֵ
	*phKey = NULL;

	//�Ƿ�֧�ָ��㷨
	PROV_ENUMALGS_EX info;
	info.aiAlgid = Algid;
	if(!::GetAlgInfo(info)){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}
	
	//�����Կ����
	DWORD dwKeyBitLen = HIWORD(dwFlags);
	//δָ������ȱʡֵ,�����ж��Ƿ��ڷ�Χ��
	if(dwKeyBitLen == 0)
		dwKeyBitLen = info.dwDefaultLen;
	else{
		if(dwKeyBitLen < info.dwMinLen || dwKeyBitLen > info.dwMaxLen){
			SETLASTERROR(NTE_BAD_FLAGS );
			return FALSE;
		}
		//������8��������
		if(dwKeyBitLen%8 != 0){
			SETLASTERROR(NTE_BAD_FLAGS);
			return FALSE;
		}
	}
	TRACE_LINE("\n��Կ����Ϊ %d\n", dwKeyBitLen);

	//������HASH���㷨ID
	if(GET_ALG_CLASS(Algid) == ALG_CLASS_HASH){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}

	//��������Կ�Ե��㷨ID
	if(::IsSupportKeyPairAlgId(Algid)){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}

	//����HASH����
	CCSPHashObject* pHashObject = GetHashObjectByHandle(hBaseData);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	//�����յ���Կ����
	CCSPKey* pKeyObject = CreateKeyObjectByAlgId(Algid);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}
	//������Կ����
	BOOL bRetVal = pKeyObject->DeriveKey(dwKeyBitLen, pHashObject, dwFlags);

	//�ɹ������������,����ɾ��
	if(bRetVal){
		m_arSessionKeys.Add(pKeyObject);
		//������Կ���
		*phKey = pKeyObject->GetHandle();
	}
	else{
		delete pKeyObject;
		SETLASTERROR(NTE_FAIL);
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		Makes an exact copy of a key. Some keys have an associated 
//	state such as an initialization vector or a salt value. If a key 
//	with an associated state is duplicated, the associated state is 
//	also copied.
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTKEY hKey			Դ��Կ���
//		DWORD *pdwReserved		����ֵ
//		DWORD dwFlags			��־
//		HCRYPTKEY* phKey		��������Կ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::DuplicateKey(
	HCRYPTKEY hKey,
	DWORD *pdwReserved,
	DWORD dwFlags,
	HCRYPTKEY* phKey
	)
{
	//�������
	if(pdwReserved != NULL && dwFlags != 0){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if(phKey == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//�����ʼֵ
	*phKey = NULL;
	
	//����Դ��Կ����
	CCSPKey* pSourceKeyObject = GetSessionKeyObjectByHandle(hKey);
	if(pSourceKeyObject == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

/*	//��Կ�Բ��ܱ�����
	if(::IsSupportKeyPairAlgId(pSourceKeyObject->GetAlgId()) &&
		pSourceKeyObject->IsPermanent()
		)
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}*/

	//����
	CCSPKey* pDuplicateKeyObject = NULL;
	if(!DuplicateSessionKeyObject(pSourceKeyObject, pDuplicateKeyObject)){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}
	else{
		m_arSessionKeys.Add(pDuplicateKeyObject);
		//������Կ���
		*phKey = pDuplicateKeyObject->GetHandle();
		
		return TRUE;
	}
}

//-------------------------------------------------------------------
//	���ܣ�
//		Releases the handle referenced by the hKey parameter. After 
//	a key handle has been released, it becomes invalid and can no 
//	longer be used.
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTKEY hKey		��Կ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::DestroyKey(
	HCRYPTKEY hKey
	)
{
	//��ɾ��ǰ�Ƚ����������ɾ��
	CCSPKey* pKeyObject = NULL;

	//���ڹ�����Կ�в���
	for(int i = 0; i < m_arSessionKeys.GetSize(); i++){
		pKeyObject = m_arSessionKeys.GetAt(i);
		if(pKeyObject->GetHandle() == hKey){
			m_arSessionKeys.RemoveAt(i);
			delete pKeyObject;
			return TRUE;
		}
	}

	//������Կ���в���
	for(i = 0; i < m_arKeyPair.GetSize(); i++){
		pKeyObject = m_arKeyPair.GetAt(i);
		if(pKeyObject->GetHandle() == hKey){
			pKeyObject->ValidateHandle(FALSE);
//			m_arKeyPair.RemoveAt(i);
//			delete pKeyObject;
			return TRUE;
		}
	}

	//û���ҵ�
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		Retrieves data that governs the operations of a key.
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTKEY hKey			��Կ������
//		DWORD dwParam			��������
//		BYTE *pbData			��������
//		DWORD *pdwDataLen		�������ݳ���
//		DWORD dwFlags			��־
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::GetKeyParam(
	HCRYPTKEY hKey,
	DWORD dwParam,
	BYTE *pbData,
	DWORD *pdwDataLen,
	DWORD dwFlags
	)
{
	//������Կ����
	CCSPKey* pKeyObject = GetKeyObjectByHandle(hKey);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	//��ȡ����
	return pKeyObject->GetParam(dwParam, pbData, pdwDataLen, dwFlags);
}

//-------------------------------------------------------------------
//	���ܣ�
//		Customizes the operations of a key.
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTKEY hKey			��Կ������
//		DWORD dwParam			��������
//		BYTE *pbData			��������
//		DWORD dwFlags			��־
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::SetKeyParam(
	HCRYPTKEY hKey,
	DWORD dwParam,
	BYTE *pbData,
	DWORD dwFlags
	)
{
	//������Կ����
	CCSPKey* pKeyObject = GetKeyObjectByHandle(hKey);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	//���ò���
	return pKeyObject->SetParam(dwParam, pbData, dwFlags);
}

//-------------------------------------------------------------------
//	���ܣ�
//		Transfers a cryptographic key from a key BLOB to a CSP key 
//	container
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		CONST BYTE *pbData		Key BLOB ����
//		DWORD dwDataLen			Key BLOB ���ݵĳ���
//		HCRYPTKEY hImpKey		������Կ�ľ��
//		DWORD dwFlags			��־
//		HCRYPTKEY *phKey		��������Կ�ľ��
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::ImportKey(
	CONST BYTE *pbData,
	DWORD dwDataLen,
	HCRYPTKEY hImpKey,
	DWORD dwFlags,
	HCRYPTKEY *phKey
	)
{
	//�������
	if(phKey == NULL || pbData == NULL || 
		dwDataLen <= sizeof(BLOBHEADER)){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//�����ʼֵ
	*phKey = NULL;
	
	//���KEY BLOB����Ч��
	BLOBHEADER* pHeader = (BLOBHEADER* )pbData;
	if(pHeader->bVersion != 0x02){
		SETLASTERROR(NTE_BAD_VER);
		return FALSE;
	}

	if(pHeader->reserved != 0){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	BOOL bIsKeyPair = FALSE;

	switch(pHeader->bType){
	case SIMPLEBLOB:
		if(!::IsSupportSymmetricKeyAlgId(pHeader->aiKeyAlg)){
			SETLASTERROR(NTE_BAD_ALGID);
			return FALSE;
		}
		break;
	case PUBLICKEYBLOB:
		if(!::IsSupportKeyPairAlgId(pHeader->aiKeyAlg)){
			SETLASTERROR(NTE_BAD_ALGID);
			return FALSE;
		}
		break;
	case PRIVATEKEYBLOB:
		if(!::IsSupportKeyPairAlgId(pHeader->aiKeyAlg)){
			SETLASTERROR(NTE_BAD_ALGID);
			return FALSE;
		}
		bIsKeyPair = TRUE;
		break;
	default:
		SETLASTERROR(NTE_BAD_TYPE);
		return FALSE;
	}

	//������Կ����������
	if(bIsKeyPair){
		//An application cannot create new key pairs if no key container 
		//is currently open. This can happen if CRYPT_VERIFYCONTEXT was set 
		//in the CPAcquireContext call. If a key cannot be created, the 
		//NTE_PERM error code is returned.
//		if(!IsOpened()){
//			SETLASTERROR(NTE_PERM);
//			return FALSE;
//		}

/*		//��ÿһ�����͵���Կ��,ֻ�ܴ洢һ��
		if(IsKeyPairExist(pHeader->aiKeyAlg)){
			SETLASTERROR(NTE_EXISTS);
			return FALSE;
		}
*/
		DestroyKeyPair(pHeader->aiKeyAlg);
	}

	//��ȡ������Կ����
	CCSPKey* pImpKeyObject = NULL;
	if(hImpKey != NULL){
		pImpKeyObject = GetKeyObjectByHandle(hImpKey);
		if(pImpKeyObject == NULL){
			SETLASTERROR(NTE_BAD_KEY);
			return FALSE;
		}
	}

	//�����յ���Կ����
	CCSPKey* pKeyObject = CreateKeyObjectByAlgId(pHeader->aiKeyAlg, !bIsKeyPair);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}
	//������Կ����
	BOOL bRetVal = pKeyObject->Import(pbData, dwDataLen, pImpKeyObject, dwFlags);

	//�ɹ������������
	if(bRetVal){
		if(bIsKeyPair){
			if(IsOpened()) 
				bRetVal = pKeyObject->CreateOnToken(GetKeyPairCreateIndex());
			if(!bRetVal){
				delete pKeyObject;
				SETLASTERROR(NTE_FAIL);
			}
			else
				m_arKeyPair.Add(pKeyObject);
		}
		else
			m_arSessionKeys.Add(pKeyObject);
		//������Կ���
		*phKey = pKeyObject->GetHandle();
	}
	//����ɾ��
	else{
		delete pKeyObject;
		SETLASTERROR(NTE_FAIL);
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		Securely exports cryptographic keys from a CSP's key container
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTKEY hKey			����������Կ����ľ��
//		HCRYPTKEY hExpKey		������Կ����ľ��
//		DWORD dwBlobType		Key BLOB������
//		DWORD dwFlags			��־
//		BYTE *pbData			Key BLOB����
//		DWORD *pdwDataLen		Key BLOL���ݵĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::ExportKey(
	HCRYPTKEY hKey,
	HCRYPTKEY hExpKey,
	DWORD dwBlobType,
	DWORD dwFlags,
	BYTE *pbData,
	DWORD *pdwDataLen
	)
{
	//��ȡ��������Կ����
	CCSPKey* pKeyObject = GetKeyObjectByHandle(hKey);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	//��ȡ������Կ����
	CCSPKey* pExpKeyObject = NULL;
	if(hExpKey != NULL){
		pExpKeyObject = GetKeyObjectByHandle(hExpKey);
		if(pExpKeyObject == NULL){
			SETLASTERROR(NTE_BAD_KEY);
			return FALSE;
		}
	}

	//������Կ
	return pKeyObject->Export(pExpKeyObject, dwBlobType, dwFlags, pbData, pdwDataLen);
}

//-------------------------------------------------------------------
//	���ܣ�
//		���������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		DWORD dwLen				������ĳ���
//		BYTE *pbBuffer			�����
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::GenRandom(
	DWORD dwLen,
	BYTE *pbBuffer
	)
{
	if(pbBuffer == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if(GetCSPObject()->GetCryptMode() == SOFTWARE){
		for(DWORD i = 0; i < dwLen; i++)
			pbBuffer[i] = g_rng.GetByte();
	}
	else{
		//ÿ�β���������ĸ���
		BYTE bPer = 8;
		DWORD dwDataLen = (dwLen + (bPer - 1))/bPer*bPer;
		//����������Ĵ�ſռ�
		BYTE* pData = new BYTE[dwDataLen];
		if(pData == NULL){
			SETLASTERROR(NTE_NO_MEMORY);
			return FALSE;
		}

		//���������(��LC��DATA)
		BYTE cCommand[5];
		cCommand[0] = 0x00;			//CLA
		cCommand[1] = 0x84;			//INS
		cCommand[2] = 0x00;			//P1
		cCommand[3] = 0x00;			//P2
		cCommand[4] = bPer;			//LE

		//��ȡ�����
		DWORD dwRespLen;
		BOOL bRetVal;
		for(DWORD i = 0; i < dwDataLen/bPer; i++){
			bRetVal = m_pCSPObject->SendCommand(cCommand, sizeof(cCommand), pData + i*bPer, &dwRespLen);
			if(bRetVal != TRUE){
				delete pData;
				SETLASTERROR(NTE_FAIL);
				return FALSE;
			}
		}

		//����������ظ��û�
		memcpy(pbBuffer, pData, dwLen);
		//�ͷſռ�
		delete pData;
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		Retrieves the handle of one of the permanent key pairs in the 
//	hProv key container.
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		DWORD dwKeySpec			��Կ������
//		HCRYPTKEY *phUserKey	��Կ�Ծ��
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::GetUserKey(
	DWORD dwKeySpec,
	HCRYPTKEY *phUserKey
	)
{
	//���ؾ����ָ�벻��Ϊ��
	if(phUserKey == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//�����ֵ
	*phUserKey = NULL;
	
	//����ָ�����͵���Կ��
	CCSPKey* pKeyPair = GetKeyPairObjectByAlgId(KeyPairTypeToAlgid(dwKeySpec));
	if(pKeyPair == NULL){
		SETLASTERROR(NTE_NO_KEY);
		return FALSE;
	}

	pKeyPair->ValidateHandle(TRUE);
	//������Կ�Ծ��
	*phUserKey = pKeyPair->GetHandle();

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		Encrypts data. Optionally, the application can specify that 
//	a hash of the paintext data is to be generated.
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTKEY hKey			������Կ����ľ��
//		HCRYPTHASH hHash		HASH������
//		BOOL Final				�Ƿ�Ϊ���һ������
//		DWORD dwFlags			��־
//		BYTE *pbData			��������
//		DWORD *pdwDataLen		�������ݵĳ���
//		DWORD dwBufLen			�����������ݻ�����ܳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::Encrypt(
	HCRYPTKEY hKey,
	HCRYPTHASH hHash,
	BOOL Final,
	DWORD dwFlags,
	BYTE *pbData,
	DWORD *pdwDataLen,
	DWORD dwBufLen
	)
{
	//������Կ����
	CCSPKey* pKeyObject = GetKeyObjectByHandle(hKey);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}
	
	//����HASH����
	CCSPHashObject* pHashObject = NULL;
	if(hHash != NULL){
		pHashObject = GetHashObjectByHandle(hHash);
		if(pHashObject == NULL){
			SETLASTERROR(NTE_BAD_HASH);
			return FALSE;
		}
	}

	//����
	return pKeyObject->Encrypt(pHashObject, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

//-------------------------------------------------------------------
//	���ܣ�
//		Decrypts data previously encrypted with the CPEncrypt function. 
//	Optionally, the application can specify that the decrypted data 
//	be hashed.
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTKEY hKey			������Կ����ľ��
//		HCRYPTHASH hHash		HASH������
//		BOOL Final				�Ƿ�Ϊ���һ������
//		DWORD dwFlags			��־
//		BYTE *pbData			��������
//		DWORD *pdwDataLen		�������ݵĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::Decrypt(
	HCRYPTKEY hKey,
	HCRYPTHASH hHash,
	BOOL Final,
	DWORD dwFlags,
	BYTE *pbData,
	DWORD *pdwDataLen
	)
{
	//������Կ����
	CCSPKey* pKeyObject = GetKeyObjectByHandle(hKey);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}
	
	//����HASH����
	CCSPHashObject* pHashObject = NULL;
	if(hHash != NULL){
		pHashObject = GetHashObjectByHandle(hHash);
		if(pHashObject == NULL){
			SETLASTERROR(NTE_BAD_HASH);
			return FALSE;
		}
	}

	//����
	return pKeyObject->Decrypt(pHashObject, Final, dwFlags, pbData, pdwDataLen);
}

//-------------------------------------------------------------------
//	���ܣ�
//		����һ���յ�HASH����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		ALG_ID Algid			�㷨��ʶ		
//		HCRYPTKEY hKey			MAC�õ���Կ���
//		DWORD dwFlags			��־
//		HCRYPTHASH *phHash		���ز�����HASH������
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::CreateHash(
	ALG_ID Algid,
	HCRYPTKEY hKey,
	DWORD dwFlags,
	HCRYPTHASH *phHash
	)
{
	//���صľ��ָ�벻��Ϊ��
	if(phHash == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//�����ʼֵ
	*phHash = NULL;

	//�Ƿ�Ϊ֧�ֵ�HASH�㷨
	if(!::IsSupportHashAlgId(Algid)){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}
	if(Algid == CALG_SHA)
		TRACE_LINE("\n��ϣ�㷨��ʶΪ CALG_SHA\n");
	else if(Algid == CALG_MD5)
		TRACE_LINE("\n��ϣ�㷨��ʶΪ CALG_MD5\n");
	else
		TRACE_LINE("\n��ϣ�㷨��ʶΪ CALG_SSL3_SHAMD5\n");

	//��hKey����Ϊ0
	if(hKey != NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	//��dwFlags,SDK����û�ж����κ�ֵ,��Ҫ�����Ϊ0
	if(dwFlags != 0){
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}

	//����һ��HASH����
	CCSPHashObject* pHashObject = new CCSPHashObject(Algid);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}
	//���´�����HASH�����������
	m_arHashObjects.Add(pHashObject);
	//����HASH���
	*phHash = pHashObject->GetHandle();

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		����һ��HASH����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTHASH hHash	�����ٵ�HASH����
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::DestroyHash(
	HCRYPTHASH hHash
	)
{
	//����ָ����HASH����
	CCSPHashObject* pHashObject = NULL;
	for(int i = 0; i < m_arHashObjects.GetSize(); i++){
		pHashObject = m_arHashObjects.GetAt(i);
		if(pHashObject->GetHandle() == hHash){
			//�ȴ�������ɾ��,��ɾ��ʵ�ʶ���
			m_arHashObjects.RemoveAt(i);
			delete pHashObject;

			return TRUE;
		}
	}

	//�Ҳ���ָ����HASH����
	SETLASTERROR(NTE_BAD_HASH);
	return FALSE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		����һ����ָ��HASH������ͬ��HASH����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTHASH hHash			ԴHASH������
//		DWORD *pdwReserved			����
//		DWORD dwFlags				��־
//		HCRYPTHASH *phHash			�²�����HASH������
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::DuplicateHash(
	HCRYPTHASH hHash,
	DWORD *pdwReserved,
	DWORD dwFlags,
	HCRYPTHASH *phHash
	)
{
	//pdwReserved����ΪNULL,dwFlags����Ϊ0,���صľ��ָ�벻��Ϊ��
	if(pdwReserved != NULL || dwFlags != 0 || phHash == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//�ȸ����ʼֵ
	*phHash = NULL;

	//����ָ����ԴHASH����
	CCSPHashObject* pSourceHashObject = GetHashObjectByHandle(hHash);
	if(pSourceHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	//����һ�µ�HASH����,�㷨��ʶ��ԴHASH����ͬ
	CCSPHashObject* pDuplicateHashObject = new CCSPHashObject(
		pSourceHashObject->GetAlgId()
		);
	if(pDuplicateHashObject == NULL){
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}

	//����HASH����
	BOOL bRetVal = pDuplicateHashObject->Duplicate(
		pdwReserved, dwFlags, pSourceHashObject
		);

	//����ɹ��򷵻��²�����HASH����ľ���������������
	if(bRetVal){
		*phHash = pDuplicateHashObject->GetHandle();
		m_arHashObjects.Add(pDuplicateHashObject);
	}
	//������ɾ��.�ڸú����ڲ���������LastError,
	//�������治������
	else
		delete pDuplicateHashObject;

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡHASH����Ĳ���
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTHASH hHash		HASH����ľ��
//		DWORD dwParam			��������
//		BYTE *pbData			��������
//		DWORD *pdwDataLen		�������ݳ���
//		DWORD dwFlags			��־
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::GetHashParam(
	HCRYPTHASH hHash,
	DWORD dwParam,
	BYTE *pbData,
	DWORD *pdwDataLen,
	DWORD dwFlags
	)
{
	//�Ȳ���ָ����HASH����
	CCSPHashObject* pHashObject = GetHashObjectByHandle(hHash);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	return pHashObject->GetParam(dwParam, pbData, pdwDataLen, dwFlags);
}

//-------------------------------------------------------------------
//	���ܣ�
//		����HASH����Ĳ���
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTHASH hHash		HASH����ľ��
//		DWORD dwParam			��������
//		BYTE *pbData			��������
//		DWORD dwFlags			��־
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::SetHashParam(
	HCRYPTHASH hHash,
	DWORD dwParam,
	BYTE *pbData,
	DWORD dwFlags
	)
{
	//�Ȳ���ָ����HASH����
	CCSPHashObject* pHashObject = GetHashObjectByHandle(hHash);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	return pHashObject->SetParam(dwParam, pbData, dwFlags);
}

//-------------------------------------------------------------------
//	���ܣ�
//		��һ�����ݸ�HASH�������HASHֵ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTHASH hHash		HASH����ľ��
//		CONST BYTE *pbData		����
//		DWORD dwDataLen			���ݵĳ���
//		DWORD dwFlags			��־
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::HashData(
	HCRYPTHASH hHash,
	CONST BYTE *pbData,
	DWORD dwDataLen,
	DWORD dwFlags
	)
{
	//�Ȳ���ָ����HASH����
	CCSPHashObject* pHashObject = GetHashObjectByHandle(hHash);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	return pHashObject->HashData(pbData, dwDataLen, dwFlags);
}

//-------------------------------------------------------------------
//	���ܣ�
//		��һ������Կ����HASH�������HASHֵ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTHASH hHash	HASH������
//		HCRYPTKEY hKey		��Կ������
//		DWORD dwFlags		��־
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::HashSessionKey(
	HCRYPTHASH hHash,
	HCRYPTKEY hKey,
	DWORD dwFlags
	)
{
	//����ָ����HASH����
	CCSPHashObject* pHashObject = GetHashObjectByHandle(hHash);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}
	
	//����ָ������Կ����
	CCSPKey* pKeyObject = GetKeyObjectByHandle(hKey);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	return pHashObject->HashSessionKey(pKeyObject, dwFlags);;
}

//-------------------------------------------------------------------
//	���ܣ�
//		ǩ��
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTHASH hHash		HASH������
//		DWORD dwKeySpec			ָ������Կ��
//		LPCWSTR sDescription	������
//		DWORD dwFlags			��־
//		BYTE *pbSignature		ǩ��
//		DWORD *pdwSigLen		ǩ���ĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::SignHash(
	HCRYPTHASH hHash,
	DWORD dwKeySpec,
	LPCWSTR sDescription,
	DWORD dwFlags,
	BYTE *pbSignature,
	DWORD *pdwSigLen
	)
{
	//����ָ����HASH����
	CCSPHashObject* pHashObject = GetHashObjectByHandle(hHash);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	//����˽Կ����
	CCSPKey* pPrivateKey = GetKeyPairObjectByAlgId(KeyPairTypeToAlgid(dwKeySpec));
	if(pPrivateKey == NULL){
		SETLASTERROR(NTE_NO_KEY);
		return FALSE;
	}

	//��˽Կǩ��
	return pPrivateKey->SignHash(pHashObject, sDescription, dwFlags, pbSignature, pdwSigLen);
}

//-------------------------------------------------------------------
//	���ܣ�
//		��֤
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTHASH hHash		HASH������
//		CONST BYTE pbSignature	ǩ��
//		DWORD dwSigLen			ǩ���ĳ���
//		HCRYPTKEY hPubKey		��֤�Ĺ�Կ
//		LPCWSTR sDescription	������
//		DWORD dwFlags			��־
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::VerifySignature(
	HCRYPTHASH hHash,
	CONST BYTE *pbSignature,
	DWORD dwSigLen,
	HCRYPTKEY hPubKey,
	LPCWSTR sDescription,
	DWORD dwFlags
	)
{
	//����ָ����HASH����
	CCSPHashObject* pHashObject = GetHashObjectByHandle(hHash);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	//���ҹ�Կ����
	CCSPKey* pPublicKey = GetKeyObjectByHandle(hPubKey);
	if(pPublicKey == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	//�ù�Կ��֤
	return pPublicKey->VerifySignature(pHashObject, pbSignature, dwSigLen, sDescription, dwFlags);
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ɻָ�ǩ��
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		DWORD dwKeySpec			ָ������Կ��
//		LPBYTE pbData			����
//		DWORD dwDataLen			���ݳ���
//		DWORD dwFlags			��־
//		BYTE *pbSignature		ǩ��
//		DWORD *pdwSigLen		ǩ���ĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::SignRecover(
	DWORD dwKeySpec, 
	LPBYTE pbData,
	DWORD dwDataLen,
	DWORD dwFlags,
	LPBYTE pbSignature,     
	LPDWORD pdwSigLen       
	)
{
	//����˽Կ����
	CCSPKey* pPrivateKey = GetKeyPairObjectByAlgId(KeyPairTypeToAlgid(dwKeySpec));
	if(pPrivateKey == NULL){
		SETLASTERROR(NTE_NO_KEY);
		return FALSE;
	}

	return pPrivateKey->SignRecover(pbData, dwDataLen, dwFlags, pbSignature, pdwSigLen);
}

//-------------------------------------------------------------------
//	���ܣ�
//		��֤��ԭ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		CONST LPBYTE pbSignatureǩ��
//		DWORD dwSigLen			ǩ���ĳ���
//		HCRYPTKEY hPubKey		��֤�Ĺ�Կ
//		DWORD dwFlags			��־
//		LPBYTE pbData			��֤��ԭ�������
//		LPDWORD pdwDataLen		��֤��ԭ�����ݵĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::VerifyRecover(
	CONST LPBYTE pbSignature,  
	DWORD dwSigLen,     
	HCRYPTKEY hPubKey,
	DWORD dwFlags,
	LPBYTE pbData,
	LPDWORD pdwDataLen
	)
{
	//���ҹ�Կ����
	CCSPKey* pPublicKey = GetKeyObjectByHandle(hPubKey);
	if(pPublicKey == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	return pPublicKey->VerifyRecover(pbSignature, dwSigLen, dwFlags, pbData, pdwDataLen);
}

BOOL 
CCSPKeyContainer::RSARawEncrypt(
	HCRYPTKEY hKey,
	LPBYTE pbInData,
	DWORD dwInDataLen,
	LPBYTE pbOutData,
	LPDWORD pdwOutDataLen
	)
{
	//���ҹ�Կ����
	CCSPKey* pPublicKey = GetKeyObjectByHandle(hKey);
	if(pPublicKey == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	return pPublicKey->RSARawEncrypt(pbInData, dwInDataLen, pbOutData, pdwOutDataLen);
}


BOOL 
CCSPKeyContainer::RSARawDecrypt(
	HCRYPTKEY hKey,
	LPBYTE pbInData,
	DWORD dwInDataLen,
	LPBYTE pbOutData,
	LPDWORD pdwOutDataLen
	)
{
	//����˽Կ����
	CCSPKey* pPrivateKey = GetKeyPairObjectByHandle(hKey);
	if(pPrivateKey == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	return pPrivateKey->RSARawDecrypt(pbInData, dwInDataLen, pbOutData, pdwOutDataLen);
}
