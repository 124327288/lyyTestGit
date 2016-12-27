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
//	功能：
//		构造函数
//
//	返回：
//		无
//
//  参数：
//		CTYCSP* pCSPObject		CSP对象
//		LPCTSTR lpszName		名字
//		BOOL bInitOpen			创建时是否打开
//
//  说明：
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
CCSPKeyContainer::~CCSPKeyContainer()
{
	if(m_szName != NULL){
		delete m_szName;
		m_szName = NULL;
	}
	DeleteAllObjects();	
}

//-------------------------------------------------------------------
//	功能：
//		打开Key Container
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
CCSPKeyContainer::Open()
{
	m_bOpened = TRUE;
	m_bReleased = FALSE;
}

//-------------------------------------------------------------------
//	功能：
//		增加引用计数
//
//	返回：
//		当前引用计数
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
DWORD
CCSPKeyContainer::AddRef()
{
	//释放标记设置为FALSE
	m_bReleased = FALSE;

	m_dwRefCount++;
	return m_dwRefCount;
}

//-------------------------------------------------------------------
//	功能：
//		释放Key Container
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
DWORD
CCSPKeyContainer::Release()
{
	m_dwRefCount--;
	if(0 == m_dwRefCount){
		//删除过程密钥和HASH对象，但保留密钥对
		DeleteHashObjects();
		DeleteSessionKeyObjects();

		m_bOpened = FALSE;
		m_bReleased = TRUE;
	}

	return m_dwRefCount;
}

//-------------------------------------------------------------------
//	功能：
//		删除所有的对象
//
//	返回：
//		无
//
//  参数：
//		BOOL bDestroyOnToken	是否从卡中销毁
//
//  说明：
//		并不会从卡中删除数据
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
//	功能：
//		删除HASH对象
//
//	返回：
//		无
//
//  参数：
//		BOOL bDestroyOnToken	是否从卡中销毁
//
//  说明：
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
//	功能：
//		删除过程密钥对象
//
//	返回：
//		无
//
//  参数：
//		BOOL bDestroyOnToken	是否从卡中销毁
//
//  说明：
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
//	功能：
//		删除密钥对对象
//
//	返回：
//		无
//
//  参数：
//		BOOL bDestroyOnToken	是否从卡中销毁
//
//  说明：
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
//	功能：
//		销毁指定算法标识的密钥对
//
//	返回：
//		无
//
//  参数：
//		ALG_ID algId		算法标识
//
//  说明：
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
//	功能：
//		通过句柄获取HASH对象
//
//	返回：
//		HASH对象指针
//
//  参数：
//		HCRYPTHASH hHash	HASH名柄
//
//  说明：
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
//	功能：
//		通过句柄获取密钥对对象
//
//	返回：
//		KEY对象指针
//
//  参数：
//		HCRYPTKEY hKey		KEY名柄
//
//  说明：
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
			//判断密钥句柄是否为非法的                                                         
			if(!pKeyPair->IsHandleValid())
				return NULL;

			return pKeyPair;
		}
	}

	return NULL;
}

//-------------------------------------------------------------------
//	功能：
//		获取指定类型的密钥对
//
//	返回：
//		KEY 对象指针
//
//  参数：
//		ALG_ID algId	密钥对类型
//
//  说明：
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
//	功能：
//		判断是否已存在指定算法标识的密钥对
//
//	返回：
//		TRUE:存在		FALSE:不存在
//
//  参数：
//		ALG_ID algId	算法标识
//
//  说明：
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
//	功能：
//		判断是否有受保护的密钥对
//
//	返回：
//		TRUE：有		FALSE：没有
//
//  参数：
//		无
//
//  说明：
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
//	功能：
//		通过句柄获取过程密钥对象
//
//	返回：
//		KEY对象指针
//
//  参数：
//		HCRYPTKEY hKey		KEY名柄
//
//  说明：
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
//	功能：
//		通过句柄获取密钥对对象
//
//	返回：
//		KEY对象指针
//
//  参数：
//		HCRYPTKEY hKey		KEY名柄
//
//  说明：
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
//	功能：
//		根据算法标识产生密钥对象
//
//	返回：
//		密钥对象指针
//
//  参数：
//		ALG_ID	algId		算法标识
//		BOOL bIsPublicKey	是否为公钥对象
//
//  说明：
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
		TRACE_LINE("\n创建RC2密钥\n");
		pKeyObject = new CCSPRc2Key(this, algId, FALSE);
		break;
	case CALG_RC4:
		TRACE_LINE("\n创建RC4密钥\n");
		pKeyObject = new CCSPRc4Key(this, algId, FALSE);
		break;
	case CALG_DES:
		TRACE_LINE("\n创建DES密钥\n");
		pKeyObject = new CCSPDesKey(this, algId, FALSE);
		break;
	case CALG_3DES_112:
		TRACE_LINE("\n创建2DES密钥\n");
		pKeyObject = new CCSP2DesKey(this, algId, FALSE);
		break;
	case CALG_3DES:
		TRACE_LINE("\n创建3DES密钥\n");
		pKeyObject = new CCSP3DesKey(this, algId, FALSE);
		break;
	case CALG_RSA_SIGN:
	case CALG_RSA_KEYX:
		if(bIsPublicKey){
			if(algId == CALG_RSA_SIGN)
				TRACE_LINE("\n创建RSA签名密钥对\n");
			else
				TRACE_LINE("\n创建RSA签名公钥\n");

			pKeyObject = new CCSPRsaPuk(this, algId, FALSE);
		}
		else{
			if(algId == CALG_RSA_SIGN)
				TRACE_LINE("\n创建RSA交换密钥对\n");
			else
				TRACE_LINE("\n创建RSA交换公钥\n");

			pKeyObject = new CCSPRsaPrk(this, algId, TRUE);
		}
		break;
	}
	////////////////////////////////////////////////////////
	//下面的算法ID wincrypt.h里没有定义。
	if (algId == g_dwSSF33Algid)//CALG_SSF33
	{	
		TRACE_LINE("\n创建SSF33密钥\n");
		pKeyObject = new CCSPSSF33Key(this, algId, FALSE);
	}
	else if (algId == g_dwSCB2Algid)//CALG_SCB2
	{
		TRACE_LINE("\n创建SCB2密钥\n");
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
//	功能：
//		复制并新建一个过程密钥对象
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		CCSPKey* pSource		源对象
//		CCSPKey*& pDuplicate	目标对象
//
//  说明：
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
//	功能：
//		从卡中载入密钥对
//
//	返回：
//		无
//
//  参数：
//		CONST BYTE* pDERStr		密钥对的DER编码 
//		DWORD dwDERLen			DER编码的长度
//
//  说明：
//-------------------------------------------------------------------
void
CCSPKeyContainer::LoadKeyPairs(
	BYTE* pDERStr, 
	ULONG ulDERLen
	)
{
	if(pDERStr == NULL)
		return;

	//第一个是交换密钥对
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

	//第二个是签名密钥对
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
//	功能：
//		设置Key Container对象的在卡片上的创建索引
//
//	返回：
//		无
//
//  参数：
//		int nIndex	索引值
//
//  说明：
//-------------------------------------------------------------------
void 
CCSPKeyContainer::SetTokenIndex(
	int nIndex
	)
{
	m_nIndexOnToken = nIndex; 

	//同是更改所有密钥的索引
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
//	功能：
//		在卡上创建
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		int nIndex		在卡中的创建索引
//
//  说明：
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
	//留出两对密钥的空挡
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
	//多写两个字节00 00作为结尾标志
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
//	功能：
//		在卡中删除
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
	
	//直接置删除标记
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
//	功能：
//		Generates a random cryptographic key or key pair.
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		ALG_ID Algid			算法标识
//		DWORD dwFlags			标志
//		HCRYPTKEY* phKey		创建的密钥句柄
//
//  说明：
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

	//参数检测
	if(phKey == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//赋予初始值
	*phKey = NULL;

	//是否支持该算法
	PROV_ENUMALGS_EX info;
	info.aiAlgid = idAlg;
	if(!::GetAlgInfo(info)){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}

	//检测密钥长度
	DWORD dwKeyBitLen = HIWORD(dwFlags);
	//未指定则用缺省值,否则判断是否在范围内
	if(dwKeyBitLen == 0)
		dwKeyBitLen = info.dwDefaultLen;
	else{
		if(dwKeyBitLen < info.dwMinLen || dwKeyBitLen > info.dwMaxLen){
			SETLASTERROR(NTE_BAD_FLAGS );
			return FALSE;
		}
		//必须是8的整数倍
		if(dwKeyBitLen%8 != 0){
			SETLASTERROR(NTE_BAD_FLAGS);
			return FALSE;
		}
	}
	TRACE_LINE("\n密钥长度为 %d\n", dwKeyBitLen);
	
	//不能是HASH算法的ID
	if(GET_ALG_CLASS(idAlg) == ALG_CLASS_HASH){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}

	//是否产生密钥对
	BOOL bIsKeyPair = ::IsSupportKeyPairAlgId(idAlg);
	//对于密钥对作额外检测
	if(bIsKeyPair){
		//An application cannot create new key pairs if no key container 
		//is currently open. This can happen if CRYPT_VERIFYCONTEXT was set 
		//in the CPAcquireContext call. If a key cannot be created, the 
		//NTE_PERM error code is returned.
		if(!IsOpened()){
			SETLASTERROR(NTE_PERM);
			return FALSE;
		}

/*		//对每一种类型的密钥对,只能存储一对
		if(IsKeyPairExist(idAlg)){
			SETLASTERROR(NTE_EXISTS);
			return FALSE;
		}
*/
		DestroyKeyPair(idAlg);

		//如果需要保护,则需验证PIN码
		if(dwFlags & CRYPT_USER_PROTECTED){
			if(!m_pCSPObject->IsLogin()){
				SETLASTERROR(NTE_PERM);
				return FALSE;
			}
		}
	}

	//创建空的密钥对象
	CCSPKey* pKeyObject = CreateKeyObjectByAlgId(idAlg);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}
	//创建密钥内容
	BOOL bRetVal = pKeyObject->Create(dwKeyBitLen, dwFlags);

	//成功则将其加入链表
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

		//返回密钥句柄
		*phKey = pKeyObject->GetHandle();
	}
	//否则删除
	else{
		delete pKeyObject;
		SETLASTERROR(NTE_FAIL);
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		Generates a cryptographic session key using a hash of base data
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		ALG_ID Algid				算法标识
//		HCRYPTHASH hBaseData		基数据
//		DWORD dwFlags				标志
//		HCRYPTKEY *phKey			产生的密钥句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::DeriveKey(
	ALG_ID Algid,
	HCRYPTHASH hBaseData,
	DWORD dwFlags,
	HCRYPTKEY *phKey
	)
{
	//参数检测
	if(phKey == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//赋予初始值
	*phKey = NULL;

	//是否支持该算法
	PROV_ENUMALGS_EX info;
	info.aiAlgid = Algid;
	if(!::GetAlgInfo(info)){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}
	
	//检测密钥长度
	DWORD dwKeyBitLen = HIWORD(dwFlags);
	//未指定则用缺省值,否则判断是否在范围内
	if(dwKeyBitLen == 0)
		dwKeyBitLen = info.dwDefaultLen;
	else{
		if(dwKeyBitLen < info.dwMinLen || dwKeyBitLen > info.dwMaxLen){
			SETLASTERROR(NTE_BAD_FLAGS );
			return FALSE;
		}
		//必须是8的整数倍
		if(dwKeyBitLen%8 != 0){
			SETLASTERROR(NTE_BAD_FLAGS);
			return FALSE;
		}
	}
	TRACE_LINE("\n密钥长度为 %d\n", dwKeyBitLen);

	//不能是HASH的算法ID
	if(GET_ALG_CLASS(Algid) == ALG_CLASS_HASH){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}

	//不能是密钥对的算法ID
	if(::IsSupportKeyPairAlgId(Algid)){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}

	//查找HASH对象
	CCSPHashObject* pHashObject = GetHashObjectByHandle(hBaseData);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	//创建空的密钥对象
	CCSPKey* pKeyObject = CreateKeyObjectByAlgId(Algid);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}
	//创建密钥内容
	BOOL bRetVal = pKeyObject->DeriveKey(dwKeyBitLen, pHashObject, dwFlags);

	//成功则将其加入链表,否则删除
	if(bRetVal){
		m_arSessionKeys.Add(pKeyObject);
		//返回密钥句柄
		*phKey = pKeyObject->GetHandle();
	}
	else{
		delete pKeyObject;
		SETLASTERROR(NTE_FAIL);
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		Makes an exact copy of a key. Some keys have an associated 
//	state such as an initialization vector or a salt value. If a key 
//	with an associated state is duplicated, the associated state is 
//	also copied.
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTKEY hKey			源密钥句柄
//		DWORD *pdwReserved		保留值
//		DWORD dwFlags			标志
//		HCRYPTKEY* phKey		产生的密钥句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::DuplicateKey(
	HCRYPTKEY hKey,
	DWORD *pdwReserved,
	DWORD dwFlags,
	HCRYPTKEY* phKey
	)
{
	//参数检测
	if(pdwReserved != NULL && dwFlags != 0){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if(phKey == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//赋予初始值
	*phKey = NULL;
	
	//查找源密钥对象
	CCSPKey* pSourceKeyObject = GetSessionKeyObjectByHandle(hKey);
	if(pSourceKeyObject == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

/*	//密钥对不能被复制
	if(::IsSupportKeyPairAlgId(pSourceKeyObject->GetAlgId()) &&
		pSourceKeyObject->IsPermanent()
		)
	{
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}*/

	//复制
	CCSPKey* pDuplicateKeyObject = NULL;
	if(!DuplicateSessionKeyObject(pSourceKeyObject, pDuplicateKeyObject)){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}
	else{
		m_arSessionKeys.Add(pDuplicateKeyObject);
		//返回密钥句柄
		*phKey = pDuplicateKeyObject->GetHandle();
		
		return TRUE;
	}
}

//-------------------------------------------------------------------
//	功能：
//		Releases the handle referenced by the hKey parameter. After 
//	a key handle has been released, it becomes invalid and can no 
//	longer be used.
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTKEY hKey		密钥句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::DestroyKey(
	HCRYPTKEY hKey
	)
{
	//在删除前先将其从链表中删除
	CCSPKey* pKeyObject = NULL;

	//先在过程密钥中查找
	for(int i = 0; i < m_arSessionKeys.GetSize(); i++){
		pKeyObject = m_arSessionKeys.GetAt(i);
		if(pKeyObject->GetHandle() == hKey){
			m_arSessionKeys.RemoveAt(i);
			delete pKeyObject;
			return TRUE;
		}
	}

	//后在密钥对中查找
	for(i = 0; i < m_arKeyPair.GetSize(); i++){
		pKeyObject = m_arKeyPair.GetAt(i);
		if(pKeyObject->GetHandle() == hKey){
			pKeyObject->ValidateHandle(FALSE);
//			m_arKeyPair.RemoveAt(i);
//			delete pKeyObject;
			return TRUE;
		}
	}

	//没有找到
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}

//-------------------------------------------------------------------
//	功能：
//		Retrieves data that governs the operations of a key.
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTKEY hKey			密钥对象句柄
//		DWORD dwParam			参数类型
//		BYTE *pbData			参数数据
//		DWORD *pdwDataLen		参数数据长度
//		DWORD dwFlags			标志
//
//  说明：
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
	//查找密钥对象
	CCSPKey* pKeyObject = GetKeyObjectByHandle(hKey);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	//获取参数
	return pKeyObject->GetParam(dwParam, pbData, pdwDataLen, dwFlags);
}

//-------------------------------------------------------------------
//	功能：
//		Customizes the operations of a key.
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTKEY hKey			密钥对象句柄
//		DWORD dwParam			参数类型
//		BYTE *pbData			参数数据
//		DWORD dwFlags			标志
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::SetKeyParam(
	HCRYPTKEY hKey,
	DWORD dwParam,
	BYTE *pbData,
	DWORD dwFlags
	)
{
	//查找密钥对象
	CCSPKey* pKeyObject = GetKeyObjectByHandle(hKey);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	//设置参数
	return pKeyObject->SetParam(dwParam, pbData, dwFlags);
}

//-------------------------------------------------------------------
//	功能：
//		Transfers a cryptographic key from a key BLOB to a CSP key 
//	container
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		CONST BYTE *pbData		Key BLOB 数据
//		DWORD dwDataLen			Key BLOB 数据的长度
//		HCRYPTKEY hImpKey		导入密钥的句柄
//		DWORD dwFlags			标志
//		HCRYPTKEY *phKey		产生的密钥的句柄
//
//  说明：
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
	//参数检测
	if(phKey == NULL || pbData == NULL || 
		dwDataLen <= sizeof(BLOBHEADER)){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//赋予初始值
	*phKey = NULL;
	
	//检测KEY BLOB的有效性
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

	//对于密钥对作额外检测
	if(bIsKeyPair){
		//An application cannot create new key pairs if no key container 
		//is currently open. This can happen if CRYPT_VERIFYCONTEXT was set 
		//in the CPAcquireContext call. If a key cannot be created, the 
		//NTE_PERM error code is returned.
//		if(!IsOpened()){
//			SETLASTERROR(NTE_PERM);
//			return FALSE;
//		}

/*		//对每一种类型的密钥对,只能存储一对
		if(IsKeyPairExist(pHeader->aiKeyAlg)){
			SETLASTERROR(NTE_EXISTS);
			return FALSE;
		}
*/
		DestroyKeyPair(pHeader->aiKeyAlg);
	}

	//获取导入密钥对象
	CCSPKey* pImpKeyObject = NULL;
	if(hImpKey != NULL){
		pImpKeyObject = GetKeyObjectByHandle(hImpKey);
		if(pImpKeyObject == NULL){
			SETLASTERROR(NTE_BAD_KEY);
			return FALSE;
		}
	}

	//创建空的密钥对象
	CCSPKey* pKeyObject = CreateKeyObjectByAlgId(pHeader->aiKeyAlg, !bIsKeyPair);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_FAIL);
		return FALSE;
	}
	//创建密钥内容
	BOOL bRetVal = pKeyObject->Import(pbData, dwDataLen, pImpKeyObject, dwFlags);

	//成功则将其加入链表
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
		//返回密钥句柄
		*phKey = pKeyObject->GetHandle();
	}
	//否则删除
	else{
		delete pKeyObject;
		SETLASTERROR(NTE_FAIL);
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		Securely exports cryptographic keys from a CSP's key container
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTKEY hKey			被导出的密钥对象的句柄
//		HCRYPTKEY hExpKey		导出密钥对象的句柄
//		DWORD dwBlobType		Key BLOB的类型
//		DWORD dwFlags			标志
//		BYTE *pbData			Key BLOB数据
//		DWORD *pdwDataLen		Key BLOL数据的长度
//
//  说明：
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
	//获取被导出密钥对象
	CCSPKey* pKeyObject = GetKeyObjectByHandle(hKey);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	//获取导出密钥对象
	CCSPKey* pExpKeyObject = NULL;
	if(hExpKey != NULL){
		pExpKeyObject = GetKeyObjectByHandle(hExpKey);
		if(pExpKeyObject == NULL){
			SETLASTERROR(NTE_BAD_KEY);
			return FALSE;
		}
	}

	//导出密钥
	return pKeyObject->Export(pExpKeyObject, dwBlobType, dwFlags, pbData, pdwDataLen);
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
			bRetVal = m_pCSPObject->SendCommand(cCommand, sizeof(cCommand), pData + i*bPer, &dwRespLen);
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
//		Retrieves the handle of one of the permanent key pairs in the 
//	hProv key container.
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		DWORD dwKeySpec			密钥对类型
//		HCRYPTKEY *phUserKey	密钥对句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::GetUserKey(
	DWORD dwKeySpec,
	HCRYPTKEY *phUserKey
	)
{
	//返回句柄的指针不能为空
	if(phUserKey == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//赋予初值
	*phUserKey = NULL;
	
	//查找指定类型的密钥对
	CCSPKey* pKeyPair = GetKeyPairObjectByAlgId(KeyPairTypeToAlgid(dwKeySpec));
	if(pKeyPair == NULL){
		SETLASTERROR(NTE_NO_KEY);
		return FALSE;
	}

	pKeyPair->ValidateHandle(TRUE);
	//返回密钥对句柄
	*phUserKey = pKeyPair->GetHandle();

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		Encrypts data. Optionally, the application can specify that 
//	a hash of the paintext data is to be generated.
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTKEY hKey			加密密钥对象的句柄
//		HCRYPTHASH hHash		HASH对象句柄
//		BOOL Final				是否为最后一块数据
//		DWORD dwFlags			标志
//		BYTE *pbData			明文数据
//		DWORD *pdwDataLen		明文数据的长度
//		DWORD dwBufLen			载有明文数据缓冲的总长度
//
//  说明：
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
	//查找密钥对象
	CCSPKey* pKeyObject = GetKeyObjectByHandle(hKey);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}
	
	//查找HASH对象
	CCSPHashObject* pHashObject = NULL;
	if(hHash != NULL){
		pHashObject = GetHashObjectByHandle(hHash);
		if(pHashObject == NULL){
			SETLASTERROR(NTE_BAD_HASH);
			return FALSE;
		}
	}

	//加密
	return pKeyObject->Encrypt(pHashObject, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

//-------------------------------------------------------------------
//	功能：
//		Decrypts data previously encrypted with the CPEncrypt function. 
//	Optionally, the application can specify that the decrypted data 
//	be hashed.
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTKEY hKey			解密密钥对象的句柄
//		HCRYPTHASH hHash		HASH对象句柄
//		BOOL Final				是否为最后一块数据
//		DWORD dwFlags			标志
//		BYTE *pbData			密文数据
//		DWORD *pdwDataLen		密文数据的长度
//
//  说明：
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
	//查找密钥对象
	CCSPKey* pKeyObject = GetKeyObjectByHandle(hKey);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}
	
	//查找HASH对象
	CCSPHashObject* pHashObject = NULL;
	if(hHash != NULL){
		pHashObject = GetHashObjectByHandle(hHash);
		if(pHashObject == NULL){
			SETLASTERROR(NTE_BAD_HASH);
			return FALSE;
		}
	}

	//解密
	return pKeyObject->Decrypt(pHashObject, Final, dwFlags, pbData, pdwDataLen);
}

//-------------------------------------------------------------------
//	功能：
//		产生一个空的HASH对象
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		ALG_ID Algid			算法标识		
//		HCRYPTKEY hKey			MAC用的密钥句柄
//		DWORD dwFlags			标志
//		HCRYPTHASH *phHash		返回产生的HASH对象句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::CreateHash(
	ALG_ID Algid,
	HCRYPTKEY hKey,
	DWORD dwFlags,
	HCRYPTHASH *phHash
	)
{
	//返回的句柄指针不能为空
	if(phHash == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//赋予初始值
	*phHash = NULL;

	//是否为支持的HASH算法
	if(!::IsSupportHashAlgId(Algid)){
		SETLASTERROR(NTE_BAD_ALGID);
		return FALSE;
	}
	if(Algid == CALG_SHA)
		TRACE_LINE("\n哈希算法标识为 CALG_SHA\n");
	else if(Algid == CALG_MD5)
		TRACE_LINE("\n哈希算法标识为 CALG_MD5\n");
	else
		TRACE_LINE("\n哈希算法标识为 CALG_SSL3_SHAMD5\n");

	//对hKey必须为0
	if(hKey != NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	//对dwFlags,SDK现在没有定义任何值,故要求必须为0
	if(dwFlags != 0){
		SETLASTERROR(NTE_BAD_FLAGS);
		return FALSE;
	}

	//创建一个HASH对象
	CCSPHashObject* pHashObject = new CCSPHashObject(Algid);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}
	//将新创建的HASH对象加入链表
	m_arHashObjects.Add(pHashObject);
	//返回HASH句柄
	*phHash = pHashObject->GetHandle();

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		销毁一个HASH对象
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTHASH hHash	待销毁的HASH对象
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::DestroyHash(
	HCRYPTHASH hHash
	)
{
	//查找指定的HASH对象
	CCSPHashObject* pHashObject = NULL;
	for(int i = 0; i < m_arHashObjects.GetSize(); i++){
		pHashObject = m_arHashObjects.GetAt(i);
		if(pHashObject->GetHandle() == hHash){
			//先从链表中删除,再删除实际对象
			m_arHashObjects.RemoveAt(i);
			delete pHashObject;

			return TRUE;
		}
	}

	//找不到指定的HASH对象
	SETLASTERROR(NTE_BAD_HASH);
	return FALSE;
}

//-------------------------------------------------------------------
//	功能：
//		产生一个与指定HASH对象相同的HASH对象
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTHASH hHash			源HASH对象句柄
//		DWORD *pdwReserved			保留
//		DWORD dwFlags				标志
//		HCRYPTHASH *phHash			新产生的HASH对象句柄
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::DuplicateHash(
	HCRYPTHASH hHash,
	DWORD *pdwReserved,
	DWORD dwFlags,
	HCRYPTHASH *phHash
	)
{
	//pdwReserved必须为NULL,dwFlags必须为0,返回的句柄指针不能为空
	if(pdwReserved != NULL || dwFlags != 0 || phHash == NULL){
		SETLASTERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	//先赋予初始值
	*phHash = NULL;

	//查找指定的源HASH对象
	CCSPHashObject* pSourceHashObject = GetHashObjectByHandle(hHash);
	if(pSourceHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	//创建一新的HASH对象,算法标识与源HASH对象同
	CCSPHashObject* pDuplicateHashObject = new CCSPHashObject(
		pSourceHashObject->GetAlgId()
		);
	if(pDuplicateHashObject == NULL){
		SETLASTERROR(NTE_NO_MEMORY);
		return FALSE;
	}

	//复制HASH对象
	BOOL bRetVal = pDuplicateHashObject->Duplicate(
		pdwReserved, dwFlags, pSourceHashObject
		);

	//如果成功则返回新产生的HASH对象的句柄将其加入链表中
	if(bRetVal){
		*phHash = pDuplicateHashObject->GetHandle();
		m_arHashObjects.Add(pDuplicateHashObject);
	}
	//否则将其删除.在该函数内部已设置了LastError,
	//故在外面不需再设
	else
		delete pDuplicateHashObject;

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		获取HASH对象的参数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTHASH hHash		HASH对象的句柄
//		DWORD dwParam			参数类型
//		BYTE *pbData			参数数据
//		DWORD *pdwDataLen		参数数据长度
//		DWORD dwFlags			标志
//
//  说明：
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
	//先查找指定的HASH对象
	CCSPHashObject* pHashObject = GetHashObjectByHandle(hHash);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	return pHashObject->GetParam(dwParam, pbData, pdwDataLen, dwFlags);
}

//-------------------------------------------------------------------
//	功能：
//		设置HASH对象的参数
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTHASH hHash		HASH对象的句柄
//		DWORD dwParam			参数类型
//		BYTE *pbData			参数数据
//		DWORD dwFlags			标志
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::SetHashParam(
	HCRYPTHASH hHash,
	DWORD dwParam,
	BYTE *pbData,
	DWORD dwFlags
	)
{
	//先查找指定的HASH对象
	CCSPHashObject* pHashObject = GetHashObjectByHandle(hHash);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	return pHashObject->SetParam(dwParam, pbData, dwFlags);
}

//-------------------------------------------------------------------
//	功能：
//		送一组数据给HASH对象计算HASH值
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTHASH hHash		HASH对象的句柄
//		CONST BYTE *pbData		数据
//		DWORD dwDataLen			数据的长度
//		DWORD dwFlags			标志
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::HashData(
	HCRYPTHASH hHash,
	CONST BYTE *pbData,
	DWORD dwDataLen,
	DWORD dwFlags
	)
{
	//先查找指定的HASH对象
	CCSPHashObject* pHashObject = GetHashObjectByHandle(hHash);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	return pHashObject->HashData(pbData, dwDataLen, dwFlags);
}

//-------------------------------------------------------------------
//	功能：
//		将一过程密钥送往HASH对象计算HASH值
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTHASH hHash	HASH对象句柄
//		HCRYPTKEY hKey		密钥对象句柄
//		DWORD dwFlags		标志
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CCSPKeyContainer::HashSessionKey(
	HCRYPTHASH hHash,
	HCRYPTKEY hKey,
	DWORD dwFlags
	)
{
	//查找指定的HASH对象
	CCSPHashObject* pHashObject = GetHashObjectByHandle(hHash);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}
	
	//查找指定的密钥对象
	CCSPKey* pKeyObject = GetKeyObjectByHandle(hKey);
	if(pKeyObject == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	return pHashObject->HashSessionKey(pKeyObject, dwFlags);;
}

//-------------------------------------------------------------------
//	功能：
//		签名
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTHASH hHash		HASH对象句柄
//		DWORD dwKeySpec			指定的密钥对
//		LPCWSTR sDescription	描述符
//		DWORD dwFlags			标志
//		BYTE *pbSignature		签名
//		DWORD *pdwSigLen		签名的长度
//
//  说明：
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
	//查找指定的HASH对象
	CCSPHashObject* pHashObject = GetHashObjectByHandle(hHash);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	//查找私钥对象
	CCSPKey* pPrivateKey = GetKeyPairObjectByAlgId(KeyPairTypeToAlgid(dwKeySpec));
	if(pPrivateKey == NULL){
		SETLASTERROR(NTE_NO_KEY);
		return FALSE;
	}

	//用私钥签名
	return pPrivateKey->SignHash(pHashObject, sDescription, dwFlags, pbSignature, pdwSigLen);
}

//-------------------------------------------------------------------
//	功能：
//		验证
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		HCRYPTHASH hHash		HASH对象句柄
//		CONST BYTE pbSignature	签名
//		DWORD dwSigLen			签名的长度
//		HCRYPTKEY hPubKey		验证的公钥
//		LPCWSTR sDescription	描述符
//		DWORD dwFlags			标志
//
//  说明：
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
	//查找指定的HASH对象
	CCSPHashObject* pHashObject = GetHashObjectByHandle(hHash);
	if(pHashObject == NULL){
		SETLASTERROR(NTE_BAD_HASH);
		return FALSE;
	}

	//查找公钥对象
	CCSPKey* pPublicKey = GetKeyObjectByHandle(hPubKey);
	if(pPublicKey == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	//用公钥验证
	return pPublicKey->VerifySignature(pHashObject, pbSignature, dwSigLen, sDescription, dwFlags);
}

//-------------------------------------------------------------------
//	功能：
//		可恢复签名
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		DWORD dwKeySpec			指定的密钥对
//		LPBYTE pbData			数据
//		DWORD dwDataLen			数据长度
//		DWORD dwFlags			标志
//		BYTE *pbSignature		签名
//		DWORD *pdwSigLen		签名的长度
//
//  说明：
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
	//查找私钥对象
	CCSPKey* pPrivateKey = GetKeyPairObjectByAlgId(KeyPairTypeToAlgid(dwKeySpec));
	if(pPrivateKey == NULL){
		SETLASTERROR(NTE_NO_KEY);
		return FALSE;
	}

	return pPrivateKey->SignRecover(pbData, dwDataLen, dwFlags, pbSignature, pdwSigLen);
}

//-------------------------------------------------------------------
//	功能：
//		验证复原
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		CONST LPBYTE pbSignature签名
//		DWORD dwSigLen			签名的长度
//		HCRYPTKEY hPubKey		验证的公钥
//		DWORD dwFlags			标志
//		LPBYTE pbData			验证复原后的数据
//		LPDWORD pdwDataLen		验证复原后数据的长度
//
//  说明：
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
	//查找公钥对象
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
	//查找公钥对象
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
	//查找私钥对象
	CCSPKey* pPrivateKey = GetKeyPairObjectByHandle(hKey);
	if(pPrivateKey == NULL){
		SETLASTERROR(NTE_BAD_KEY);
		return FALSE;
	}

	return pPrivateKey->RSARawDecrypt(pbInData, dwInDataLen, pbOutData, pdwOutDataLen);
}
