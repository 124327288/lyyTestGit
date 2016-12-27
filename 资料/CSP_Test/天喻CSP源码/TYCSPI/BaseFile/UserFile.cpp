#include "stdafx.h"
#include "userfile.h"
#include "cspobject.h"
#include "HelperFunc.h"

//-------------------------------------------------------------------
//	功能：
//		构造函数
//
//	返回：
//		无
//
//  参数：
//		CTYCSP* pCSPObject		CSP对象
//
//  说明：
//-------------------------------------------------------------------
CUserFile::CUserFile(
	CTYCSP* pCSPObject
	)
{
	ASSERT(pCSPObject != NULL);
	m_pCSPObject = pCSPObject;
	m_nIndexOnToken = -1;
	m_szName = NULL;
	memset(m_path, 0, sizeof(m_path));
	m_hHandle = MAKE_HCRYPTPROV(pCSPObject->GetHandle(), pCSPObject->GetNextKCHandle());
	m_dwSize = 0;
	m_pbData = NULL;
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
CUserFile::~CUserFile()
{
	SetName(NULL);
	if(m_pbData != NULL){
		delete m_pbData;
		m_pbData = NULL;
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
void CUserFile::SetName(LPCTSTR szName)
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
//		从卡中载入
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		LPBYTE pbDerString
//		DWORD dwDerStringLen 
//		int nIndexOnToken
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CUserFile::LoadFromToken(
	LPBYTE pbDerString, 
	DWORD dwDerStringLen, 
	int nIndexOnToken
	)
{
	m_nIndexOnToken = nIndexOnToken;

//	30 len
//		02 len (name)
//		02 len (path)
//		02 len (size)

	ByteArray baDerString;
	MakeByteArray(pbDerString, dwDerStringLen, baDerString);

	DWORD dwTag, dwLen;
	DERDecoding(baDerString, dwTag, dwLen);
	if(dwTag != 0x30)
		return FALSE;

	//解码获取名字
	DERDecoding(baDerString, dwTag, dwLen);
	if(dwTag != 0x02)
		return FALSE;
	SetName((LPCTSTR)(baDerString.GetData()));
	baDerString.RemoveAt(0, dwLen);

	//解码获取路径
	DERDecoding(baDerString, dwTag, dwLen);
	if(dwTag != 0x02)
		return FALSE;
	memcpy(m_path, baDerString.GetData(), sizeof(m_path));
	baDerString.RemoveAt(0, dwLen);

	//解码获取真实大小
	if(baDerString.GetSize()){
		DERDecoding(baDerString, dwTag, dwLen);
		if(dwTag == 0x02){
			memcpy(&m_dwSize, baDerString.GetData(), sizeof(m_dwSize));
			baDerString.RemoveAt(0, dwLen);
		}
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		在卡中创建
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		int nIndex			索引
//		LPCTSTR lpszName	文件名
//		DWORD dwSize		文件尺寸
//		BOOL bReadAuth		读是否要权限
//		BOOL bWriteAuth		写是否要权限
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CUserFile::CreateOnToken(
	int nIndex,
	LPCTSTR lpszName,
	DWORD dwSize,
	BOOL bReadAuth, 
	BOOL bWriteAuth
	)
{
	m_pCSPObject->BeginTransaction();

	m_nIndexOnToken = nIndex;
	m_dwSize = dwSize;
	SetName(lpszName);

	BOOL bRetVal;

	//创建文件
	BYTE flag = FILETYPE_DATA | FILE_UNUSED;
	if(bReadAuth) SET_READ_NEEDAUTH(flag);
	if(bWriteAuth) SET_WRITE_NEEDAUTH(flag);
	bRetVal = m_pCSPObject->GetWorkableFile(flag, dwSize, m_path);
	if (bRetVal == FALSE){
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	//创建索引
	FILEHANDLE hFile = NULL;
	if(!m_pCSPObject->OpenFile(g_cPathTable.dodfPath, &hFile, NULL)){
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

//	DER编码
//	30 len
//		02 len (name)
//		02 len (path)
//		02 len (size)

	ByteArray baName;
	MakeByteArray((LPBYTE)m_szName, lstrlen(m_szName), baName);
	baName.Add(0x00);
	DEREncoding(0x02, baName.GetSize(), baName);

	ByteArray baPath;
	MakeByteArray(m_path, sizeof(m_path), baPath);
	DEREncoding(0x02, baPath.GetSize(), baPath);

	ByteArray baSize;
	MakeByteArray((LPBYTE)&dwSize, sizeof(dwSize), baSize);
	DEREncoding(0x02, baSize.GetSize(), baSize);

	ConnectByteArray(baName, baPath);
	ConnectByteArray(baName, baSize);

	DEREncoding(0x30, baName.GetSize(), baName);
	//多加两个0
	baName.Add(0x00), baName.Add(0x00);

	SHARE_XDF xdf;
	m_pCSPObject->GetXdf(DFTYPE_DATA, &xdf);

	DWORD dwOffset, dwLen;
	m_pCSPObject->GetOffsetFormIndex(&xdf, m_nIndexOnToken, dwOffset, dwLen);
	
	bRetVal = m_pCSPObject->WriteFile(hFile, baName.GetData(), baName.GetSize(), dwOffset);
	m_pCSPObject->CloseFile(hFile);
	
	if(bRetVal){
		xdf.ulDataLen += (baName.GetSize() - 2);
		memcpy(xdf.cContent + dwOffset, baName.GetData(), baName.GetSize());
		m_pCSPObject->SetXdf(DFTYPE_DATA, &xdf);
	}

	m_pCSPObject->EndTransaction();

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		从卡中销毁
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
CUserFile::DestroyOnToken()
{
	m_pCSPObject->BeginTransaction();

	//删除ODF文件中的索引
	FILEHANDLE hFile = NULL;
	if(!m_pCSPObject->OpenFile(g_cPathTable.dodfPath, &hFile, NULL)){
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	SHARE_XDF xdf;
	if(!m_pCSPObject->GetXdf(DFTYPE_DATA, &xdf)){
		m_pCSPObject->CloseFile(hFile);
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	DWORD dwOffset,dwLen;
	if (!m_pCSPObject->GetOffsetFormIndex(&xdf, m_nIndexOnToken, dwOffset, dwLen)){
		m_pCSPObject->CloseFile(hFile);
		m_pCSPObject->EndTransaction();
		return FALSE;
	}
	
	//直接置删除标记
	BYTE data = DESTROIED_TAG;
	if(!m_pCSPObject->WriteFile(hFile, &data, 1, dwOffset)){
		m_pCSPObject->CloseFile(hFile);
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	xdf.cContent[dwOffset] = data;
	xdf.bHasFragment = TRUE;
	m_pCSPObject->SetXdf(DFTYPE_DATA, &xdf);
	m_pCSPObject->CloseFile(hFile);

	//删除真实的文件
	BOOL bRetVal = m_pCSPObject->DeleteFile(m_path);

	m_pCSPObject->EndTransaction();

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		获取文件大小
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		LPDWORD pdwSize		文件大小
//
//  说明：
//-------------------------------------------------------------------
BOOL CUserFile::GetSize(LPDWORD pdwSize)
{
	if(pdwSize == NULL)
		return FALSE;

	//已从目录文件中获取文件大小
	if(m_dwSize != 0){
		*pdwSize = m_dwSize;
		return TRUE;
	}

	m_pCSPObject->BeginTransaction();
	
	FILEHANDLE hFile = NULL;
	BOOL bRetVal = m_pCSPObject->OpenFile(m_path, &hFile, pdwSize);
	if(bRetVal)
		m_pCSPObject->CloseFile(hFile);

	m_pCSPObject->EndTransaction();

	if(!bRetVal){
		*pdwSize = 0;
		return FALSE;
	}
	else{
		m_dwSize = *pdwSize;
		return TRUE;
	}
}

//-------------------------------------------------------------------
//	功能：
//		读取文件内容
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		DWORD dwReadLen				要读取的长度
//		LPBYTE pReadBuffer			读取的内容
//		LPDWORD pdwRealReadLen		实际读取的长度
//		DWORD dwOffset				读取偏移量
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CUserFile::Read(
	DWORD dwReadLen, 
	LPBYTE pReadBuffer, 
	LPDWORD pdwRealReadLen, 
	DWORD dwOffset
	)
{
	if(pReadBuffer == NULL || pdwRealReadLen == NULL)
		return FALSE;

	//获取文件大小
	DWORD dwFileSize;
	if(!GetSize(&dwFileSize))
		return FALSE;

	m_pCSPObject->BeginTransaction();
	
	//打开文件
	FILEHANDLE hFile = NULL;
	if(!m_pCSPObject->OpenFile(m_path, &hFile, NULL)){
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	//如果偏移量为0且读取整个文件,则将文件内容在内存在缓存起来
	BOOL bToCache = FALSE;
	if(dwReadLen + dwOffset >= dwFileSize){
		*pdwRealReadLen = dwFileSize - dwOffset;
		if(dwOffset == 0) bToCache = TRUE;
	}
	else
		*pdwRealReadLen = dwReadLen;

	BOOL bRetVal = TRUE;
	if(m_pbData){
		//如果已缓存,则直接从内存中读取
		memcpy(pReadBuffer, m_pbData + dwOffset, *pdwRealReadLen);
	}
	else{
		//读取文件内容
		bRetVal = m_pCSPObject->ReadFile(
			hFile, *pdwRealReadLen, pReadBuffer, pdwRealReadLen, dwOffset
			);
		//缓存
		if(bRetVal && bToCache){
			m_pbData = new BYTE[dwFileSize];
			if(m_pbData) memcpy(m_pbData, pReadBuffer, dwFileSize);
		}
	}

	//关闭文件
	m_pCSPObject->CloseFile(hFile);
	
	m_pCSPObject->EndTransaction();
	
	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		写数据到文件中
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		LPBYTE pWriteBuffer				写入的内容
//		DWORD dwWriteBufferLen			写入内容的大小
//		DWORD dwOffset					写入偏移量
//
//  说明：
//-------------------------------------------------------------------
BOOL 
CUserFile::Write(
	LPBYTE pWriteBuffer, 
	DWORD dwWriteBufferLen, 
	DWORD dwOffset
	)
{
	m_pCSPObject->BeginTransaction();
	
	//获取文件大小
	DWORD dwFileSize;
	if(!GetSize(&dwFileSize))
		return FALSE;

	//打开文件
	FILEHANDLE hFile = NULL;
	if(!m_pCSPObject->OpenFile(m_path, &hFile, NULL)){
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	//判断是否越界
	if(dwWriteBufferLen + dwOffset > dwFileSize){
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	//更新文件
	BOOL bRetVal = m_pCSPObject->WriteFile(
		hFile, pWriteBuffer, dwWriteBufferLen, dwOffset
		);

	//更新缓存的内容
	if(bRetVal && m_pbData)
		memcpy(m_pbData + dwOffset, pWriteBuffer, dwWriteBufferLen);

	//关闭文件
	m_pCSPObject->CloseFile(hFile);
	
	m_pCSPObject->EndTransaction();
	
	return bRetVal;
}

