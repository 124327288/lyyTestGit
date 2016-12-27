#include "stdafx.h"
#include "userfile.h"
#include "cspobject.h"
#include "HelperFunc.h"

//-------------------------------------------------------------------
//	���ܣ�
//		���캯��
//
//	���أ�
//		��
//
//  ������
//		CTYCSP* pCSPObject		CSP����
//
//  ˵����
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
CUserFile::~CUserFile()
{
	SetName(NULL);
	if(m_pbData != NULL){
		delete m_pbData;
		m_pbData = NULL;
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
//	���ܣ�
//		�ӿ�������
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		LPBYTE pbDerString
//		DWORD dwDerStringLen 
//		int nIndexOnToken
//
//  ˵����
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

	//�����ȡ����
	DERDecoding(baDerString, dwTag, dwLen);
	if(dwTag != 0x02)
		return FALSE;
	SetName((LPCTSTR)(baDerString.GetData()));
	baDerString.RemoveAt(0, dwLen);

	//�����ȡ·��
	DERDecoding(baDerString, dwTag, dwLen);
	if(dwTag != 0x02)
		return FALSE;
	memcpy(m_path, baDerString.GetData(), sizeof(m_path));
	baDerString.RemoveAt(0, dwLen);

	//�����ȡ��ʵ��С
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
//	���ܣ�
//		�ڿ��д���
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		int nIndex			����
//		LPCTSTR lpszName	�ļ���
//		DWORD dwSize		�ļ��ߴ�
//		BOOL bReadAuth		���Ƿ�ҪȨ��
//		BOOL bWriteAuth		д�Ƿ�ҪȨ��
//
//  ˵����
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

	//�����ļ�
	BYTE flag = FILETYPE_DATA | FILE_UNUSED;
	if(bReadAuth) SET_READ_NEEDAUTH(flag);
	if(bWriteAuth) SET_WRITE_NEEDAUTH(flag);
	bRetVal = m_pCSPObject->GetWorkableFile(flag, dwSize, m_path);
	if (bRetVal == FALSE){
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	//��������
	FILEHANDLE hFile = NULL;
	if(!m_pCSPObject->OpenFile(g_cPathTable.dodfPath, &hFile, NULL)){
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

//	DER����
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
	//�������0
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
//	���ܣ�
//		�ӿ�������
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
CUserFile::DestroyOnToken()
{
	m_pCSPObject->BeginTransaction();

	//ɾ��ODF�ļ��е�����
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
	
	//ֱ����ɾ�����
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

	//ɾ����ʵ���ļ�
	BOOL bRetVal = m_pCSPObject->DeleteFile(m_path);

	m_pCSPObject->EndTransaction();

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ�ļ���С
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		LPDWORD pdwSize		�ļ���С
//
//  ˵����
//-------------------------------------------------------------------
BOOL CUserFile::GetSize(LPDWORD pdwSize)
{
	if(pdwSize == NULL)
		return FALSE;

	//�Ѵ�Ŀ¼�ļ��л�ȡ�ļ���С
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
//	���ܣ�
//		��ȡ�ļ�����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		DWORD dwReadLen				Ҫ��ȡ�ĳ���
//		LPBYTE pReadBuffer			��ȡ������
//		LPDWORD pdwRealReadLen		ʵ�ʶ�ȡ�ĳ���
//		DWORD dwOffset				��ȡƫ����
//
//  ˵����
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

	//��ȡ�ļ���С
	DWORD dwFileSize;
	if(!GetSize(&dwFileSize))
		return FALSE;

	m_pCSPObject->BeginTransaction();
	
	//���ļ�
	FILEHANDLE hFile = NULL;
	if(!m_pCSPObject->OpenFile(m_path, &hFile, NULL)){
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	//���ƫ����Ϊ0�Ҷ�ȡ�����ļ�,���ļ��������ڴ��ڻ�������
	BOOL bToCache = FALSE;
	if(dwReadLen + dwOffset >= dwFileSize){
		*pdwRealReadLen = dwFileSize - dwOffset;
		if(dwOffset == 0) bToCache = TRUE;
	}
	else
		*pdwRealReadLen = dwReadLen;

	BOOL bRetVal = TRUE;
	if(m_pbData){
		//����ѻ���,��ֱ�Ӵ��ڴ��ж�ȡ
		memcpy(pReadBuffer, m_pbData + dwOffset, *pdwRealReadLen);
	}
	else{
		//��ȡ�ļ�����
		bRetVal = m_pCSPObject->ReadFile(
			hFile, *pdwRealReadLen, pReadBuffer, pdwRealReadLen, dwOffset
			);
		//����
		if(bRetVal && bToCache){
			m_pbData = new BYTE[dwFileSize];
			if(m_pbData) memcpy(m_pbData, pReadBuffer, dwFileSize);
		}
	}

	//�ر��ļ�
	m_pCSPObject->CloseFile(hFile);
	
	m_pCSPObject->EndTransaction();
	
	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		д���ݵ��ļ���
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		LPBYTE pWriteBuffer				д�������
//		DWORD dwWriteBufferLen			д�����ݵĴ�С
//		DWORD dwOffset					д��ƫ����
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
CUserFile::Write(
	LPBYTE pWriteBuffer, 
	DWORD dwWriteBufferLen, 
	DWORD dwOffset
	)
{
	m_pCSPObject->BeginTransaction();
	
	//��ȡ�ļ���С
	DWORD dwFileSize;
	if(!GetSize(&dwFileSize))
		return FALSE;

	//���ļ�
	FILEHANDLE hFile = NULL;
	if(!m_pCSPObject->OpenFile(m_path, &hFile, NULL)){
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	//�ж��Ƿ�Խ��
	if(dwWriteBufferLen + dwOffset > dwFileSize){
		m_pCSPObject->EndTransaction();
		return FALSE;
	}

	//�����ļ�
	BOOL bRetVal = m_pCSPObject->WriteFile(
		hFile, pWriteBuffer, dwWriteBufferLen, dwOffset
		);

	//���»��������
	if(bRetVal && m_pbData)
		memcpy(m_pbData + dwOffset, pWriteBuffer, dwWriteBufferLen);

	//�ر��ļ�
	m_pCSPObject->CloseFile(hFile);
	
	m_pCSPObject->EndTransaction();
	
	return bRetVal;
}

