//-------------------------------------------------------------------
//	���ļ�Ϊ TY Cryptographic Service Provider ����ɲ���
//
//
//	��Ȩ���� ������Ϣ��ҵ���޹�˾ (c) 1996 - 2005 ����һ��Ȩ��
//-------------------------------------------------------------------
#include "stdafx.h"
#include "HelperFunc.h"
#include "Modifier.h"

CTYCSP*
GetCSPByReaderName(
	LPCSTR lpszName,
	CTYCSPPtrArray *parrCSPs
	)
{
	int nCount = parrCSPs->GetSize();
	CTYCSP* pCSPObject = NULL;
	LPCSTR szTemp;
	for(int i = 0; i < nCount; i++){
		pCSPObject = parrCSPs->GetAt(i);
		szTemp = pCSPObject->GetReaderName();
		if(strcmp(szTemp, lpszName) == 0)
			return pCSPObject;
	}

	return NULL;
}

BOOL bStringInArray(char *szSrc, CArrayTemplate<char*, char*> *parrStrings)
{
	int count = parrStrings->GetSize();

	for(int i = 0; i<count; i++)
	{
		if(strcmp(szSrc, parrStrings->GetAt(i)) == 0)
			return TRUE;
	}
	
	return FALSE;
}

void DeleteStringArray(CArrayTemplate<char*, char*> *parrStrings)
{
	while (parrStrings->GetSize()) {
		delete parrStrings->GetAt(0);
		parrStrings->RemoveAt(0);
	}	
}
////////////////////////////////////////////////////////////////////////////////////////////////////

//��ȫ����Ҫ�������
BOOL FullReadFile(HANDLE hFile,                // handle of file to read
				  LPBYTE lpBuffer,             // pointer to buffer that receives data
				  DWORD nNumberOfBytesToRead,  // number of bytes to read
				  LPOVERLAPPED lpOverlapped)    // pointer to structure for data
{
	DWORD dwReaded = 0;
	DWORD dwRest = nNumberOfBytesToRead;

	while(dwRest)
	{
		if(!ReadFile(hFile, (void*)lpBuffer, dwRest, &dwReaded, lpOverlapped))
			return FALSE;
		if(dwReaded == 0) return FALSE;
		dwRest -= dwReaded;
		lpBuffer += dwReaded;
	}
	return TRUE;
}
//��ȫд��Ҫ�������
BOOL FullWriteFile(HANDLE hFile,                    // handle to file to write to
				  LPBYTE lpBuffer,                // pointer to data to write to file
				  DWORD nNumberOfBytesToWrite,     // number of bytes to write
				  LPOVERLAPPED lpOverlapped)        // pointer to structure for overlapped I/O
{
	DWORD dwWritten = 0;
	DWORD dwRest = nNumberOfBytesToWrite;

	while(dwRest)
	{
		if(!WriteFile(hFile, (LPVOID)lpBuffer, dwRest, &dwWritten, lpOverlapped))
			return FALSE;
		dwRest -= dwWritten;
		lpBuffer += dwWritten;
	}
	return TRUE;
}

/////////////////////////////////////////////////////////////////////
//
//	HELPER FUNCTION

BOOL IsFileExist(LPCTSTR lpszFileName)
{
	WIN32_FIND_DATA find_data;
	HANDLE hFind = ::FindFirstFile(lpszFileName, &find_data);
	if(hFind == INVALID_HANDLE_VALUE)
		return FALSE;
	else
		::FindClose(hFind);

	return TRUE;
}
BOOL FixTempFilePath(char *szFileName)
{
	GetWindowsDirectory(szFileName, MAX_PATH);
	strcat(szFileName, TEMP_PATH);
	BOOL bRet = CreateDirectory(szFileName, NULL);

	strcat(szFileName, MODIFY_RECORD_FILE);
	
	return TRUE;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void CheckProcIDs(CArrayProcIDs *parrProcIDs)
{
	int count = parrProcIDs->GetSize();
	DWORD dwTempID;
	HANDLE hTemp;
	CArrayTemplate<int, int> arrLostProcIDs;
	
	BOOL bProcExist;
	DWORD dwExitCode;
	//���ID
	for(int i = 0; i<count; i++)
	{
		hTemp = NULL;
		bProcExist = FALSE;
		dwTempID = parrProcIDs->GetAt(i);
		hTemp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTempID);
		if(hTemp) 
		{
			if((GetExitCodeProcess(hTemp, &dwExitCode)) && (dwExitCode == STILL_ACTIVE))
				bProcExist = TRUE;
			CloseHandle(hTemp);
		}
		if(!bProcExist)
			arrLostProcIDs.InsertAt(0, i);
	}
	//ɾ��ID
	count = arrLostProcIDs.GetSize();
	for(i=0; i<count; i++)
	{
		parrProcIDs->RemoveAt(arrLostProcIDs.GetAt(i));
	}
}

BOOL CModifyManager::ReadModify(CArrayModify *parrModify, DWORD *pdwMaxModifyID, DWORD *pdwRef, CArrayProcIDs *parrProcIDs)
{
	if(!parrModify->Load(m_szFileName))
		return FALSE;
	if((parrModify->m_dwHeadLen % 4) != 0)
		return FALSE;

	int count = parrModify->m_dwHeadLen / 4;
	BYTE *pbItor = parrModify->m_pbHead;
	memcpy(pdwMaxModifyID, parrModify->m_pbHead, 4);
	memcpy(pdwRef, parrModify->m_pbHead + 4, 4);
	count -= 2;
	pbItor += 8;
	DWORD dwTemp;

	while (count > 0) 
	{
		memcpy(&dwTemp, pbItor, 4);
		parrProcIDs->Add(dwTemp);
		pbItor += 4;
		count--;
	}
	return TRUE;
}
BOOL CModifyManager::WriteModify(CArrayModify *parrModify, DWORD dwMaxModifyID, DWORD dwRef, CArrayProcIDs *parrProcIDs)
{
	int count = parrProcIDs->GetSize();
	DWORD dwHeadLen = 8 + 4 * count;
	BYTE *pbHead = new BYTE[dwHeadLen];
	BYTE *pbItor = pbHead;
	memcpy(pbHead, &dwMaxModifyID, 4);
	memcpy(pbHead + 4, &dwRef, 4);
	pbItor += 8;
	DWORD dwTemp;
	for(int i = 0; i<count; i++)
	{
		dwTemp = parrProcIDs->GetAt(i);
		memcpy(pbItor, &dwTemp, 4);
		pbItor += 4;
	}

	parrModify->SetHead(pbHead, dwHeadLen);
	delete pbHead;

	if(!parrModify->Save(m_szFileName))
		return FALSE;
	return TRUE;
}
//���ļ�,���û��,���������ļ�,�����Ѵ����޸�ID
CModifyManager::CModifyManager()
{
	CArrayModify arrModify;
	CArrayProcIDs arrProcIDs;

	if(!FixTempFilePath(m_szFileName))
	{
		ASSERT(0);
	}
	DWORD dwRef = 0;
	if((!IsFileExist(m_szFileName)) || (!ReadModify(&arrModify, &m_dwFixedModifyID, &dwRef, &arrProcIDs)))
	{
		m_dwFixedModifyID = MODIFY_START_ID;
		dwRef = 0;
	}

	m_dwProgID = GetCurrentProcessId();
	CheckProcIDs(&arrProcIDs);
	if(arrProcIDs.GetSize() == 0)
	{
		DeleteFile(m_szFileName);
		while (arrModify.m_arr.GetSize()) {
			arrModify.DeleteAt(0);
		}
	}
	dwRef = arrProcIDs.GetSize();
	m_dwFixedModifyID = arrModify.m_arr.GetSize();

	arrProcIDs.Add(m_dwProgID);
	dwRef++;

	WriteModify(&arrModify, m_dwFixedModifyID, dwRef, &arrProcIDs);
}
//�޸����ü���,��������һ������,��ɾ���ļ�
CModifyManager::~CModifyManager()
{
	CArrayModify arrModify;
	CArrayProcIDs arrProcIDs;

	DWORD dwRef = 0;	
	if(!ReadModify(&arrModify, &m_dwFixedModifyID, &dwRef, &arrProcIDs))
		dwRef = 0;
	else
		dwRef--;

	if(dwRef)
	{
		int index = FindItemInArray<DWORD>(m_dwProgID, &arrProcIDs);
		if(index>=0)
		{
			arrProcIDs.RemoveAt(index);
		}
		WriteModify(&arrModify, m_dwFixedModifyID, dwRef, &arrProcIDs);
	}
	else
		DeleteFile(m_szFileName);
}

//���������޸�
void CModifyManager::FixModifies(CTYCSPPtrArray *parrCSPs)
{
	CArrayModify arrModify;
	CArrayProcIDs arrProcIDs;
	DWORD dwRef = 0;
	DWORD dwMaxModifyID;
	//��ȡ�޸ļ�¼
	if(!ReadModify(&arrModify, &dwMaxModifyID, &dwRef, &arrProcIDs))
		return;
	if(dwMaxModifyID <= m_dwFixedModifyID)
		return;
	if(dwMaxModifyID != int(arrModify.m_arr.GetSize()))
		return;

	//�����޸�
	MODIFY_ITEM mi;
	CTYCSP *pCSPObj = NULL;
	CArrayTemplate<char*, char*> arrLoadedReaders;
	char* szTemp;
	for(DWORD i = m_dwFixedModifyID; i<dwMaxModifyID; i++)
	{
		if(!arrModify.GetAt(i, &mi))
			break;
		if(mi.dwProgID == m_dwProgID)
			continue;
		pCSPObj = GetCSPByReaderName(mi.szReaderName, parrCSPs);
		if(!pCSPObj)
			continue;
		mi.szReaderName;
		if(!bStringInArray(mi.szReaderName, &arrLoadedReaders))
		{//���һ�������������й�����޸�,ֻ���¼���һ��
			pCSPObj->RefreshCard();

			szTemp = new char[MAX_PATH];
			strcpy(szTemp, mi.szReaderName);
			arrLoadedReaders.Add(szTemp);
		}
		DeleteStringArray(&arrLoadedReaders);
	}
	//�����Ѵ�����޸�ID
	m_dwFixedModifyID = dwMaxModifyID;
}
 
void CModifyManager::AddModify(const char *szReaderName)
{
	CArrayModify arrModify;
	CArrayProcIDs arrProcIDs;
	DWORD dwRef = 0;
	DWORD dwMaxModifyID;
	//��ȡ�޸ļ�¼
	if(!ReadModify(&arrModify, &dwMaxModifyID, &dwRef, &arrProcIDs))
		return;
	if(dwMaxModifyID != int(arrModify.m_arr.GetSize()))
		return;

	dwMaxModifyID++;
	//�����޸�
	MODIFY_ITEM mi;
	memset(&mi, 0, sizeof(mi));
	mi.dwModifyID = dwMaxModifyID;
	mi.dwProgID = m_dwProgID;
	strcpy(mi.szReaderName, szReaderName);

	//�����޸ļ�¼
	arrModify.Add(&mi);
	if(!WriteModify(&arrModify, dwMaxModifyID, dwRef, &arrProcIDs))
		return;
	
	//�����Ѵ�����޸�ID
	m_dwFixedModifyID = dwMaxModifyID;
	
}
