//-------------------------------------------------------------------
//	���ļ�Ϊ TY Cryptographic Service Provider ����ɲ���
//
//
//	��Ȩ���� ������Ϣ��ҵ���޹�˾ (c) 1996 - 2005 ����һ��Ȩ��
//-------------------------------------------------------------------

#ifndef __TYCSP_MODIFIER_H__
#define __TYCSP_MODIFIER_H__

#include "CSPObject.h"
#include "ArrayTmpl.h"

#define MODIFY_START_ID			0
#define TEMP_PATH				_T("\\temp\\")
#define MODIFY_RECORD_FILE		_T("TYModify.tmp")



//��ȫ����Ҫ�������
BOOL FullReadFile(HANDLE hFile,                // handle of file to read
				  LPBYTE lpBuffer,             // pointer to buffer that receives data
				  DWORD nNumberOfBytesToRead,  // number of bytes to read
				  LPOVERLAPPED lpOverlapped);    // pointer to structure for data

//��ȫд��Ҫ�������
BOOL FullWriteFile(HANDLE hFile,                    // handle to file to write to
				  LPBYTE lpBuffer,                // pointer to data to write to file
				  DWORD nNumberOfBytesToWrite,     // number of bytes to write
				  LPOVERLAPPED lpOverlapped);        // pointer to structure for overlapped I/O


///////////////////////////////////////////////////////////////////////////////////////////////////
//�����Ǹ������ļ���ģ��,���Խ������ౣ�浽�ض��ļ�,��������,��ԭ������
template<class Item>
class CArrayFile
{
public:
	CArrayFile()
	{
		m_arr.RemoveAll();
		memset(m_szPathName, 0, sizeof(m_szPathName));
		m_pbHead = NULL;
		m_dwHeadLen = 0;
	}
	~CArrayFile()
	{
		while(m_arr.GetSize() > 0)
		{
			delete m_arr.GetAt(0);
			m_arr.RemoveAt(0);
		}
		if(m_pbHead && m_dwHeadLen)
			delete m_pbHead;

	}
	CArrayTemplate<Item*, Item*> m_arr;
	char m_szPathName[MAX_PATH];
	BYTE *m_pbHead;
	DWORD m_dwHeadLen;
	
	BOOL SetHead(BYTE *pbHead, DWORD dwHeadLen)
	{
		if(m_pbHead && m_dwHeadLen)
			delete m_pbHead;
		m_dwHeadLen = 0;
		m_pbHead = NULL;
		m_pbHead = new BYTE[dwHeadLen];
		if(!m_pbHead)
			return FALSE;
		m_dwHeadLen = dwHeadLen;
		memcpy(m_pbHead, pbHead, dwHeadLen);
		return TRUE;
	}

	BOOL Add(Item *pItem)
	{
		Item *pNewItem = new Item;
		memcpy(pNewItem, pItem, sizeof(Item));
		m_arr.Add(pNewItem);

		return TRUE;
	}

	BOOL SetAt(int nIndex, Item *pItem)
	{
		if(nIndex >= m_arr.GetSize())
			return FALSE;
		delete m_arr.GetAt(nIndex);
		Item *pNewItem = new Item;
		memcpy(pNewItem, pItem, sizeof(Item));
		m_arr.SetAt(nIndex, pNewItem);
		return TRUE;
	}
	BOOL GetAt(int nIndex, Item *pItem)
	{
		if(nIndex >= m_arr.GetSize())
			return FALSE;
		memcpy(pItem, m_arr.GetAt(nIndex), sizeof(Item));
		return TRUE;
	}
	BOOL DeleteAt(int nIndex)
	{
		if(nIndex >= m_arr.GetSize())
			return FALSE;
		delete m_arr.GetAt(nIndex);
		m_arr.RemoveAt(nIndex);
		return TRUE;
	}
	BOOL Save(LPCSTR szPathName = NULL)
	{
		LPCSTR szPath;
		if(szPathName)
			szPath = szPathName;
		else
		{
			if(strlen(m_szPathName) == 0)
				return FALSE;
			szPath = m_szPathName;
		}
		BOOL bResult = FALSE;
		HANDLE hFile = INVALID_HANDLE_VALUE;//�ļ����
		BYTE *pbDate = NULL;			//����ָ��
		BYTE *pbTempBuf = NULL;				//�ƶ�ָ��
		DWORD i = 0;					//ѭ������
		DWORD count = m_arr.GetSize();//��¼��
		DWORD unit = sizeof(Item);		//��Ԫ����
		DWORD dwFileSize = count * (unit + 2) + 8 + m_dwHeadLen + 4;//�ļ��ܳ�
		Item *TempItem;					//��ȡ��¼
		do 
		{
			hFile = CreateFile((LPCTSTR)szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
			if(hFile == INVALID_HANDLE_VALUE)
				break;

			pbDate = new BYTE[dwFileSize];
			if(!pbDate) break;
			pbTempBuf = pbDate;
			memcpy(pbTempBuf, "\x00\xff", 2);//�ļ�ͷ2 bytes
			pbTempBuf += 2;
			memcpy(pbTempBuf, &m_dwHeadLen, 4);//ͷ����
			pbTempBuf += 4;
			memcpy(pbTempBuf, m_pbHead, m_dwHeadLen);//ͷ����
			pbTempBuf += m_dwHeadLen;

			i = count | 0x80000000;
			memcpy(pbTempBuf, &i, 4);//��¼��Ŀ	4 bytes big_endian, ���λ��ʾ�绰���ļ�
			pbTempBuf += 4;
			memcpy(pbTempBuf, "\x00\xff", 2);
			pbTempBuf += 2;
			for(i = 0; i<count; i++)
			{
				TempItem = m_arr.GetAt(i);
				memcpy(pbTempBuf, (void*)TempItem, unit);//��¼	����Ϊsizeof(CtelElement)
				pbTempBuf += unit;
				memcpy(pbTempBuf, "\x00\xff", 2);//�ָ�	2 byte
				pbTempBuf += 2;
			}
			if(!FullWriteFile(hFile, pbDate, dwFileSize, NULL))
				break;
			bResult = TRUE;
		} while(0);
		
		if(hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
		if(pbDate) delete pbDate;
		return bResult;
	}
	BOOL Load(LPCSTR szPathName = NULL)
	{
		LPCSTR szPath;
		if(szPathName)
			szPath = szPathName;
		else
		{
			if(strlen(m_szPathName) == 0)
				return FALSE;
			szPath = m_szPathName;
		}

		BOOL bResult = FALSE;
		HANDLE hFile = INVALID_HANDLE_VALUE;//�ļ����
		BYTE *pbDate = NULL;			//����ָ��
		BYTE *temp = NULL;				//�ƶ�ָ��
		DWORD i = 0;					//ѭ������
		DWORD count = 0;//��¼��
		DWORD unit = sizeof(Item);		//��Ԫ����
		DWORD dwFileSize = count * (unit + 2) + 8;//�ļ��ܳ�

		do 
		{
			hFile = CreateFile((LPCTSTR)szPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
			if(hFile == INVALID_HANDLE_VALUE)
				break;
			dwFileSize = GetFileSize(hFile, NULL);
			pbDate = new BYTE[dwFileSize];
			if(!pbDate) break;
			temp = pbDate;
			if(!FullReadFile(hFile, pbDate, dwFileSize, NULL))
				break;
			if(memcmp(temp, "\x00\xff", 2) != 0) break;
			temp += 2;
			//��������ͷ
			if(m_pbHead && m_dwHeadLen)
				delete m_pbHead;
			m_dwHeadLen = 0;
			m_pbHead = NULL;
			//��ͷ����
			memcpy(&m_dwHeadLen, temp, 4);
			temp += 4;
			//Ϊͷ�������ڴ�
			m_pbHead = new BYTE[m_dwHeadLen];
			if(!m_pbHead)
				break;
			//����ͷ��
			memcpy(m_pbHead, temp, m_dwHeadLen);
			temp += m_dwHeadLen;

			count = *((DWORD*)(temp));
			if(!(count & 0x80000000)) break;
			count &= 0x7fffffff;

			if(dwFileSize < (count * (unit+2) + 8 + m_dwHeadLen + 4)) break;
			temp += 6;
			
			while(m_arr.GetSize() > 0)
			{
				DeleteAt(0);
			}

			for(i = 0; i<count; i++)
			{
				Add((Item*)temp);
				temp += unit;
				if(memcmp(temp, "\x00\xff", 2) != 0) break;
				temp += 2;
			}
			if(i != count) break;
			bResult = TRUE;
		}while (0);

		if(hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
		if(pbDate) delete pbDate;
		
		return bResult;
	}

	
protected:
private:
};

typedef struct _MODIFY_ITEM {
	DWORD dwModifyID;
	DWORD dwProgID;
	char szReaderName[MAX_PATH];
}MODIFY_ITEM, LPMODIFY_ITEM;

typedef	CArrayFile<LPMODIFY_ITEM> CArrayModify;
typedef CArrayTemplate<DWORD, DWORD> CArrayProcIDs;

class CModifyManager 
{
public:
	void AddModify(const char *szReaderName);
	//���ļ�,���û��,���������ļ�,�����Ѵ����޸�ID
	CModifyManager();
	//�޸����ü���,��������һ������,��ɾ���ļ�
	~CModifyManager();
	
	//���������޸�
	void FixModifies(CTYCSPPtrArray *parrCSPs);
	//��д��¼�ļ�
	BOOL ReadModify(CArrayModify *parrModify, DWORD *pdwMaxModifyID, DWORD *pdwRef, CArrayProcIDs *parrProcIDs);
	BOOL WriteModify(CArrayModify *parrModify, DWORD dwMaxModifyID, DWORD dwRef, CArrayProcIDs *parrProcIDs);
	
protected:
	DWORD m_dwFixedModifyID;
	DWORD m_dwProgID;
	char m_szFileName[MAX_PATH];
};




template <class T>
BOOL bIsInArray(T item, CArrayTemplate<T, T>* pArray)
{
	int count = pArray->GetSize();

	for(int i = 0; i<count; i++)
	{
		if(item == pArray->GetAt(i))
			return TRUE;
	}
	
	return FALSE;
}

template <class T>
int FindItemInArray(T item, CArrayTemplate<T, T>* pArray)
{
	int count = pArray->GetSize();

	for(int i = 0; i<count; i++)
	{
		if(item == pArray->GetAt(i))
			return i;
	}
	
	return -1;
}






#endif//__TYCSP_MODIFIER_H__
