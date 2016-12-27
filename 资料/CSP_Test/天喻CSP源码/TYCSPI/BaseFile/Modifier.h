//-------------------------------------------------------------------
//	本文件为 TY Cryptographic Service Provider 的组成部分
//
//
//	版权所有 天喻信息产业有限公司 (c) 1996 - 2005 保留一切权利
//-------------------------------------------------------------------

#ifndef __TYCSP_MODIFIER_H__
#define __TYCSP_MODIFIER_H__

#include "CSPObject.h"
#include "ArrayTmpl.h"

#define MODIFY_START_ID			0
#define TEMP_PATH				_T("\\temp\\")
#define MODIFY_RECORD_FILE		_T("TYModify.tmp")



//完全读出要求的数据
BOOL FullReadFile(HANDLE hFile,                // handle of file to read
				  LPBYTE lpBuffer,             // pointer to buffer that receives data
				  DWORD nNumberOfBytesToRead,  // number of bytes to read
				  LPOVERLAPPED lpOverlapped);    // pointer to structure for data

//完全写入要求的数据
BOOL FullWriteFile(HANDLE hFile,                    // handle to file to write to
				  LPBYTE lpBuffer,                // pointer to data to write to file
				  DWORD nNumberOfBytesToWrite,     // number of bytes to write
				  LPOVERLAPPED lpOverlapped);        // pointer to structure for overlapped I/O


///////////////////////////////////////////////////////////////////////////////////////////////////
//以下是个数组文件类模板,用以将数组类保存到特定文件,并读出来,还原成数组
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
		HANDLE hFile = INVALID_HANDLE_VALUE;//文件句柄
		BYTE *pbDate = NULL;			//数据指针
		BYTE *pbTempBuf = NULL;				//移动指针
		DWORD i = 0;					//循环变量
		DWORD count = m_arr.GetSize();//记录数
		DWORD unit = sizeof(Item);		//单元长度
		DWORD dwFileSize = count * (unit + 2) + 8 + m_dwHeadLen + 4;//文件总长
		Item *TempItem;					//获取记录
		do 
		{
			hFile = CreateFile((LPCTSTR)szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
			if(hFile == INVALID_HANDLE_VALUE)
				break;

			pbDate = new BYTE[dwFileSize];
			if(!pbDate) break;
			pbTempBuf = pbDate;
			memcpy(pbTempBuf, "\x00\xff", 2);//文件头2 bytes
			pbTempBuf += 2;
			memcpy(pbTempBuf, &m_dwHeadLen, 4);//头长度
			pbTempBuf += 4;
			memcpy(pbTempBuf, m_pbHead, m_dwHeadLen);//头数据
			pbTempBuf += m_dwHeadLen;

			i = count | 0x80000000;
			memcpy(pbTempBuf, &i, 4);//记录数目	4 bytes big_endian, 最高位表示电话簿文件
			pbTempBuf += 4;
			memcpy(pbTempBuf, "\x00\xff", 2);
			pbTempBuf += 2;
			for(i = 0; i<count; i++)
			{
				TempItem = m_arr.GetAt(i);
				memcpy(pbTempBuf, (void*)TempItem, unit);//记录	长度为sizeof(CtelElement)
				pbTempBuf += unit;
				memcpy(pbTempBuf, "\x00\xff", 2);//分隔	2 byte
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
		HANDLE hFile = INVALID_HANDLE_VALUE;//文件句柄
		BYTE *pbDate = NULL;			//数据指针
		BYTE *temp = NULL;				//移动指针
		DWORD i = 0;					//循环变量
		DWORD count = 0;//记录数
		DWORD unit = sizeof(Item);		//单元长度
		DWORD dwFileSize = count * (unit + 2) + 8;//文件总长

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
			//重新设置头
			if(m_pbHead && m_dwHeadLen)
				delete m_pbHead;
			m_dwHeadLen = 0;
			m_pbHead = NULL;
			//读头长度
			memcpy(&m_dwHeadLen, temp, 4);
			temp += 4;
			//为头部申请内存
			m_pbHead = new BYTE[m_dwHeadLen];
			if(!m_pbHead)
				break;
			//拷贝头部
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
	//打开文件,如果没有,则生成新文件,设置已处理修改ID
	CModifyManager();
	//修改引用计数,如果是最后一个进程,则删除文件
	~CModifyManager();
	
	//处理所有修改
	void FixModifies(CTYCSPPtrArray *parrCSPs);
	//读写记录文件
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
