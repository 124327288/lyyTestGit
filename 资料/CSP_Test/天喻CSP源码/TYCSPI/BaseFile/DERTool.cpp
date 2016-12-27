#include "stdafx.h"
#include "DERTool.h"

////////////////////////////////////////////////////////////////////
//	CDERTool out-of-line functions

//缺省构造函数
CDERTool::_DER::_DER()
{
	pDEREncodeStr = NULL;
	ulLength = 0;
}

//赋值构造函数
CDERTool::_DER::_DER(LPBYTE pEncodeStr, ULONG ulLen)
{
	if(pEncodeStr != NULL && ulLen != 0){
		ulLength = ulLen;
		pDEREncodeStr = new BYTE[ulLen];
		if(pDEREncodeStr != NULL)
			memcpy(pDEREncodeStr, pEncodeStr, ulLength);
		else
			ulLength = 0;
	}
	else{
		pDEREncodeStr = NULL;
		ulLength = 0;
	}
}

//析构函数
CDERTool::_DER::~_DER()
{
	if(pDEREncodeStr != NULL){
		delete pDEREncodeStr;
		pDEREncodeStr = NULL;
	}
	ulLength = 0;
}


//-------------------------------------------------------------------
//	功能：
//		清空编码集
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
CDERTool::Clear()
{
	int ulSize = GetCount();
	for(int i = 0; i < ulSize; i++)
		delete m_arDERs.GetAt(i);
	m_arDERs.RemoveAll();
}

//-------------------------------------------------------------------
//	功能：
//		添加一条DER编码
//
//	返回：
//		索引
//
//  参数：
//		LPBYTE pDEREncodeStr		DER编码
//		ULONG ulLength				编码的长度
//
//  说明：
//-------------------------------------------------------------------
int 
CDERTool::Add(
	LPBYTE pDEREncodeStr, 
	ULONG ulLength
	)
{
	int nRetVal = -1;
	if(pDEREncodeStr == NULL || ulLength == 0)
		return nRetVal;

	_DER* pDER = new _DER(pDEREncodeStr, ulLength);
	if(pDER != NULL)
		nRetVal = m_arDERs.Add(pDER);

	return nRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		获取指定索引处的DER编码
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		int nIndex					索引
//		LPBYTE& pDEREncodeStr		返回指向DER编码的指针
//		ULONG& ulLength				返回的编码的长度
//
//  说明：
//		使用者不能对该指针做任何修改
//-------------------------------------------------------------------
BOOL 
CDERTool::GetAt(
	int nIndex,	
	LPBYTE& pDEREncodeStr,	
	ULONG& ulLength	
	) const
{
	pDEREncodeStr = NULL;
	ulLength  =0;
	if(nIndex >= m_arDERs.GetSize())
		return FALSE;
	_DER* pDER = m_arDERs.GetAt(nIndex);
	if(pDER != NULL){
		pDEREncodeStr = pDER->pDEREncodeStr;
		ulLength = pDER->ulLength;
		return TRUE;
	}
	else
		return FALSE;
}

