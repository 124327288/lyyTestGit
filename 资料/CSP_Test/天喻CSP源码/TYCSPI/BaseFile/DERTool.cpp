#include "stdafx.h"
#include "DERTool.h"

////////////////////////////////////////////////////////////////////
//	CDERTool out-of-line functions

//ȱʡ���캯��
CDERTool::_DER::_DER()
{
	pDEREncodeStr = NULL;
	ulLength = 0;
}

//��ֵ���캯��
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

//��������
CDERTool::_DER::~_DER()
{
	if(pDEREncodeStr != NULL){
		delete pDEREncodeStr;
		pDEREncodeStr = NULL;
	}
	ulLength = 0;
}


//-------------------------------------------------------------------
//	���ܣ�
//		��ձ��뼯
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
CDERTool::Clear()
{
	int ulSize = GetCount();
	for(int i = 0; i < ulSize; i++)
		delete m_arDERs.GetAt(i);
	m_arDERs.RemoveAll();
}

//-------------------------------------------------------------------
//	���ܣ�
//		���һ��DER����
//
//	���أ�
//		����
//
//  ������
//		LPBYTE pDEREncodeStr		DER����
//		ULONG ulLength				����ĳ���
//
//  ˵����
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
//	���ܣ�
//		��ȡָ����������DER����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		int nIndex					����
//		LPBYTE& pDEREncodeStr		����ָ��DER�����ָ��
//		ULONG& ulLength				���صı���ĳ���
//
//  ˵����
//		ʹ���߲��ܶԸ�ָ�����κ��޸�
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

