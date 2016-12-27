#include "StdAfx.h"
#include "DERCoding.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
//////////////////////////////////////////////////////////////////////////
/*
���ܣ�	����DER�ı�������γ�TLV�ṹ
���룺	ulTag����Tagֵ
		ulLen����Lenֵ
		Value����vlueֵ
�����	Vlaue������ɱ�����TLV�ṹ
*/
///////////////////////////////////////////////////////////////////////////
void TLVEncoding(
	ULONG ulTag,
	ULONG ulLen,
	byteArray& Value
	)
{
		
	if (ulLen < 0x80)
		Value.InsertAt(0,BYTE(ulLen));
	else
	{
		BYTE tmpLen=0x80;
		for (int i=0;i<sizeof(ULONG);i++)
		{
			ulLen>>=(i*8);
			if (ulLen)
			{
				Value.InsertAt(0,BYTE(ulLen&0xff));
				tmpLen++;
			}
		}
		Value.InsertAt(0,tmpLen);
	}
	//Ŀǰtag���ᳬ��31
	Value.InsertAt(0,BYTE(ulTag));
		
}
//////////////////////////////////////////////////////////////////////////
/*
���ܣ�	����DER�Ľ�������򣬵ó�tag
���룺	Value����DER����Ĵ�
�����	Tagֵ
˵����  �ú�����Ӱ��value��ֵ
*/
///////////////////////////////////////////////////////////////////////////
ULONG GetDERTag(
	byteArray& Value
	)
{
	if (Value.GetSize()>1)
		//Ŀǰtag���ᳬ��31
		return Value[0];
	else
		return 0;
}

//////////////////////////////////////////////////////////////////////////
/*
���ܣ�	����DER�Ľ�������򣬵ó�tag
���룺	pDERStr����DER����Ĵ�, ulLen -- ����
�����	Tagֵ
˵����  �ú�����Ӱ��value��ֵ
*/
///////////////////////////////////////////////////////////////////////////
ULONG GetDERTag(
	BYTE* pDERStr,
	ULONG ulLen
	)
{
	if(pDERStr == NULL || ulLen <= 1)
		return 0;
	else
		return pDERStr[0];
}
//////////////////////////////////////////////////////////////////////////
/*
���ܣ�	����DER�Ľ�������򣬵ó�len
���룺	Value����DER����Ĵ�
�����	lenֵ
		ulTagFiledLen ---tag��ĳ���
		ulLenFiledLen----len��ĳ���
˵����  �ú�����Ӱ��value��ֵ
*/
///////////////////////////////////////////////////////////////////////////
ULONG GetDERLen(
		BYTE* pDERStr,
		ULONG ulDERLen,
		ULONG& ulTagFiledLen,
		ULONG& ulLenFiledLen
		)
{
	ULONG ulLen = 0xffffffff;
	if (ulDERLen>1)
	{
		if(pDERStr[1]&0x80)
		{
			ulLen = 0;
			int Len = pDERStr[1]&0x7F;
			ulLenFiledLen = Len+1;
			for (int i=Len;i>0;i--)
			{
				ulLen+=pDERStr[1+i]<<((Len-i)*8);
			}
		}
		else
		{
			ulLen = pDERStr[1];
			ulLenFiledLen = 1;
		}
	}
	ulTagFiledLen = 1;
	return ulLen;
}
//////////////////////////////////////////////////////////////////////////
/*
���ܣ�	����DER�Ľ�������򣬵ó�����DER���ĳ���
���룺	Value����DER����Ĵ�
		ulDERLen----���ĳ��ȣ����ܴ�������ĳ��ȣ���Ϊ����Ĵ��п��ܰ�������
		��DER���봮
�����	DER���ĳ���
˵����  �ú�����Ӱ��value��ֵ
*/
///////////////////////////////////////////////////////////////////////////
ULONG GetDERTotalStrLen(
		BYTE* pDERStr,
		ULONG ulDERLen
		)
{
	ULONG ulTagFieldLen=0,ulLenFieldLen=0,ulValueFieldLen=0;
	ulValueFieldLen = GetDERLen((BYTE*)(pDERStr),ulDERLen,ulTagFieldLen,ulLenFieldLen);
	return ulTagFieldLen+ulLenFieldLen+ulValueFieldLen;
}
//////////////////////////////////////////////////////////////////////////
/*
���ܣ�	����DER�Ľ�������ж�tlv��ʽ����ȷ��
���룺	ulTag����DER����Ĵ�
�����	lenֵ
˵����  �ú�����Ӱ��value��ֵ
*/
///////////////////////////////////////////////////////////////////////////
BOOL IsTLVStr(
	ULONG ulTag,
	VOID* pDERStr,
	ULONG ulDERLen
	)
{
	if (ulDERLen<2)
		return FALSE;
	if (((BYTE*)(pDERStr))[0] != ulTag)
		return FALSE;
	
	ULONG ulTagFieldLen=0,ulLenFieldLen=0,ulValueFieldLen=0;
	ulValueFieldLen = GetDERLen((BYTE*)(pDERStr),ulDERLen,ulTagFieldLen,ulLenFieldLen);
	if (ulDERLen != ulTagFieldLen+ulLenFieldLen+ulValueFieldLen)
		return FALSE;

	return TRUE;
	
}
//////////////////////////////////////////////////////////////////////////
/*
���ܣ�	����DER�Ľ�������򣬽���TLV�ṹ
���룺	Value����DER����Ĵ�
�����	ulTag����Tagֵ
		ulLen����Lenֵ
		Value����vlueֵ
˵���� Value�е�ԭ�е�ֵ�����ȥ��tag��len��ֵ
*/
///////////////////////////////////////////////////////////////////////////
void TLVDecoding(
	ULONG& ulTag,
	ULONG& ulLen,
	byteArray& Value
	)
{
	//Ŀǰtag���ᳬ��31
	ulTag = Value[0];
	ulLen = 0;
	if(Value[1]&0x80)
	{
		int Len = Value[1]&0x7F;
		for (int i=Len;i>0;i--)
		{
			ulLen+=Value[1+i]<<(Len-i);
		}
		Value.RemoveAt(0,Len+2);
	}
	else
	{
		ulLen = Value[1];
		Value.RemoveAt(0,2);
	}
	
}

//////////////////////////////////////////////////////////////////////////
/*
���ܣ�	��һ���ַ�����ֵ��������̬��byte������
���룺	pbStr����Դ�ַ���ͷָ��
		ulLen����Դ�ַ�������
		byArray����Ŀ�궯̬����
�����	byArray����Ŀ�궯̬����
˵����  �ú��������byArray��ԭ�е����ݣ��滻���µ�Դ�ַ���������
*/
///////////////////////////////////////////////////////////////////////////
void CopyToByteArray(
	BYTE* pbStr,
	ULONG ulLen,
	byteArray& byArray
	)
{
	byArray.RemoveAll();
	for (ULONG i=0; i<ulLen; i++)
	{
		byArray.Add(pbStr[i]);
	}
}
//////////////////////////////////////////////////////////////////////////
/*
���ܣ�	��һ���ַ����Ĵ�Դ��̬����ת�Ƶ�Ŀ�궯̬������
���룺	bySrArray����Դ��̬����
		ulLen������Ҫת�Ƶĳ���
�����	byArray����Ŀ�궯̬����
˵����  �ú��������byDeArray��ԭ�е����ݣ��滻���µ�ת�ƹ���������
		bySrArray����Ӧ��ulLen���ȵ����ݻᱻȥ��
*/
///////////////////////////////////////////////////////////////////////////
void MoveToByteArray(
	byteArray& bySrArray,
	ULONG ulLen,
	byteArray& byDeArray
	)
{
	byDeArray.RemoveAll();
	CopyToByteArray(bySrArray.GetData(),ulLen,byDeArray);
	bySrArray.RemoveAt(0,ulLen);

}
//////////////////////////////////////////////////////////////////////////
/*
���ܣ�	��asn.1�й涨��GeneralizedTime���ͽ��б���
���룺	pDate��������
		byArray����Ŀ�궯̬���飬���ڴ�ű����ֵ
�����	byArray����Ŀ�궯̬���飬���ڴ�ű����ֵ
˵����  �ú��������byArray��ԭ�е����ݣ��滻���µı����ֵ
*/
///////////////////////////////////////////////////////////////////////////
void GeneralizedTimeEncoding(
	DATE* pDate,
	byteArray& byArray
	)
{
	byArray.RemoveAll();
	CopyToByteArray((BYTE*)(pDate),sizeof(DATE),byArray);
	byArray.Add('0');
	byArray.Add('0');
	byArray.Add('0');
	byArray.Add('0');
	byArray.Add('Z');
	TLVEncoding(0x18,byArray.GetSize(),byArray);
}

//////////////////////////////////////////////////////////////////////////
/*
���ܣ�	��asn.1�й涨��GeneralizedTime���ͽ��н���
���룺byArray����Դ��̬���飬���ڴ�ű����ֵ
�����	pDate��������
˵����  �ú�����Ӱ��byArray��ԭ�е����ݣ�ȥ��byArray�й���GeneralizedTime��
		����
*/
///////////////////////////////////////////////////////////////////////////
void GeneralizedTimeDecoding(
	byteArray& byArray,
	DATE* pDate
	)
{
	ULONG ulTag,ulLen;
	TLVDecoding(ulTag,ulLen,byArray);
	memcpy(pDate,byArray.GetData(),sizeof(DATE));
	byArray.RemoveAt(0,ulLen);
}

/////////////////////////////////////////////////////////////////////////
/*
���ܣ�	��ULONG�������ͽ��б���
���룺	ulInt��������
		byArray����Ŀ�궯̬���飬���ڴ�ű����ֵ
�����	byArray����Ŀ�궯̬���飬���ڴ�ű����ֵ
˵����  �ú��������byArray��ԭ�е����ݣ��滻���µı����ֵ
		�ú��������޷��������б���
*/
///////////////////////////////////////////////////////////////////////////
void ULONGEncoding(
	ULONG ulInt,
	byteArray &byArray
	)
{
	byArray.RemoveAll();
	for (int i=0; i<sizeof(ULONG); i++)
	{
		ulInt >>= (i*8);
		if (ulInt!=0)
		{
			byArray.InsertAt(0,BYTE(ulInt&0xff));
		}
	}
	if((byArray.GetSize()==0)||(byArray[0]>0x7f))
		byArray.InsertAt(0,BYTE(0x00));

	TLVEncoding(0x02,byArray.GetSize(),byArray);
}

/////////////////////////////////////////////////////////////////////////
/*
���ܣ�	��asn.1�й涨���������ͽ��н���
���룺	byArray������̬���飬���ڴ�ű����ֵ
�����	ulInt������Ž����������ֵ
˵����  �ú�����Ӱ��byArray��ԭ�е����ݣ�ȥ�����ڶ������ı���
		�ú��������޷��������н���
*/
///////////////////////////////////////////////////////////////////////////
void ULONGDecoding(
	byteArray &byArray,
	ULONG &ulInt
	)
{
	ulInt = 0;
	ULONG ulTag,ulLen;
	TLVDecoding(ulTag,ulLen,byArray);

	for (ULONG i=0; i<ulLen; i++)
		ulInt += byArray[i]<<((ulLen-i-1)*8);
	byArray.RemoveAt(0,ulLen);
}
