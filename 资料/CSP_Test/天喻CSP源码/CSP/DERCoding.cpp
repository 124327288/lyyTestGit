#include "StdAfx.h"
#include "DERCoding.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
//////////////////////////////////////////////////////////////////////////
/*
功能：	按照DER的编码规则，形成TLV结构
输入：	ulTag——Tag值
		ulLen——Len值
		Value——vlue值
输出：	Vlaue——完成编码后的TLV结构
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
	//目前tag不会超过31
	Value.InsertAt(0,BYTE(ulTag));
		
}
//////////////////////////////////////////////////////////////////////////
/*
功能：	按照DER的解码码规则，得出tag
输入：	Value——DER编码的串
输出：	Tag值
说明：  该函数不影响value的值
*/
///////////////////////////////////////////////////////////////////////////
ULONG GetDERTag(
	byteArray& Value
	)
{
	if (Value.GetSize()>1)
		//目前tag不会超过31
		return Value[0];
	else
		return 0;
}

//////////////////////////////////////////////////////////////////////////
/*
功能：	按照DER的解码码规则，得出tag
输入：	pDERStr——DER编码的串, ulLen -- 长度
输出：	Tag值
说明：  该函数不影响value的值
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
功能：	按照DER的解码码规则，得出len
输入：	Value——DER编码的串
输出：	len值
		ulTagFiledLen ---tag域的长度
		ulLenFiledLen----len域的长度
说明：  该函数不影响value的值
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
功能：	按照DER的解码码规则，得出整个DER串的长度
输入：	Value——DER编码的串
		ulDERLen----串的长度，可能大于输出的长度，因为输入的串中可能包含其他
		的DER编码串
输出：	DER串的长度
说明：  该函数不影响value的值
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
功能：	按照DER的解码规则，判断tlv格式的正确性
输入：	ulTag——DER编码的串
输出：	len值
说明：  该函数不影响value的值
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
功能：	按照DER的解码码规则，解析TLV结构
输入：	Value——DER编码的串
输出：	ulTag——Tag值
		ulLen——Len值
		Value——vlue值
说明： Value中的原有的值将变成去掉tag和len的值
*/
///////////////////////////////////////////////////////////////////////////
void TLVDecoding(
	ULONG& ulTag,
	ULONG& ulLen,
	byteArray& Value
	)
{
	//目前tag不会超过31
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
功能：	将一个字符串的值拷贝到动态的byte数组中
输入：	pbStr——源字符串头指针
		ulLen——源字符串长度
		byArray——目标动态数组
输出：	byArray——目标动态数组
说明：  该函数将清除byArray中原有的数据，替换成新的源字符串的数据
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
功能：	将一个字符串的从源动态数组转移到目标动态数组中
输入：	bySrArray——源动态数组
		ulLen——需要转移的长度
输出：	byArray——目标动态数组
说明：  该函数将清除byDeArray中原有的数据，替换成新的转移过来的数据
		bySrArray中相应的ulLen长度的数据会被去掉
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
功能：	对asn.1中规定的GeneralizedTime类型进行编码
输入：	pDate——日期
		byArray——目标动态数组，用于存放编码的值
输出：	byArray——目标动态数组，用于存放编码的值
说明：  该函数将清除byArray中原有的数据，替换成新的编码的值
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
功能：	对asn.1中规定的GeneralizedTime类型进行解码
输入：byArray——源动态数组，用于存放编码的值
输出：	pDate——日期
说明：  该函数将影响byArray中原有的数据，去掉byArray中关于GeneralizedTime的
		编码
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
功能：	对ULONG整数类型进行编码
输入：	ulInt——整数
		byArray——目标动态数组，用于存放编码的值
输出：	byArray——目标动态数组，用于存放编码的值
说明：  该函数将清除byArray中原有的数据，替换成新的编码的值
		该函数仅对无符号数进行编码
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
功能：	对asn.1中规定的整数类型进行解码
输入：	byArray——动态数组，用于存放编码的值
输出：	ulInt——存放解出的整数的值
说明：  该函数将影响byArray中原有的数据，去掉关于对整数的编码
		该函数仅对无符号数进行解码
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
