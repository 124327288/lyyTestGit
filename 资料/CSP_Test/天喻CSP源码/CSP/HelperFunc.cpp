//-------------------------------------------------------------------
//	本文件为 TY Cryptographic Service Provider 的组成部分
//
//
//	版权所有 天喻信息产业有限公司 (c) 1996 - 2005 保留一切权利
//-------------------------------------------------------------------
#include "stdafx.h"
#include "HelperFunc.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
extern DWORD g_dwEccSignAlgid,g_dwEccKeyxAlgid;
//-------------------------------------------------------------------
//	功能：
//		将一字节数组反转
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		BYTE* pbBuf				字节数组			 
//		DWORD dwBufLen			字节数
//
//  说明：
//-------------------------------------------------------------------
void ByteReverse(
	BYTE* pbBuf,			 
	DWORD dwBufLen
	)
{
	if(pbBuf == NULL)
		return;

	for(DWORD dwI = 0; dwI < dwBufLen / 2; dwI++){
		BYTE t = pbBuf[dwI];
		pbBuf[dwI] = pbBuf[dwBufLen - dwI - 1];
		pbBuf[dwBufLen - dwI - 1] = t;
	}
}

//-------------------------------------------------------------------
//	功能：
//		将密钥对类型转换为密钥算法标识
//
//	返回：
//		算法标识
//
//  参数：
//		DWORD dwKeySpec	密钥对类型
//
//  说明：
//-------------------------------------------------------------------
ALG_ID KeyPairTypeToAlgid(
	DWORD dwKeySpec
	)
{
	if(dwKeySpec == AT_KEYEXCHANGE)
		return CALG_RSA_KEYX;
	else if(dwKeySpec == AT_SIGNATURE)
		return CALG_RSA_SIGN;
	else if(dwKeySpec == g_dwEccKeyxAlgid)
		return g_dwEccKeyxAlgid;
	else if(dwKeySpec == g_dwEccSignAlgid)
		return g_dwEccSignAlgid;
	else return 0;
}

//-------------------------------------------------------------------
//	功能：
//		判断一个字符串中是否包含一个子串
//
//	返回：
//		TRUE：包含		FALSE：不包含
//
//  参数：
//		LPCTSTR lpszSource		源串
//		LPCTSTR lpszSub			子串
//
//  说明：
//-------------------------------------------------------------------
BOOL IsContainSubString(LPCTSTR lpszSource, LPCTSTR lpszSub)
{
	if(lpszSource == NULL || lpszSub == NULL)
		return FALSE;

	TCHAR* szSourceDup = _tcsdup(lpszSource);
	TCHAR* szSubDup = _tcsdup(lpszSub);
	if(szSourceDup == NULL || szSubDup == NULL){
		if(szSourceDup != NULL) free(szSourceDup);
		if(szSubDup != NULL) free(szSubDup);
		return FALSE;
	}
	TCHAR* szSourceUp = _tcsupr(szSourceDup);
	TCHAR* szSubUp = _tcsupr(szSubDup);
	BOOL bRetVal = (_tcsstr(szSourceDup, szSubUp) != NULL);

	free(szSourceDup);
	free(szSubDup);

	return bRetVal;
}

/////////////////////////////////////////////////////////////////////
//
//	DER Encoding Helper Functions

//-------------------------------------------------------------------
//	功能：
//		生成一个ByteArray
//
//	返回：
//		无
//
//  参数：
//		LPBYTE pData
//		DWORD dwDataLen
//		ByteArray& arByte
//
//  说明：
//-------------------------------------------------------------------
void
MakeByteArray(
	IN LPBYTE pData,
	IN DWORD dwDataLen,
	OUT ByteArray& arByte
	)
{
	arByte.RemoveAll();
	for(DWORD dwI = 0; dwI < dwDataLen; dwI++)
		arByte.Add(pData[dwI]);
}

//-------------------------------------------------------------------
//	功能：
//		连接两个ByteArray
//
//	返回：
//		无
//
//  参数：
//		ByteArray& destByte			
//		ByteArray srcByte
//
//  说明：
//-------------------------------------------------------------------
void 
ConnectByteArray(
	IN OUT ByteArray& destByte,
	IN const ByteArray& srcByte
	)
{
	for(int i = 0; i < srcByte.GetSize(); i++)
		destByte.Add(srcByte.GetAt(i));
}

//-------------------------------------------------------------------
//	功能：
//		获取DER编码各部分的长度
//
//	返回：
//		DER编码的总长度, 为0表示出错
//
//  参数：
//		LPBYTE pDERCode				DER编码
//		DWORD dwDERLen				DER编码的长度
//		DWORD& dwTagFieldLen		标记域的长度
//		DWORD& dwLenFieldLen		长度域的长度
//		DWORD& dwValueFieldLen		值域的长度
//
//  说明：
//-------------------------------------------------------------------
DWORD
GetDERCodeFieldLen(
	IN const LPBYTE pDERCode,
	IN const DWORD dwDERLen,
	OUT DWORD& dwTagFieldLen,
	OUT DWORD& dwLenFieldLen,
	OUT DWORD& dwValueFieldLen
	)
{
	dwTagFieldLen = 0;
	dwLenFieldLen = 0;
	dwValueFieldLen = 0;

	if(pDERCode == NULL || dwDERLen < 2)
		return 0;

	dwTagFieldLen = 1;

	DWORD dwOffset = 1;
	BYTE b = pDERCode[dwOffset++];
	if(b < 0x80){
		dwLenFieldLen = 1;
		dwValueFieldLen = b;
	}
	else{
		DWORD dwDERLenCountLen = b - 0x80;
		if(dwDERLenCountLen > dwDERLen - 2)
			return 0;
		dwLenFieldLen = dwDERLenCountLen + 1;
		for(DWORD dwI = 0; dwI < dwDERLenCountLen; dwI++){
			b = pDERCode[dwOffset++];
			dwValueFieldLen += (b << 8*(dwDERLenCountLen - dwI - 1));
		}
	}

	return (dwTagFieldLen + dwLenFieldLen + dwValueFieldLen);
}

//-------------------------------------------------------------------
//	功能：
//		计算一个DER编码的长度
//
//	返回：
//		DER编码的长度	
//
//  参数：
//		DWORD dwTagLen		标记的长度
//		DWORD dwValueLen	值的长度
//
//  说明：
//-------------------------------------------------------------------
DWORD
CalcDEREncodingLength(
	DWORD dwTagLen,
	DWORD dwValueLen
	)
{
	DWORD dwRetLen = dwTagLen + dwValueLen;

	if (dwValueLen < 0x80)
		dwRetLen ++;
	else{
		dwRetLen ++;
		DWORD dwTmpLen = dwValueLen;
		while(dwTmpLen){
			if (dwTmpLen) dwRetLen++;
			dwTmpLen >>= 8;
		}
	}

	return dwRetLen;
}

//-------------------------------------------------------------------
//	功能：
//		DER编码
//
//	返回：
//		无
//
//  参数：
//		DWORD dwTag				标记
//		DWORD dwLen				值的长度
//		ByteArray& Value		值
//
//  说明：
//-------------------------------------------------------------------
void 
DEREncoding(
	IN DWORD dwTag,
	IN DWORD dwLen,
	IN OUT ByteArray& Value
	)
{
	if(dwTag == 0x02){
		if(Value.GetAt(0) >= 0x80){
			Value.InsertAt(0, BYTE(0));
			dwLen += 1;
		}
	}

	if (dwLen < 0x80)
		Value.InsertAt(0, BYTE(dwLen));
	else{
		DWORD dwValueLen = dwLen;
		BYTE tmpLen = 0x80;
		while(dwValueLen){
			if (dwValueLen){
				Value.InsertAt(0, BYTE(dwValueLen));
				tmpLen++;
			}
			dwValueLen >>= 8;
		}

		Value.InsertAt(0,tmpLen);
	}

	Value.InsertAt(0, BYTE(dwTag));
}

//-------------------------------------------------------------------
//	功能：
//		DER解码
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		ByteArray& baDERCode	DER编码(IN)/值(OUT)
//		DWORD& dwTag			标记
//		DWORD& dwLen			长度
//
//  说明：
//-------------------------------------------------------------------
BOOL 
DERDecoding(
	IN OUT ByteArray& baDERCode,
	OUT DWORD& dwTag,
	OUT DWORD& dwLen
	)
{
	if(baDERCode.GetSize() < 2)
		return FALSE;

	BYTE b;
 
	//标记为1字节
	b = baDERCode.GetAt(0);
	baDERCode.RemoveAt(0);
	dwTag = b;

	//长度
	dwLen = 0;
	b = baDERCode.GetAt(0);
	baDERCode.RemoveAt(0);
	if(b < 0x80)
		dwLen = b;
	else{
		//长度的字节数
		DWORD dwDERLenCountLen = b - 0x80;
		if(dwDERLenCountLen > (DWORD)baDERCode.GetSize())
			return FALSE;

		for(DWORD dwI = 0; dwI < dwDERLenCountLen; dwI++){
			b = baDERCode.GetAt(0);
			baDERCode.RemoveAt(0);
			dwLen += (b << 8*(dwDERLenCountLen - dwI - 1));
		}
	}

	//如果是整数，去掉前面的0
	if(dwTag == 0x02){
		if(baDERCode.GetAt(0) == 0x00 && 
			baDERCode.GetAt(1) > 0x7F)
		{
			baDERCode.RemoveAt(0);
			dwLen--;
		}
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		DER解码
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		ByteArray& baDERCode	DER编码(IN)/下一个DER编码(OUT)
//		DWORD& dwTag			标记
//		LPBYTE pValue			值
//		DWORD& dwValueLen		值的长度
//
//  说明：
//-------------------------------------------------------------------
BOOL
DERDecoding(
	IN OUT ByteArray& baDERCode,
	OUT DWORD& dwTag,
	OUT LPBYTE pValue,
	IN OUT DWORD& dwValueLen
	)
{
	if(pValue == NULL)
		return FALSE;

	if(baDERCode.GetSize() < 2)
		return FALSE;

	//获取当前DER编码各部份的长度，用于判断是否为合法的DER编码
	DWORD dwTagFieldLen, dwLenFieldLen, dwValueFieldLen;
	DWORD dwTotalLen = GetDERCodeFieldLen(
		baDERCode.GetData(), baDERCode.GetSize(), dwTagFieldLen, dwLenFieldLen, dwValueFieldLen
		);
	if(dwTotalLen == 0 || dwTotalLen > (DWORD)baDERCode.GetSize())
		return FALSE;

	//解码
	DWORD dwLen;
	DERDecoding(baDERCode, dwTag, dwLen);

	//如果是整数，去掉前面的0
	DWORD dwRealLen = dwLen;
	if(dwTag == 0x02){
		if(baDERCode.GetAt(0) == 0x00 && 
			baDERCode.GetAt(1) > 0x7F)
			dwRealLen--;
	}

	//判断缓冲是否足够大
	if(dwRealLen > dwValueLen)
		return FALSE;

	//复制值段
	memcpy(pValue, baDERCode.GetData() + (dwLen - dwRealLen), dwRealLen);
	dwValueLen = dwRealLen;

	//指向下一个DER编码
	baDERCode.RemoveAt(0, dwLen);

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		对TokenInfo进行DER编码
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		LPTOKENINFO pInfo
//		ByteArray& baDERCode
//
//  说明：
//-------------------------------------------------------------------
BOOL 
TokenInfoDEREncoding(
	IN LPTOKENINFO pInfo,
	OUT ByteArray& baDERCode
	)
{
	//Token Info
	//	;30 len tokenInfo
	//	;	02 len version
	//	;	04 len serialNumber
	//	;	0C len manufacturerID (utf8)
	//	;	80 len label(utf8)
	//	;	0F len mode(utf8)
	//	;	02 len pinMaxRetry (1个字节, HIGH为SO, LOW为USER) 

	if(pInfo == NULL)
		return FALSE;

	//version
	ByteArray baVersion;
	MakeByteArray((LPBYTE)"\x01", 1, baVersion);
	DEREncoding(0x02, baVersion.GetSize(), baVersion);

	//serialNumber
	ByteArray baSerialNumber;
	MakeByteArray((LPBYTE)pInfo->serialNumber, sizeof(pInfo->serialNumber), baSerialNumber);
	DEREncoding(0x04, baSerialNumber.GetSize(), baSerialNumber);

	//manufacturerID
	ByteArray baManufacturerID;
	MakeByteArray((LPBYTE)pInfo->manufacturerID, sizeof(pInfo->manufacturerID), baManufacturerID);
	DEREncoding(0x0C, baManufacturerID.GetSize(), baManufacturerID);

	//label
	ByteArray baLabel;
	MakeByteArray((LPBYTE)pInfo->label, sizeof(pInfo->label), baLabel);
	DEREncoding(0x80, baLabel.GetSize(), baLabel);

	//model
	ByteArray baModel;
	MakeByteArray((LPBYTE)pInfo->model, sizeof(pInfo->model), baModel);
	DEREncoding(0x0F, baModel.GetSize(), baModel);

	//pinMaxRetry
	ByteArray baPinMaxRetry;
	MakeByteArray(&(pInfo->pinMaxRetry), 1, baPinMaxRetry);
	DEREncoding(0x02, baPinMaxRetry.GetSize(), baPinMaxRetry);

	baDERCode.RemoveAll();
	ConnectByteArray(baDERCode, baVersion);
	ConnectByteArray(baDERCode, baSerialNumber);
	ConnectByteArray(baDERCode, baManufacturerID);
	ConnectByteArray(baDERCode, baLabel);
	ConnectByteArray(baDERCode, baModel);
	ConnectByteArray(baDERCode, baPinMaxRetry);

	DEREncoding(0x30, baDERCode.GetSize(), baDERCode);

	return TRUE;
}

//-------------------------------------------------------------------
//	功能：
//		解TokenInfo的DER编码
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		LPBYTE pbDERCode
//		DWORD dwDERCodeLen
//		LPTOKENINFO pInfo
//
//  说明：
//-------------------------------------------------------------------
BOOL
TokenInfoDERDecoding(
	IN LPBYTE pbDERCode,
	IN DWORD dwDERCodeLen,
	OUT LPTOKENINFO pInfo
	)
{
	//Token Info
	//	;30 len tokenInfo
	//	;	02 len version
	//	;	04 len serialNumber
	//	;	0C len manufacturerID (utf8)
	//	;	80 len label(utf8)
	//	;	0F len mode(utf8)
	//	;	02 len pinMaxRetry (1个字节, HIGH为SO, LOW为USER) 
	
	if(pInfo == NULL || pbDERCode == NULL)
		return FALSE;

	ByteArray baTokenInfo;
	MakeByteArray(pbDERCode, dwDERCodeLen, baTokenInfo);

	DWORD dwTag, dwLen;
	DERDecoding(baTokenInfo, dwTag, dwLen);
	if(dwTag != 0x30)
		return FALSE;

	//version
	DWORD dwVersion;
	dwLen = sizeof(dwVersion);
	if(!DERDecoding(baTokenInfo, dwTag, (LPBYTE)&dwVersion, dwLen))
		return FALSE;
	if(dwTag != 0x02)
		return FALSE;

	//serialNumber
	dwLen = sizeof(pInfo->serialNumber);
	if(!DERDecoding(baTokenInfo, dwTag, (LPBYTE)pInfo->serialNumber, dwLen))
		return FALSE;
	if(dwTag != 0x04)
		return FALSE;

	//manufacturerID
	dwLen = sizeof(pInfo->manufacturerID);
	if(!DERDecoding(baTokenInfo, dwTag, (LPBYTE)pInfo->manufacturerID, dwLen))
		return FALSE;
	if(dwTag != 0x0C)
		return FALSE;

	//label
	dwLen = sizeof(pInfo->label);
	if(!DERDecoding(baTokenInfo, dwTag, (LPBYTE)pInfo->label, dwLen))
		return FALSE;
	if(dwTag != 0x80)
		return FALSE;

	if(dwVersion != 0){
		//model
		dwLen = sizeof(pInfo->model);
		if(!DERDecoding(baTokenInfo, dwTag, (LPBYTE)pInfo->model, dwLen))
			return FALSE;
		if(dwTag != 0x0F)
			return FALSE;
	}

	dwLen = 1;
	if(!DERDecoding(baTokenInfo, dwTag, &(pInfo->pinMaxRetry), dwLen))
		return FALSE;
	if(dwTag != 0x02)
		return FALSE;

	return TRUE;
}
