#ifndef __TYCSP_HELPER_FUNCTIONS_H__
#define __TYCSP_HELPER_FUNCTIONS_H__

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
//		输入与输出可位于同一个地址
//-------------------------------------------------------------------
void ByteReverse(BYTE* pbBuf, DWORD dwBufLen);

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
ALG_ID KeyPairTypeToAlgid(DWORD dwKeySpec);

typedef CArrayTemplate<BYTE, BYTE> ByteArray;

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
	);

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
	);

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
	);

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
	);

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
	);

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
	);

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
	);

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
//		BYTE* pVersion
//
//  说明：
//-------------------------------------------------------------------
BOOL 
TokenInfoDEREncoding(
	IN LPTOKENINFO pInfo,
	OUT ByteArray& baDERCode,
	IN BYTE* pVersion = NULL
	);

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
//		BYTE* pVersion
//
//  说明：
//-------------------------------------------------------------------
BOOL
TokenInfoDERDecoding(
	IN LPBYTE pbDERCode,
	IN DWORD dwDERCodeLen,
	OUT LPTOKENINFO pInfo,
	OUT BYTE* pVersion = NULL
	);

#endif