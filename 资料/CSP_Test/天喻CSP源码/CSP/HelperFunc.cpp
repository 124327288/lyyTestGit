//-------------------------------------------------------------------
//	���ļ�Ϊ TY Cryptographic Service Provider ����ɲ���
//
//
//	��Ȩ���� ������Ϣ��ҵ���޹�˾ (c) 1996 - 2005 ����һ��Ȩ��
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
//	���ܣ�
//		��һ�ֽ����鷴ת
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		BYTE* pbBuf				�ֽ�����			 
//		DWORD dwBufLen			�ֽ���
//
//  ˵����
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
//	���ܣ�
//		����Կ������ת��Ϊ��Կ�㷨��ʶ
//
//	���أ�
//		�㷨��ʶ
//
//  ������
//		DWORD dwKeySpec	��Կ������
//
//  ˵����
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
//	���ܣ�
//		�ж�һ���ַ������Ƿ����һ���Ӵ�
//
//	���أ�
//		TRUE������		FALSE��������
//
//  ������
//		LPCTSTR lpszSource		Դ��
//		LPCTSTR lpszSub			�Ӵ�
//
//  ˵����
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
//	���ܣ�
//		����һ��ByteArray
//
//	���أ�
//		��
//
//  ������
//		LPBYTE pData
//		DWORD dwDataLen
//		ByteArray& arByte
//
//  ˵����
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
//	���ܣ�
//		��������ByteArray
//
//	���أ�
//		��
//
//  ������
//		ByteArray& destByte			
//		ByteArray srcByte
//
//  ˵����
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
//	���ܣ�
//		��ȡDER��������ֵĳ���
//
//	���أ�
//		DER������ܳ���, Ϊ0��ʾ����
//
//  ������
//		LPBYTE pDERCode				DER����
//		DWORD dwDERLen				DER����ĳ���
//		DWORD& dwTagFieldLen		�����ĳ���
//		DWORD& dwLenFieldLen		������ĳ���
//		DWORD& dwValueFieldLen		ֵ��ĳ���
//
//  ˵����
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
//	���ܣ�
//		����һ��DER����ĳ���
//
//	���أ�
//		DER����ĳ���	
//
//  ������
//		DWORD dwTagLen		��ǵĳ���
//		DWORD dwValueLen	ֵ�ĳ���
//
//  ˵����
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
//	���ܣ�
//		DER����
//
//	���أ�
//		��
//
//  ������
//		DWORD dwTag				���
//		DWORD dwLen				ֵ�ĳ���
//		ByteArray& Value		ֵ
//
//  ˵����
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
//	���ܣ�
//		DER����
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		ByteArray& baDERCode	DER����(IN)/ֵ(OUT)
//		DWORD& dwTag			���
//		DWORD& dwLen			����
//
//  ˵����
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
 
	//���Ϊ1�ֽ�
	b = baDERCode.GetAt(0);
	baDERCode.RemoveAt(0);
	dwTag = b;

	//����
	dwLen = 0;
	b = baDERCode.GetAt(0);
	baDERCode.RemoveAt(0);
	if(b < 0x80)
		dwLen = b;
	else{
		//���ȵ��ֽ���
		DWORD dwDERLenCountLen = b - 0x80;
		if(dwDERLenCountLen > (DWORD)baDERCode.GetSize())
			return FALSE;

		for(DWORD dwI = 0; dwI < dwDERLenCountLen; dwI++){
			b = baDERCode.GetAt(0);
			baDERCode.RemoveAt(0);
			dwLen += (b << 8*(dwDERLenCountLen - dwI - 1));
		}
	}

	//�����������ȥ��ǰ���0
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
//	���ܣ�
//		DER����
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		ByteArray& baDERCode	DER����(IN)/��һ��DER����(OUT)
//		DWORD& dwTag			���
//		LPBYTE pValue			ֵ
//		DWORD& dwValueLen		ֵ�ĳ���
//
//  ˵����
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

	//��ȡ��ǰDER��������ݵĳ��ȣ������ж��Ƿ�Ϊ�Ϸ���DER����
	DWORD dwTagFieldLen, dwLenFieldLen, dwValueFieldLen;
	DWORD dwTotalLen = GetDERCodeFieldLen(
		baDERCode.GetData(), baDERCode.GetSize(), dwTagFieldLen, dwLenFieldLen, dwValueFieldLen
		);
	if(dwTotalLen == 0 || dwTotalLen > (DWORD)baDERCode.GetSize())
		return FALSE;

	//����
	DWORD dwLen;
	DERDecoding(baDERCode, dwTag, dwLen);

	//�����������ȥ��ǰ���0
	DWORD dwRealLen = dwLen;
	if(dwTag == 0x02){
		if(baDERCode.GetAt(0) == 0x00 && 
			baDERCode.GetAt(1) > 0x7F)
			dwRealLen--;
	}

	//�жϻ����Ƿ��㹻��
	if(dwRealLen > dwValueLen)
		return FALSE;

	//����ֵ��
	memcpy(pValue, baDERCode.GetData() + (dwLen - dwRealLen), dwRealLen);
	dwValueLen = dwRealLen;

	//ָ����һ��DER����
	baDERCode.RemoveAt(0, dwLen);

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��TokenInfo����DER����
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		LPTOKENINFO pInfo
//		ByteArray& baDERCode
//
//  ˵����
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
	//	;	02 len pinMaxRetry (1���ֽ�, HIGHΪSO, LOWΪUSER) 

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
//	���ܣ�
//		��TokenInfo��DER����
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		LPBYTE pbDERCode
//		DWORD dwDERCodeLen
//		LPTOKENINFO pInfo
//
//  ˵����
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
	//	;	02 len pinMaxRetry (1���ֽ�, HIGHΪSO, LOWΪUSER) 
	
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
