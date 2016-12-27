#ifndef __TYCSP_HELPER_FUNCTIONS_H__
#define __TYCSP_HELPER_FUNCTIONS_H__

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
//		�����������λ��ͬһ����ַ
//-------------------------------------------------------------------
void ByteReverse(BYTE* pbBuf, DWORD dwBufLen);

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
ALG_ID KeyPairTypeToAlgid(DWORD dwKeySpec);

typedef CArrayTemplate<BYTE, BYTE> ByteArray;

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
	);

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
	);

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
	);

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
	);

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
	);

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
	);

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
	);

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
//		BYTE* pVersion
//
//  ˵����
//-------------------------------------------------------------------
BOOL 
TokenInfoDEREncoding(
	IN LPTOKENINFO pInfo,
	OUT ByteArray& baDERCode,
	IN BYTE* pVersion = NULL
	);

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
//		BYTE* pVersion
//
//  ˵����
//-------------------------------------------------------------------
BOOL
TokenInfoDERDecoding(
	IN LPBYTE pbDERCode,
	IN DWORD dwDERCodeLen,
	OUT LPTOKENINFO pInfo,
	OUT BYTE* pVersion = NULL
	);

#endif