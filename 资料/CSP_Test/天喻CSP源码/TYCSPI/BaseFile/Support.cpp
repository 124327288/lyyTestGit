#include "Stdafx.h"
#include "Support.h"
#include "HelperFunc.h"
#include "CryptSPI.h"
#include "CSPObject.h"
#include "Integer.h"
#include "des.h"
#include "queue.h"
#include "md5.h"
#include "sha.h"
#include "Base64.h"

//-------------------------------------------------------------------
//	���ܣ�
//		��ָ�����ֵ���Կ����,���û���򴴽�
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		DWORD dwCardIndex			������(��0��ʼ)
//		char* szName				��Կ��������
//		HCRYPTPROV* phProv 			�򿪻򴴽�����Կ�������
//		BOOL bCreateIfNoneExist		����������Ƿ񴴽�
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI
OpenKeyContainer(
	IN DWORD dwCardIndex,
	IN LPSTR szName, 
	OUT HCRYPTPROV* phProv, 
	IN BOOL bCreateIfNoneExist
	)
{
	//�������
	if(phProv == NULL)
		return FALSE;

	//�����Ŵ�
	BOOL bRetVal = CPAcquireContext(phProv, szName, 0, dwCardIndex);
	//���û������Ҫ�Ļ�,�����µ�
	if(!bRetVal && bCreateIfNoneExist)
		bRetVal = CPAcquireContext(phProv, szName, CRYPT_NEWKEYSET, dwCardIndex);

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��DER�������ʽ����ָ����Կ�ԵĹ�Կ
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			��Կ�����ľ��
//		HCRYPTKEY hKeyPair			��Կ��(˽Կ)�ľ��
//		LPBYTE lpPubKey				������Կ��DER����
//		LPDWORD lpPubKeyLen			����ĳ���/����ĳ���
//
//  ˵����
//		��Կ��ASN.1��ʾ
//		RSAPublicKey ::= SEQUENCE{
//			modulus INTEGER, -- n
//			publicExponent INTEGER -- e 
//			}
//-------------------------------------------------------------------
BOOL WINAPI
ExportPublicKey(
	IN HCRYPTPROV hProv,
	IN HCRYPTKEY hKeyPair,
	OUT LPBYTE lpPubKey,
	IN OUT LPDWORD lpPubKeyLen
	)
{
	if(g_ByteOrderMode != BOM_BIG_ENDIAN){
		TRACE_LINE("\nByteOrdeMode = LITTLE_ENDIAN\n");
	}
	else{
		TRACE_LINE("\nByteOrdeMode = BIG_ENDIAN\n");
	}

	//�������
	if(lpPubKeyLen == NULL)
		return FALSE;
	
	//������Կ��BLOB
	BYTE pbBlob[MAX_RSAPUBKEY_BLOB_LEN];
	DWORD dwBlobLen = sizeof(pbBlob);
	BOOL bRetVal = CPExportKey(
		hProv, hKeyPair, NULL, PUBLICKEYBLOB, 0, pbBlob, &dwBlobLen
		);
	if(!bRetVal)
		return FALSE;

	//��BLOB�л�ȡ������Կ��ģ����ָ��
	BYTE pbExponent[4], pbModulus[256];
	DWORD dwExponentLen, dwModulusLen;

	//Խ��Blob Header
	RSAPUBKEY* pbPubKey = (RSAPUBKEY* )(pbBlob + sizeof(BLOBHEADER));

	//�õ�ָ��
	Integer e(pbPubKey->pubexp);
	dwExponentLen = e.ByteCount();
	e.Encode(pbExponent, dwExponentLen);

	//�õ�ģ��
	dwModulusLen = pbPubKey->bitlen/8;
	memcpy(pbModulus, (LPBYTE)pbPubKey + sizeof(RSAPUBKEY), dwModulusLen);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(pbModulus, dwModulusLen);

	//���ɸù�Կ��DER����(PKCS#1)

	//��ģ������DER����
	ByteArray baModulus;
	MakeByteArray(pbModulus, dwModulusLen, baModulus);
	DEREncoding(0x02, baModulus.GetSize(), baModulus);

	//��ָ������DER����
	ByteArray baExponent;
	MakeByteArray(pbExponent, dwExponentLen, baExponent);
	DEREncoding(0x02, baExponent.GetSize(), baExponent);

	//�Թ�Կ����DER����
	ByteArray baPublicKey;
	ConnectByteArray(baPublicKey, baModulus);
	ConnectByteArray(baPublicKey, baExponent);
	DEREncoding(0x30, baPublicKey.GetSize(), baPublicKey);

	//�жϿռ��Ƿ��㹻��
	if(lpPubKey == NULL){
		*lpPubKeyLen = baPublicKey.GetSize();
	}
	else{
		if(*lpPubKeyLen < (DWORD)baPublicKey.GetSize()){
			*lpPubKeyLen = baPublicKey.GetSize();
			return FALSE;
		}
		else{
			*lpPubKeyLen = baPublicKey.GetSize();
			memcpy(lpPubKey, baPublicKey.GetData(), baPublicKey.GetSize());
		}
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��DER�������ʽ����ָ����Կ�Ե�˽Կ
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			��Կ�����ľ��
//		HCRYPTKEY hKeyPair			��Կ��(˽Կ)�ľ��
//		LPBYTE lpPriKey				����˽Կ��DER����
//		LPDWORD lpPriKeyLen			����ĳ���/����ĳ���
//
//  ˵����
//		˽Կ��ASN.1��ʾ
//			RSAPrivateKey ::= SEQUENCE {
//				version Version,
//				modulus INTEGER, -- n
//				publicExponent INTEGER, -- e
//				privateExponent INTEGER, -- d
//				prime1 INTEGER, -- p
//				prime2 INTEGER, -- q
//				exponent1 INTEGER, -- d mod (p-1)
//				exponent2 INTEGER, -- d mod (q-1)
//				coefficient INTEGER -- (inverse of q) mod p 
//				}
//
//			Version ::= INTEGER
//-------------------------------------------------------------------
BOOL WINAPI
ExportPrivateKey(
	IN HCRYPTPROV hProv,
	IN HCRYPTKEY hKeyPair,
	OUT LPBYTE lpPriKey,
	IN OUT LPDWORD lpPriKeyLen
	)
{
	if(g_ByteOrderMode != BOM_BIG_ENDIAN){
		TRACE_LINE("\nByteOrdeMode = LITTLE_ENDIAN\n");
	}
	else{
		TRACE_LINE("\nByteOrdeMode = BIG_ENDIAN\n");
	}

	//�������
	if(lpPriKeyLen == NULL)
		return FALSE;
	
	//����˽Կ��BLOB
	BYTE pbBlob[MAX_RSAPRIKEY_BLOB_LEN];
	DWORD dwBlobLen = sizeof(pbBlob);
	BOOL bRetVal = CPExportKey(
		hProv, hKeyPair, NULL, PRIVATEKEYBLOB, 0, pbBlob, &dwBlobLen
		);
	if(!bRetVal)
		return FALSE;

	//Խ��Blob Header
	RSAPUBKEY* pbPubKey = (RSAPUBKEY* )(pbBlob + sizeof(BLOBHEADER));

	//e
	BYTE pbExponent[4];
	DWORD dwExponentLen;
	Integer e(pbPubKey->pubexp);
	dwExponentLen = e.ByteCount();
	e.Encode(pbExponent, dwExponentLen);

	DWORD dwOffset = sizeof(RSAPUBKEY);

	//n
	BYTE pbModulus[MAX_RSAKEYPAIR_MODULUS_LEN/8];	
	DWORD dwModulusLen = sizeof(pbModulus);
	memcpy(pbModulus, (LPBYTE)pbPubKey + dwOffset, dwModulusLen);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(pbModulus, dwModulusLen);
	dwOffset += dwModulusLen;

	//p
	BYTE pbPrime1[MAX_RSAKEYPAIR_MODULUS_LEN / 16];
	DWORD dwPrime1Len = sizeof(pbPrime1);
	memcpy(pbPrime1, (LPBYTE)pbPubKey + dwOffset, dwPrime1Len);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(pbPrime1, dwPrime1Len);
	dwOffset += dwPrime1Len;

	//q
	BYTE pbPrime2[MAX_RSAKEYPAIR_MODULUS_LEN / 16];
	DWORD dwPrime2Len = sizeof(pbPrime2);
	memcpy(pbPrime2, (LPBYTE)pbPubKey + dwOffset, dwPrime2Len);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(pbPrime2, dwPrime2Len);
	dwOffset += dwPrime2Len;

	//dp
	BYTE pbExponent1[MAX_RSAKEYPAIR_MODULUS_LEN / 16];
	DWORD dwExponent1Len = sizeof(pbExponent1);
	memcpy(pbExponent1, (LPBYTE)pbPubKey + dwOffset, dwExponent1Len);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(pbExponent1, dwExponent1Len);
	dwOffset += dwExponent1Len;

	//dq
	BYTE pbExponent2[MAX_RSAKEYPAIR_MODULUS_LEN / 16];
	DWORD dwExponent2Len = sizeof(pbExponent2);
	memcpy(pbExponent2, (LPBYTE)pbPubKey + dwOffset, dwExponent2Len);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(pbExponent2, dwExponent2Len);
	dwOffset += dwExponent2Len;

	//qinv
	BYTE pbCoefficient[MAX_RSAKEYPAIR_MODULUS_LEN / 16];
	DWORD dwCoefficientLen = sizeof(pbCoefficient);
	memcpy(pbCoefficient, (LPBYTE)pbPubKey + dwOffset, dwCoefficientLen);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(pbCoefficient, dwCoefficientLen);
	dwOffset += dwCoefficientLen;

	//d
	BYTE pbPrivateExponent[MAX_RSAKEYPAIR_MODULUS_LEN / 8];
	DWORD dwPrivateExponentLen = sizeof(pbPrivateExponent);
	memcpy(pbPrivateExponent, (LPBYTE)pbPubKey + dwOffset, dwPrivateExponentLen);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(pbPrivateExponent, dwPrivateExponentLen);
	dwOffset += dwPrivateExponentLen;

	//���ɸ�˽Կ��DER����(PKCS#1)

	//Version
	ByteArray baVersion;
	baVersion.Add(0);
	DEREncoding(0x02, baVersion.GetSize(), baVersion);

	//n
	ByteArray baModulus;
	MakeByteArray(pbModulus, dwModulusLen, baModulus);
	DEREncoding(0x02, baModulus.GetSize(), baModulus);

	//e
	ByteArray baExponent;
	MakeByteArray(pbExponent, dwExponentLen, baExponent);
	DEREncoding(0x02, baExponent.GetSize(), baExponent);

	//d
	ByteArray baPrivateExponent;
	MakeByteArray(pbPrivateExponent, dwPrivateExponentLen, baPrivateExponent);
	DEREncoding(0x02, baPrivateExponent.GetSize(), baPrivateExponent);

	//p
	ByteArray baPrime1;
	MakeByteArray(pbPrime1, dwPrime1Len, baPrime1);
	DEREncoding(0x02, baPrime1.GetSize(), baPrime1);

	//q
	ByteArray baPrime2;
	MakeByteArray(pbPrime2, dwPrime2Len, baPrime2);
	DEREncoding(0x02, baPrime2.GetSize(), baPrime2);

	//dp
	ByteArray baExponent1;
	MakeByteArray(pbExponent1, dwExponent1Len, baExponent1);
	DEREncoding(0x02, baExponent1.GetSize(), baExponent1);

	//dq
	ByteArray baExponent2;
	MakeByteArray(pbExponent2, dwExponent2Len, baExponent2);
	DEREncoding(0x02, baExponent2.GetSize(), baExponent2);

	//qinv
	ByteArray baCoefficient;
	MakeByteArray(pbCoefficient, dwCoefficientLen, baCoefficient);
	DEREncoding(0x02, baCoefficient.GetSize(), baCoefficient);

	//�Թ�Կ����DER����
	ByteArray baPrivateKey;
	ConnectByteArray(baPrivateKey, baVersion);
	ConnectByteArray(baPrivateKey, baModulus);
	ConnectByteArray(baPrivateKey, baExponent);
	ConnectByteArray(baPrivateKey, baPrivateExponent);
	ConnectByteArray(baPrivateKey, baPrime1);
	ConnectByteArray(baPrivateKey, baPrime2);
	ConnectByteArray(baPrivateKey, baExponent1);
	ConnectByteArray(baPrivateKey, baExponent2);
	ConnectByteArray(baPrivateKey, baCoefficient);
	DEREncoding(0x30, baPrivateKey.GetSize(), baPrivateKey);

	//�жϿռ��Ƿ��㹻��
	if(lpPriKey == NULL){
		*lpPriKeyLen = baPrivateKey.GetSize();
	}
	else{
		if(*lpPriKeyLen < (DWORD)baPrivateKey.GetSize()){
			*lpPriKeyLen = baPrivateKey.GetSize();
			return FALSE;
		}
		else{
			*lpPriKeyLen = baPrivateKey.GetSize();
			memcpy(lpPriKey, baPrivateKey.GetData(), baPrivateKey.GetSize());
		}
	}

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		������RSA��ԿDER��������д���ȥ����0
//
//	���أ�
//		������ĳ���
//
//  ������
//		LPBYTE pbData		�ս����һ��Ԫ��
//		DWORD dwDataLen		��Ԫ�صĳ���
//
//  ˵����
//		pbData�������㹻�Ŀռ������ɲ����0(һ���ֽ�)
//-------------------------------------------------------------------
DWORD FixRSADERDecodeZero(LPBYTE pbData, DWORD dwDataLen)
{
	if(dwDataLen % 2 == 0)
		return dwDataLen;

	memmove(pbData + 1, pbData, dwDataLen);
	pbData[0] = 0;

	return (dwDataLen + 1);
}

//-------------------------------------------------------------------
//	���ܣ�
//		�⹫Կ��DER���벢������Կ����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv					�������Կ�������
//		ALG_ID algId						��Կ����
//		LPBYTE pbPublicKeyDERCode			��Կ��DER����
//		DWORD dwPublicKeyDERCodeLen			��ԿDER����ĳ���
//		HCRYPTKEY* phPublicKey				�����Ĺ�Կ���
//
//  ˵����
//		��Կ��ASN.1��ʾ
//		RSAPublicKey ::= SEQUENCE{
//			modulus INTEGER, -- n
//			publicExponent INTEGER -- e 
//			}
//-------------------------------------------------------------------
BOOL WINAPI
DecodeAndCreatePublicKey(
	IN HCRYPTPROV hProv,
	IN ALG_ID algId,
	IN LPBYTE pbPublicKeyDERCode,
	IN DWORD dwPublicKeyDERCodeLen,
	OUT HCRYPTKEY* phPublicKey
	)
{
	if(g_ByteOrderMode != BOM_BIG_ENDIAN){
		TRACE_LINE("\nByteOrdeMode = LITTLE_ENDIAN\n");
	}
	else{
		TRACE_LINE("\nByteOrdeMode = BIG_ENDIAN\n");
	}

	//������
	if(pbPublicKeyDERCode == NULL || phPublicKey == NULL)
		return FALSE;

	//DER����
	ByteArray baPublicKey;
	MakeByteArray(pbPublicKeyDERCode, dwPublicKeyDERCodeLen, baPublicKey);
	DWORD dwTag, dwLen;
	if(!DERDecoding(baPublicKey, dwTag, dwLen))
		return FALSE;
	if(dwTag != 0x30)
		return FALSE;

	//ģ��
	BYTE Modulus[MAX_RSAKEYPAIR_MODULUS_LEN / 8];
	DWORD dwModulusLen = sizeof(Modulus); 
	if(!DERDecoding(baPublicKey, dwTag, Modulus, dwModulusLen))
		return FALSE;
	if(dwTag != 0x02)
		return FALSE;
	dwModulusLen = FixRSADERDecodeZero(Modulus, dwModulusLen);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(Modulus, dwModulusLen);

	//����ָ��
	BYTE PublicExponent[4];
	DWORD dwPublicExponentLen = sizeof(PublicExponent);
	if(!DERDecoding(baPublicKey, dwTag, PublicExponent, dwPublicExponentLen))
		return FALSE;
	if(dwTag != 0x02)
		return FALSE;

	//������ԿBlob
	BYTE pbKeyBlob[MAX_RSAPUBKEY_BLOB_LEN];
	DWORD dwKeyBlobLen = 0;

	BLOBHEADER bh;
	bh.bType = PUBLICKEYBLOB;
	bh.bVersion = 0x02;
	bh.reserved = NULL;
	bh.aiKeyAlg = algId;
	memcpy(pbKeyBlob, (BYTE *)(&bh), sizeof(BLOBHEADER));
	dwKeyBlobLen += sizeof(BLOBHEADER);

	RSAPUBKEY rsapuk;
	memset(&rsapuk, 0, sizeof(RSAPUBKEY));
	rsapuk.bitlen = dwModulusLen*8;
	rsapuk.magic = 0x31415352;
	ByteReverse(PublicExponent, dwPublicExponentLen);
	memcpy((LPBYTE)&(rsapuk.pubexp), PublicExponent, dwPublicExponentLen);
	memcpy(pbKeyBlob + dwKeyBlobLen, (LPBYTE)&rsapuk, sizeof(RSAPUBKEY));
	dwKeyBlobLen += sizeof(RSAPUBKEY);

	//ģ��
	memcpy(pbKeyBlob + dwKeyBlobLen, Modulus, dwModulusLen);
	dwKeyBlobLen += dwModulusLen;

	//���ɹ�Կ����
	return CPImportKey(
		hProv, pbKeyBlob, dwKeyBlobLen, NULL, 0, phPublicKey
		);
}

//-------------------------------------------------------------------
//	���ܣ�
//		��˽Կ��DER���벢����˽Կ����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv					�������Կ�������
//		ALG_ID algId						˽Կ����
//		LPBYTE pbPrivateKeyDERCode			˽Կ��DER����
//		DWORD dwPrivateKeyDERCodeLen		˽ԿDER����ĳ���
//		BOOL bExportAble					�Ƿ�ɵ���
//		HCRYPTKEY* phPrivateKey				������˽Կ���
//
//  ˵����
//		˽Կ��ASN.1��ʾ
//			RSAPrivateKey ::= SEQUENCE {
//				version Version,
//				modulus INTEGER, -- n
//				publicExponent INTEGER, -- e
//				privateExponent INTEGER, -- d
//				prime1 INTEGER, -- p
//				prime2 INTEGER, -- q
//				exponent1 INTEGER, -- d mod (p-1)
//				exponent2 INTEGER, -- d mod (q-1)
//				coefficient INTEGER -- (inverse of q) mod p 
//				}
//
//			Version ::= INTEGER
//-------------------------------------------------------------------
BOOL _ImportPrivateKeyDER(
	IN HCRYPTPROV hProv,
	IN ALG_ID algId,
	IN LPBYTE pbPrivateKeyDERCode,
	IN DWORD dwPrivateKeyDERCodeLen,
	IN BOOL bExportAble,
	OUT HCRYPTKEY* phPrivateKey
	)
{
	if(g_ByteOrderMode != BOM_BIG_ENDIAN){
		TRACE_LINE("\nByteOrdeMode = LITTLE_ENDIAN\n");
	}
	else{
		TRACE_LINE("\nByteOrdeMode = BIG_ENDIAN\n");
	}
	
	//������
	if(pbPrivateKeyDERCode == NULL || phPrivateKey == NULL)
		return FALSE;

	/////////////////////////////////////////////////////////////////
	//��˽ԿDER���� ��ʼ
	ByteArray baPrivateKey;
	MakeByteArray(pbPrivateKeyDERCode, dwPrivateKeyDERCodeLen, baPrivateKey);

	//SEQUENCE
	DWORD dwTag, dwLen;
	DERDecoding(baPrivateKey, dwTag, dwLen);
	if(dwTag != 0x30)
		return FALSE;

	//Version
	DWORD dwTagFieldLen, dwLenFieldLen, dwValueFieldLen;
	DWORD dwTotalLen = GetDERCodeFieldLen(
		baPrivateKey.GetData(), baPrivateKey.GetSize(), dwTagFieldLen, dwLenFieldLen, dwValueFieldLen
		);
	if(dwTotalLen == 0 || dwTotalLen > (DWORD)baPrivateKey.GetSize())
		return FALSE;
	baPrivateKey.RemoveAt(0, dwTotalLen);

	//Modulus
	BYTE Modulus[MAX_RSAKEYPAIR_MODULUS_LEN / 8];
	DWORD dwModulusLen = sizeof(Modulus); 
	if(!DERDecoding(baPrivateKey, dwTag, Modulus, dwModulusLen))
		return FALSE;
	if(dwTag != 0x02)
		return FALSE;
	dwModulusLen = FixRSADERDecodeZero(Modulus, dwModulusLen);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(Modulus, dwModulusLen);

	//PublicExponent
	BYTE PublicExponent[4];
	DWORD dwPublicExponentLen = sizeof(PublicExponent);
	if(!DERDecoding(baPrivateKey, dwTag, PublicExponent, dwPublicExponentLen))
		return FALSE;
	if(dwTag != 0x02)
		return FALSE;

	//PrivateExponent
	BYTE PrivateExponent[MAX_RSAKEYPAIR_MODULUS_LEN / 8];
	DWORD dwPrivateExponentLen = sizeof(PrivateExponent);
	if(!DERDecoding(baPrivateKey, dwTag, PrivateExponent, dwPrivateExponentLen))
		return FALSE;
	if(dwTag != 0x02)
		return FALSE;
	dwPrivateExponentLen = FixRSADERDecodeZero(PrivateExponent, dwPrivateExponentLen);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(PrivateExponent, dwPrivateExponentLen);

	//Prime1
	BYTE Prime1[MAX_RSAKEYPAIR_MODULUS_LEN / 16];
	DWORD dwPrime1Len = sizeof(Prime1);
	if(!DERDecoding(baPrivateKey, dwTag, Prime1, dwPrime1Len))
		return FALSE;
	if(dwTag != 0x02)
		return FALSE;
	dwPrime1Len = FixRSADERDecodeZero(Prime1, dwPrime1Len);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(Prime1, dwPrime1Len);

	//Prime2
	BYTE Prime2[MAX_RSAKEYPAIR_MODULUS_LEN / 16];
	DWORD dwPrime2Len = sizeof(Prime2);
	if(!DERDecoding(baPrivateKey, dwTag, Prime2, dwPrime2Len))
		return FALSE;
	if(dwTag != 0x02)
		return FALSE;
	dwPrime2Len = FixRSADERDecodeZero(Prime2, dwPrime2Len);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(Prime2, dwPrime2Len);

	//Exponent1
	BYTE Exponent1[MAX_RSAKEYPAIR_MODULUS_LEN / 16];
	DWORD dwExponent1Len = sizeof(Exponent1);
	if(!DERDecoding(baPrivateKey, dwTag, Exponent1, dwExponent1Len))
		return FALSE;
	if(dwTag != 0x02)
		return FALSE;
	dwExponent1Len = FixRSADERDecodeZero(Exponent1, dwExponent1Len);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(Exponent1, dwExponent1Len);

	//Exponent2
	BYTE Exponent2[MAX_RSAKEYPAIR_MODULUS_LEN / 16];
	DWORD dwExponent2Len = sizeof(Exponent2);
	if(!DERDecoding(baPrivateKey, dwTag, Exponent2, dwExponent2Len))
		return FALSE;
	if(dwTag != 0x02)
		return FALSE;
	dwExponent2Len = FixRSADERDecodeZero(Exponent2, dwExponent2Len);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(Exponent2, dwExponent2Len);

	//Coefficient
	BYTE Coefficient[MAX_RSAKEYPAIR_MODULUS_LEN / 16];
	DWORD dwCoefficientLen = sizeof(Coefficient);
	if(!DERDecoding(baPrivateKey, dwTag, Coefficient, dwCoefficientLen))
		return FALSE;
	if(dwTag != 0x02)
		return FALSE;
	dwCoefficientLen = FixRSADERDecodeZero(Coefficient, dwCoefficientLen);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(Coefficient, dwCoefficientLen);

	//��˽ԿDER����	���
	/////////////////////////////////////////////////////////////////

	/////////////////////////////////////////////////////////////////
	//����˽ԿBlob ��ʼ
	BYTE pbKeyBlob[MAX_RSAPRIKEY_BLOB_LEN];
	DWORD dwBlobLen = 0;
	BLOBHEADER bh;
	bh.bType = PRIVATEKEYBLOB;
	bh.bVersion = 0x02;
	bh.reserved = NULL;
	bh.aiKeyAlg = algId;
	memcpy(pbKeyBlob, LPBYTE(&bh), sizeof(BLOBHEADER));
	dwBlobLen += sizeof(BLOBHEADER);
	
	RSAPUBKEY rsapuk;
	memset(&rsapuk, 0, sizeof(RSAPUBKEY));
	rsapuk.bitlen = dwModulusLen*8;
	ByteReverse(PublicExponent, dwPublicExponentLen);
	memcpy((LPBYTE)&(rsapuk.pubexp), PublicExponent, dwPublicExponentLen);
	rsapuk.magic = 0x32415352;
	memcpy(pbKeyBlob + dwBlobLen, (LPBYTE)&rsapuk, sizeof(RSAPUBKEY));
	dwBlobLen += sizeof(RSAPUBKEY);

	//Modulus
	memcpy(pbKeyBlob + dwBlobLen, Modulus, dwModulusLen);
	dwBlobLen += dwModulusLen;

	//Prime1
	memcpy(pbKeyBlob + dwBlobLen, Prime1, dwPrime1Len);
	dwBlobLen += dwPrime1Len;

	//Prime2
	memcpy(pbKeyBlob + dwBlobLen, Prime2, dwPrime2Len);
	dwBlobLen += dwPrime2Len;

	//Exponent1
	memcpy(pbKeyBlob + dwBlobLen, Exponent1, dwExponent1Len);
	dwBlobLen += dwExponent1Len;

	//Exponent2
	memcpy(pbKeyBlob + dwBlobLen, Exponent2, dwExponent2Len);
	dwBlobLen += dwExponent2Len;

	//Coefficient
	memcpy(pbKeyBlob + dwBlobLen, Coefficient, dwCoefficientLen);
	dwBlobLen += dwCoefficientLen;
	
	//PrivateExponent
	memcpy(pbKeyBlob + dwBlobLen, PrivateExponent, dwPrivateExponentLen);
	dwBlobLen += dwPrivateExponentLen;

	//����˽ԿBlob ����
	/////////////////////////////////////////////////////////////////

	DWORD dwFlags = CRYPT_USER_PROTECTED;
	if(bExportAble) dwFlags |= CRYPT_EXPORTABLE;
	
	//���뵽��Կ������
	return CPImportKey(hProv, pbKeyBlob, dwBlobLen, NULL, dwFlags, phPrivateKey);
}

//-------------------------------------------------------------------
//	���ܣ�
//		��˽Կ��DER���벢����˽Կ����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv					�������Կ�������
//		ALG_ID algId						˽Կ����
//		LPBYTE pbPrivateKeyDERCode			˽Կ��DER����
//		DWORD dwPrivateKeyDERCodeLen		˽ԿDER����ĳ���
//		HCRYPTKEY* phPrivateKey				������˽Կ���
//
//  ˵����
//		˽Կ��ASN.1��ʾ
//			RSAPrivateKey ::= SEQUENCE {
//				version Version,
//				modulus INTEGER, -- n
//				publicExponent INTEGER, -- e
//				privateExponent INTEGER, -- d
//				prime1 INTEGER, -- p
//				prime2 INTEGER, -- q
//				exponent1 INTEGER, -- d mod (p-1)
//				exponent2 INTEGER, -- d mod (q-1)
//				coefficient INTEGER -- (inverse of q) mod p 
//				}
//
//			Version ::= INTEGER
//-------------------------------------------------------------------
BOOL WINAPI
DecodeAndCreatePrivateKey(
	IN HCRYPTPROV hProv,
	IN ALG_ID algId,
	IN LPBYTE pbPrivateKeyDERCode,
	IN DWORD dwPrivateKeyDERCodeLen,
	OUT HCRYPTKEY* phPrivateKey
	)
{
	return _ImportPrivateKeyDER(hProv, algId, pbPrivateKeyDERCode, dwPrivateKeyDERCodeLen, FALSE, phPrivateKey);
}

//-------------------------------------------------------------------
//	���ܣ�
//		��˽Կ��DER���벢����˽Կ����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv					�������Կ�������
//		ALG_ID algId						˽Կ����
//		LPBYTE pbPrivateKeyDERCode			˽Կ��DER����
//		DWORD dwPrivateKeyDERCodeLen		˽ԿDER����ĳ���
//		BOOL bExportAble					�Ƿ�ɵ���
//		HCRYPTKEY* phPrivateKey				������˽Կ���
//
//  ˵����
//		˽Կ��ASN.1��ʾ
//			RSAPrivateKey ::= SEQUENCE {
//				version Version,
//				modulus INTEGER, -- n
//				publicExponent INTEGER, -- e
//				privateExponent INTEGER, -- d
//				prime1 INTEGER, -- p
//				prime2 INTEGER, -- q
//				exponent1 INTEGER, -- d mod (p-1)
//				exponent2 INTEGER, -- d mod (q-1)
//				coefficient INTEGER -- (inverse of q) mod p 
//				}
//
//			Version ::= INTEGER
//-------------------------------------------------------------------
BOOL WINAPI
DecodeAndCreatePrivateKey2(
	IN HCRYPTPROV hProv,
	IN ALG_ID algId,
	IN LPBYTE pbPrivateKeyDERCode,
	IN DWORD dwPrivateKeyDERCodeLen,
	IN BOOL bExportAble,
	OUT HCRYPTKEY* phPrivateKey
	)
{
	return _ImportPrivateKeyDER(hProv, algId, pbPrivateKeyDERCode, dwPrivateKeyDERCodeLen, bExportAble, phPrivateKey);
}

//-------------------------------------------------------------------
//	���ܣ�
//		�ԳƼӽ��ܵĿ鳤����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			��Կ�������
//		ALG_ID algId				�㷨��ʶ
//		LPBYTE pbKey				��Կֵ
//		BOOL bEncrypt				TRUE������	FALSE������
//		LPBYTE pbInData				����
//		DWORD dwDataLen				���ݵĳ���
//		LPBYTE pbOutData			����
//
//  ˵����
//		���������ĵĳ�������ȵ������ĵĳ��ȱ���Ϊ�鳤��������
//	��Щ�����߱��뱣֤���ں����ڲ��������
//-------------------------------------------------------------------
BOOL
SymmCipherBlock(
	IN HCRYPTPROV hProv,
	IN ALG_ID algId,
	IN LPBYTE pbKey, 
	IN BOOL bEncrypt,
	IN LPBYTE pbInData,
	IN DWORD dwDataLen,
	OUT LPBYTE pbOutData
	)
{
	//�������
	if(pbKey == NULL || pbInData == NULL || pbOutData == NULL)
		return FALSE;

	if(algId == CALG_3DES_112){
		if(bEncrypt){
			DES_EDE_Encryption encrypt(pbKey);
			for(int i = 0; i < dwDataLen / 8; i++)
				encrypt.ProcessBlock(pbInData + i*8, pbOutData + i*8);
		}
		else{
			DES_EDE_Decryption decrypt(pbKey);
			for(int i = 0; i < dwDataLen / 8; i++)
				decrypt.ProcessBlock(pbInData + i*8, pbOutData + i*8);
		}
	}
	else if(algId == CALG_DES){
		if(bEncrypt){
			DESEncryption encrypt(pbKey);
			for(int i = 0; i < dwDataLen / 8; i++)
				encrypt.ProcessBlock(pbInData + i*8, pbOutData + i*8);
		}
		else{
			DESDecryption decrypt(pbKey);
			for(int i = 0; i < dwDataLen / 8; i++)
				decrypt.ProcessBlock(pbInData + i*8, pbOutData + i*8);
		}
	}
	else if(algId == CALG_3DES){
		if(bEncrypt){
			TripleDES_Encryption encrypt(pbKey);
			for(int i = 0; i < dwDataLen / 8; i++)
				encrypt.ProcessBlock(pbInData + i*8, pbOutData + i*8);
		}
		else{
			TripleDES_Decryption decrypt(pbKey);
			for(int i = 0; i < dwDataLen / 8; i++)
				decrypt.ProcessBlock(pbInData + i*8, pbOutData + i*8);
		}
	}
	else if(algId == CALG_SSF33){
		//ͨ����Կ���������ȡCSP����
		HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
		CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
		if(pCSPObject == NULL)
			return FALSE;

		//����SSF33��Կ
		BYTE cCommand[256];
		DWORD dwResLen;
		WORD wSW;
		memcpy(cCommand, "\x80\xd4\x01\x00\x18\x03\x01\x02\x0a\x0f\x00\x0f\xff", 13);
		memcpy(cCommand + 13, pbKey, 16);
		BOOL bRetVal = pCSPObject->SendCommand(cCommand, 13 + 16, NULL, NULL, &wSW);
		//�ϵ��ļ�ϵͳ��û��Ԥ�Ȱ�װSSF33��Կ
		if(bRetVal == FALSE){
			if(wSW != 0x9403) return FALSE;
			memcpy(cCommand, "\x80\xd4\x00\x00\x18\x03\x01\x02\x0a\x0f\x00\x0f\xff", 13);
			memcpy(cCommand + 13, pbKey, 16);
			if(!pCSPObject->SendCommand(cCommand, 13 + 16))
				return FALSE;
		}

		//SSF33�ӽ���
		#define SSF33_MAX_BLOCKSIZE 16*8
		BYTE cSSF33Ins = 0x1B;
		DWORD dwOffset = 0;
		while(dwOffset < dwDataLen){
			DWORD dwBlockSize = dwDataLen - dwOffset;
			if(dwBlockSize > SSF33_MAX_BLOCKSIZE) 
				dwBlockSize = SSF33_MAX_BLOCKSIZE;
			cCommand[0] = 0x80;
			cCommand[1] = cSSF33Ins;
			cCommand[2] = 0x03;
			cCommand[3] = (bEncrypt ? 0x00 : 0x01);
			cCommand[4] = (BYTE)dwBlockSize;
			memcpy(cCommand + 5, pbInData + dwOffset , dwBlockSize);
			if(!pCSPObject->SendCommand(cCommand, 5 + dwBlockSize, pbOutData + dwOffset, &dwResLen, &wSW)){
				if(wSW == 0x6D00){
					cSSF33Ins = 0x32;
					cCommand[1] = cSSF33Ins;
					if(!pCSPObject->SendCommand(cCommand, 5 + dwBlockSize, pbOutData + dwOffset, &dwResLen, &wSW))
						return FALSE;
				}
				else
					return FALSE;
			}

			dwOffset += dwBlockSize;
		}
	}
	else
		return FALSE;

	return TRUE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		ʹ�öԳ���Կ�����ݽ��м�/����
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv			��Կ�������
//		ALG_ID algId				�㷨��ʶ
//		LPBYTE pbKey				Ҫ����/���ܵ���Կֵ
//		DWORD dwKeyLen				����/���ܵ���Կ����
//		BOOL bEncrypt				����(TRUE)/����(FALSE)
//		LPBYTE pbInData				ԭʼ����
//		DWORD dwInDataLen			ԭʼ���ݳ���
//		LPBYTE pbOutData			�ӽ��ܺ������
//		LPDWORD pdwOutDataLen		�ӽ��ܺ�����ݳ���
//		BOOL bPadding				�Ƿ��������
//
//  ˵����
//		Ŀǰ����ECB��ģʽ
//-------------------------------------------------------------------
BOOL WINAPI
SymmCipher(
	IN HCRYPTPROV hProv,
	IN ALG_ID algId,
	IN LPBYTE pbKey,
	IN DWORD dwKeyLen,
	IN BOOL bEncrypt,
	IN LPBYTE pbInData,
	IN DWORD dwInDataLen,
	OUT LPBYTE pbOutData,
	OUT LPDWORD pdwOutDataLen,
	IN BOOL bPadding
	)
{
	//�������
	if(pbKey == NULL || pbInData == NULL || pdwOutDataLen == NULL)
		return FALSE;

	//���볤��Ϊ0���账��
	if(dwInDataLen == 0){
		*pdwOutDataLen = 0;
		return TRUE;
	}

	//ȷ��ÿ���㷨��ĳ���
	DWORD dwBlockSize;
	if(algId == CALG_DES){
		if(dwKeyLen != 8)
			return FALSE;
		dwBlockSize = 8;
	}
	else if(algId == CALG_3DES_112){
		if(dwKeyLen != 16)
			return FALSE;
		dwBlockSize = 8;
	}
	else if(algId == CALG_3DES){
		if(dwKeyLen != 24)
			return FALSE;
		dwBlockSize = 8;
	}
	else if(algId == CALG_SSF33){
		if(dwKeyLen != 16)
			return FALSE;
		dwBlockSize = 16;
	}
	else
		return FALSE;

	//����
	if(bEncrypt){
		//�������ĵĴ�С
		DWORD dwCipherTextLen;
		if(bPadding)
			dwCipherTextLen = (dwInDataLen / dwBlockSize + 1)*dwBlockSize;
		else{
			//�������Ҫ������������ݱ����ǿ鳤��������
			if(dwInDataLen % dwBlockSize)
				return FALSE;
			dwCipherTextLen = dwInDataLen;
		}

		//ȷ������ռ��Ƿ��㹻
		if(pbOutData == NULL){
			*pdwOutDataLen = dwCipherTextLen;
			return TRUE;
		}
		else{
			if(*pdwOutDataLen < dwCipherTextLen){
				*pdwOutDataLen = dwCipherTextLen;
				return FALSE;
			}
		}

		memcpy(pbOutData, pbInData, dwInDataLen);
		if(bPadding){
			BYTE pad = dwBlockSize - (dwInDataLen % dwBlockSize);
			memset(pbOutData + dwInDataLen, pad, pad);
		}

		//�������
		if(!SymmCipherBlock(hProv, algId, pbKey, TRUE, pbOutData, dwCipherTextLen, pbOutData))
			return FALSE;
		
		*pdwOutDataLen = dwCipherTextLen;

		return TRUE;
	}
	//����
	else{
		//���ı���ΪdwBlockSize��������
		if(dwInDataLen % dwBlockSize)
			return FALSE;

		//�������ɵ����ķ�����ʱ�ռ���
		LPBYTE pbPlainText = new BYTE[dwInDataLen];
		if(pbPlainText == NULL)
			return FALSE;
		memcpy(pbPlainText, pbInData, dwInDataLen);
		if(!SymmCipherBlock(hProv, algId, pbKey, FALSE, pbPlainText, dwInDataLen, pbPlainText)){
			delete pbPlainText;
			return FALSE;
		}

		DWORD dwPlainTextLen;
		if(bPadding){
			BYTE pad = pbPlainText[dwInDataLen - 1];
			if(pad < 1 || pad > dwBlockSize){
				delete pbPlainText;
				return FALSE;
			}
			dwPlainTextLen = dwInDataLen - pad;
		}
		else
			dwPlainTextLen = dwInDataLen;

		//ȷ������ռ��Ƿ��㹻
		BOOL bRetVal = TRUE;
		if(pbOutData == NULL)
			*pdwOutDataLen = dwPlainTextLen;
		else{
			if(*pdwOutDataLen < dwPlainTextLen){
				*pdwOutDataLen = dwPlainTextLen;
				bRetVal = FALSE;
			}
			else{
				*pdwOutDataLen = dwPlainTextLen;
				memcpy(pbOutData, pbPlainText, dwPlainTextLen);
			}
		}
		delete pbPlainText;

		return bRetVal;
	}

	return FALSE;
}

//-------------------------------------------------------------------
//	���ܣ�
//		��Կ����
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		 HCRYPTPROV hProv			��Կ�������
//		 HCRYPTKEY hPubKey			��Կ���
//		 LPBYTE pbInData			��������
//		 DWORD dwInDataLen			�������ݵĳ���
//		 LPBYTE pbOutData			�������
//		 LPDWORD pdwOutDataLen		������ݵĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI
PublicKeyEncrypt(
	IN HCRYPTPROV hProv,
	IN HCRYPTKEY hPubKey,
	IN LPBYTE pbInData,
	IN DWORD dwInDataLen,
	OUT LPBYTE pbOutData,
	OUT LPDWORD pdwOutDataLen
	)
{
	//�������
	if(pbInData == NULL || pdwOutDataLen == NULL)
		return FALSE;

	//���볤��Ϊ0���账��
	if(dwInDataLen == 0){
		*pdwOutDataLen = 0;
		return TRUE;
	}

	//��ȡ��Կ��ģ��
	DWORD dwModulusLen;
	DWORD dwDataLen = sizeof(dwModulusLen);
	BOOL bRetVal = CPGetKeyParam(
		hProv, hPubKey, KP_BLOCKLEN, LPBYTE(&dwModulusLen), &dwDataLen,0
		);
	if(!bRetVal)
		return FALSE;

	//�������ĳ���
	DWORD dwBlockSize = dwModulusLen / 8;
	DWORD dwCipherTextLen = (dwInDataLen / dwBlockSize + 1)*dwBlockSize;

	//�ж�����ռ��Ƿ��㹻
	if(pbOutData == NULL){
		*pdwOutDataLen = dwCipherTextLen;
		return TRUE;
	}
	else{
		if(*pdwOutDataLen < dwCipherTextLen){
			*pdwOutDataLen = dwCipherTextLen;
			return FALSE;
		}
	}

	//����
	memcpy(pbOutData, pbInData, dwInDataLen);
	DWORD dwBufLen = *pdwOutDataLen;
	*pdwOutDataLen = dwInDataLen;

	bRetVal = CPEncrypt(
		hProv, hPubKey, NULL, TRUE, 0, pbOutData, pdwOutDataLen, dwBufLen
		);
	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		˽Կ����
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		 HCRYPTPROV hProv			��Կ�������
//		 HCRYPTKEY hPrivateKey		˽Կ���
//		 LPBYTE pbInData			��������
//		 DWORD dwInDataLen			�������ݵĳ���
//		 LPBYTE pbOutData			�������
//		 LPDWORD pdwOutDataLen		������ݵĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI
PrivateKeyDecrypt(
	IN HCRYPTPROV hProv,
	IN HCRYPTKEY hPrivateKey,
	IN LPBYTE pbInData,
	IN DWORD dwInDataLen,
	OUT LPBYTE pbOutData,
	OUT LPDWORD pdwOutDataLen
	)
{
	//�������
	if(pbInData == NULL || pdwOutDataLen == NULL)
		return FALSE;

	//���볤��Ϊ0���账��
	if(dwInDataLen == 0){
		*pdwOutDataLen = 0;
		return TRUE;
	}

	//���ܽ����ķ�����ʱ�ռ���,���Ĵ�С���ᳬ������
	LPBYTE pbPlainText = new BYTE[dwInDataLen];
	if(pbPlainText == NULL)
		return FALSE;
	memcpy(pbPlainText, pbInData, dwInDataLen);
	DWORD dwPlainTextLen = dwInDataLen;
	BOOL bRetVal = CPDecrypt(
		hProv, hPrivateKey, NULL, TRUE, 0, pbPlainText, &dwPlainTextLen
		);
	if(!bRetVal){
		delete pbPlainText;
		return FALSE;
	}

	//�жϿռ��Ƿ��㹻
	bRetVal = TRUE;
	if(pbOutData == NULL){
		*pdwOutDataLen = dwPlainTextLen;
	}
	else{
		if(*pdwOutDataLen < dwPlainTextLen){
			*pdwOutDataLen = dwPlainTextLen;
			bRetVal =  FALSE;
		}
		else{
			memcpy(pbOutData, pbPlainText, dwPlainTextLen);
			*pdwOutDataLen = dwPlainTextLen;
		}
	}
	delete pbPlainText;

	return bRetVal;
}

/////////////////////////////////////////////////////////////////////
//
//	Base64

//-------------------------------------------------------------------
//	���ܣ�
//		Base64����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		LPBYTE pbInData			��������
//		DWORD dwInDataLen		�������ݵĳ���
//		LPBYTE pbOutData		�����Base64����
//		LPDWORD pdwOutDataLen	Base64�����ĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI
CPBase64Encode(
	IN LPBYTE pbInData, 
	IN DWORD dwInDataLen, 
	OUT LPBYTE pbOutData,
	IN OUT LPDWORD pdwOutDataLen
	)
{
	if(pdwOutDataLen == NULL)
		return FALSE;

	BOOL bRetVal = TRUE;
	try{
		ByteQueue* bq = new ByteQueue;
		Base64Encoder b64enc(bq);
		b64enc.Put(pbInData, dwInDataLen);
		b64enc.InputFinished();
		
		DWORD dwSize = bq->CurrentSize();
		if(pbOutData == NULL){
			*pdwOutDataLen = dwSize;
		}
		else{
			if(*pdwOutDataLen < dwSize){
				*pdwOutDataLen = dwSize;
				bRetVal = FALSE;
			}
			else
				*pdwOutDataLen = bq->Get(pbOutData, dwSize);
		}
	}
	catch(...){
		bRetVal = FALSE;
	}

	return bRetVal;
}

//-------------------------------------------------------------------
//	���ܣ�
//		Base64����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		LPBYTE pbInData			Base64����
//		DWORD dwInDataLen		Base64����ĳ���
//		LPBYTE pbOutData		���������
//		LPDWORD pdwOutDataLen	������ݵĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI
CPBase64Decode(
	IN LPBYTE pbInData, 
	IN DWORD dwInDataLen, 
	OUT LPBYTE pbOutData,
	IN OUT LPDWORD pdwOutDataLen
	)
{
	if(pdwOutDataLen == NULL)
		return FALSE;

	BOOL bRetVal = TRUE;
	try{
		ByteQueue* bq = new ByteQueue;
		Base64Decoder b64dec(bq);
		b64dec.Put(pbInData, dwInDataLen);
		b64dec.InputFinished();
		
		DWORD dwSize = bq->CurrentSize();
		if(pbOutData == NULL){
			*pdwOutDataLen = dwSize;
		}
		else{
			if(*pdwOutDataLen < dwSize){
				*pdwOutDataLen = dwSize;
				bRetVal = FALSE;
			}
			else
				*pdwOutDataLen = bq->Get(pbOutData, dwSize);
		}
	}
	catch(...){
		bRetVal = FALSE;
	}

	return bRetVal;
}

/////////////////////////////////////////////////////////////////////
//
//	HASH

//-------------------------------------------------------------------
//	���ܣ�
//		����HASH
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		IN ALG_ID algId			HASH�㷨��ʶ
//		IN LPBYTE pbInData		����
//		IN DWORD dwInDataLen	���ݵĳ��� 
//		OUT LPBYTE pbDigest		ժҪ
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI
CPSoftHash(
	IN ALG_ID algId,
	IN LPBYTE pbInData, 
	IN DWORD dwInDataLen, 
	OUT LPBYTE pbDigest
	)
{
	try{
		if(algId == CALG_MD5){
			MD5 hash;
			hash.CalculateDigest(pbDigest, pbInData, dwInDataLen);
		}
		else if(algId == CALG_SHA){
			SHA hash;
			hash.CalculateDigest(pbDigest, pbInData, dwInDataLen);
		}
		else if(algId == CALG_SSL3_SHAMD5){
			MD5 hash1;
			hash1.CalculateDigest(pbDigest, pbInData, dwInDataLen);
			SHA hash2;
			hash2.CalculateDigest(pbDigest + 16, pbInData, dwInDataLen);
		}
		else
			return FALSE;
	}
	catch(...){
		return FALSE;
	}

	return TRUE;
}

