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
//	功能：
//		打开指定名字的密钥容器,如果没有则创建
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		DWORD dwCardIndex			卡索引(从0开始)
//		char* szName				密钥容器名称
//		HCRYPTPROV* phProv 			打开或创建的密钥容器句柄
//		BOOL bCreateIfNoneExist		如果不存在是否创建
//
//  说明：
//-------------------------------------------------------------------
BOOL WINAPI
OpenKeyContainer(
	IN DWORD dwCardIndex,
	IN LPSTR szName, 
	OUT HCRYPTPROV* phProv, 
	IN BOOL bCreateIfNoneExist
	)
{
	//参数检测
	if(phProv == NULL)
		return FALSE;

	//先试着打开
	BOOL bRetVal = CPAcquireContext(phProv, szName, 0, dwCardIndex);
	//如果没有且需要的话,创建新的
	if(!bRetVal && bCreateIfNoneExist)
		bRetVal = CPAcquireContext(phProv, szName, CRYPT_NEWKEYSET, dwCardIndex);

	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		以DER编码的形式导出指定密钥对的公钥
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv			密钥容器的句柄
//		HCRYPTKEY hKeyPair			密钥对(私钥)的句柄
//		LPBYTE lpPubKey				导出公钥的DER编码
//		LPDWORD lpPubKeyLen			输入的长度/输出的长度
//
//  说明：
//		公钥的ASN.1表示
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

	//参数检测
	if(lpPubKeyLen == NULL)
		return FALSE;
	
	//导出公钥的BLOB
	BYTE pbBlob[MAX_RSAPUBKEY_BLOB_LEN];
	DWORD dwBlobLen = sizeof(pbBlob);
	BOOL bRetVal = CPExportKey(
		hProv, hKeyPair, NULL, PUBLICKEYBLOB, 0, pbBlob, &dwBlobLen
		);
	if(!bRetVal)
		return FALSE;

	//从BLOB中获取导出公钥的模数和指数
	BYTE pbExponent[4], pbModulus[256];
	DWORD dwExponentLen, dwModulusLen;

	//越过Blob Header
	RSAPUBKEY* pbPubKey = (RSAPUBKEY* )(pbBlob + sizeof(BLOBHEADER));

	//得到指数
	Integer e(pbPubKey->pubexp);
	dwExponentLen = e.ByteCount();
	e.Encode(pbExponent, dwExponentLen);

	//得到模数
	dwModulusLen = pbPubKey->bitlen/8;
	memcpy(pbModulus, (LPBYTE)pbPubKey + sizeof(RSAPUBKEY), dwModulusLen);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(pbModulus, dwModulusLen);

	//生成该公钥的DER编码(PKCS#1)

	//对模数进行DER编码
	ByteArray baModulus;
	MakeByteArray(pbModulus, dwModulusLen, baModulus);
	DEREncoding(0x02, baModulus.GetSize(), baModulus);

	//对指数进行DER编码
	ByteArray baExponent;
	MakeByteArray(pbExponent, dwExponentLen, baExponent);
	DEREncoding(0x02, baExponent.GetSize(), baExponent);

	//对公钥进行DER编码
	ByteArray baPublicKey;
	ConnectByteArray(baPublicKey, baModulus);
	ConnectByteArray(baPublicKey, baExponent);
	DEREncoding(0x30, baPublicKey.GetSize(), baPublicKey);

	//判断空间是否足够大
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
//	功能：
//		以DER编码的形式导出指定密钥对的私钥
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv			密钥容器的句柄
//		HCRYPTKEY hKeyPair			密钥对(私钥)的句柄
//		LPBYTE lpPriKey				导出私钥的DER编码
//		LPDWORD lpPriKeyLen			输入的长度/输出的长度
//
//  说明：
//		私钥的ASN.1表示
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

	//参数检测
	if(lpPriKeyLen == NULL)
		return FALSE;
	
	//导出私钥的BLOB
	BYTE pbBlob[MAX_RSAPRIKEY_BLOB_LEN];
	DWORD dwBlobLen = sizeof(pbBlob);
	BOOL bRetVal = CPExportKey(
		hProv, hKeyPair, NULL, PRIVATEKEYBLOB, 0, pbBlob, &dwBlobLen
		);
	if(!bRetVal)
		return FALSE;

	//越过Blob Header
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

	//生成该私钥的DER编码(PKCS#1)

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

	//对公钥进行DER编码
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

	//判断空间是否足够大
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
//	功能：
//		修正对RSA密钥DER解码过程中错误去掉的0
//
//	返回：
//		修正后的长度
//
//  参数：
//		LPBYTE pbData		刚解码的一个元素
//		DWORD dwDataLen		该元素的长度
//
//  说明：
//		pbData必须有足够的空间来容纳补充的0(一个字节)
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
//	功能：
//		解公钥的DER编码并创建公钥对象
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv					导入的密钥容器句柄
//		ALG_ID algId						公钥类型
//		LPBYTE pbPublicKeyDERCode			公钥的DER编码
//		DWORD dwPublicKeyDERCodeLen			公钥DER编码的长度
//		HCRYPTKEY* phPublicKey				创建的公钥句柄
//
//  说明：
//		公钥的ASN.1表示
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

	//检测参数
	if(pbPublicKeyDERCode == NULL || phPublicKey == NULL)
		return FALSE;

	//DER解码
	ByteArray baPublicKey;
	MakeByteArray(pbPublicKeyDERCode, dwPublicKeyDERCodeLen, baPublicKey);
	DWORD dwTag, dwLen;
	if(!DERDecoding(baPublicKey, dwTag, dwLen))
		return FALSE;
	if(dwTag != 0x30)
		return FALSE;

	//模数
	BYTE Modulus[MAX_RSAKEYPAIR_MODULUS_LEN / 8];
	DWORD dwModulusLen = sizeof(Modulus); 
	if(!DERDecoding(baPublicKey, dwTag, Modulus, dwModulusLen))
		return FALSE;
	if(dwTag != 0x02)
		return FALSE;
	dwModulusLen = FixRSADERDecodeZero(Modulus, dwModulusLen);
	if(g_ByteOrderMode != BOM_BIG_ENDIAN)
		ByteReverse(Modulus, dwModulusLen);

	//公开指数
	BYTE PublicExponent[4];
	DWORD dwPublicExponentLen = sizeof(PublicExponent);
	if(!DERDecoding(baPublicKey, dwTag, PublicExponent, dwPublicExponentLen))
		return FALSE;
	if(dwTag != 0x02)
		return FALSE;

	//创建公钥Blob
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

	//模数
	memcpy(pbKeyBlob + dwKeyBlobLen, Modulus, dwModulusLen);
	dwKeyBlobLen += dwModulusLen;

	//生成公钥对象
	return CPImportKey(
		hProv, pbKeyBlob, dwKeyBlobLen, NULL, 0, phPublicKey
		);
}

//-------------------------------------------------------------------
//	功能：
//		解私钥的DER编码并创建私钥对象
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv					导入的密钥容器句柄
//		ALG_ID algId						私钥类型
//		LPBYTE pbPrivateKeyDERCode			私钥的DER编码
//		DWORD dwPrivateKeyDERCodeLen		私钥DER编码的长度
//		BOOL bExportAble					是否可导出
//		HCRYPTKEY* phPrivateKey				创建的私钥句柄
//
//  说明：
//		私钥的ASN.1表示
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
	
	//检测参数
	if(pbPrivateKeyDERCode == NULL || phPrivateKey == NULL)
		return FALSE;

	/////////////////////////////////////////////////////////////////
	//解私钥DER编码 开始
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

	//解私钥DER编码	完毕
	/////////////////////////////////////////////////////////////////

	/////////////////////////////////////////////////////////////////
	//创建私钥Blob 开始
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

	//创建私钥Blob 结束
	/////////////////////////////////////////////////////////////////

	DWORD dwFlags = CRYPT_USER_PROTECTED;
	if(bExportAble) dwFlags |= CRYPT_EXPORTABLE;
	
	//导入到密钥容器中
	return CPImportKey(hProv, pbKeyBlob, dwBlobLen, NULL, dwFlags, phPrivateKey);
}

//-------------------------------------------------------------------
//	功能：
//		解私钥的DER编码并创建私钥对象
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv					导入的密钥容器句柄
//		ALG_ID algId						私钥类型
//		LPBYTE pbPrivateKeyDERCode			私钥的DER编码
//		DWORD dwPrivateKeyDERCodeLen		私钥DER编码的长度
//		HCRYPTKEY* phPrivateKey				创建的私钥句柄
//
//  说明：
//		私钥的ASN.1表示
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
//	功能：
//		解私钥的DER编码并创建私钥对象
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv					导入的密钥容器句柄
//		ALG_ID algId						私钥类型
//		LPBYTE pbPrivateKeyDERCode			私钥的DER编码
//		DWORD dwPrivateKeyDERCodeLen		私钥DER编码的长度
//		BOOL bExportAble					是否可导出
//		HCRYPTKEY* phPrivateKey				创建的私钥句柄
//
//  说明：
//		私钥的ASN.1表示
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
//	功能：
//		对称加解密的块长处理
//
//	返回：
//		TRUE：成功		FALSE：失败
//
//  参数：
//		HCRYPTPROV hProv			密钥容器句柄
//		ALG_ID algId				算法标识
//		LPBYTE pbKey				密钥值
//		BOOL bEncrypt				TRUE：加密	FALSE：解密
//		LPBYTE pbInData				明文
//		DWORD dwDataLen				数据的长度
//		LPBYTE pbOutData			密文
//
//  说明：
//		明文与密文的长度是相等的且明文的长度必须为块长的整数倍
//	这些调用者必须保证，在函数内部不作检测
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
	//参数检测
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
		//通过密钥容器句柄获取CSP对象
		HCRYPTCSP hCSP = GET_HCRYPTCSP(hProv);
		CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByHandle(hCSP);
		if(pCSPObject == NULL)
			return FALSE;

		//更新SSF33密钥
		BYTE cCommand[256];
		DWORD dwResLen;
		WORD wSW;
		memcpy(cCommand, "\x80\xd4\x01\x00\x18\x03\x01\x02\x0a\x0f\x00\x0f\xff", 13);
		memcpy(cCommand + 13, pbKey, 16);
		BOOL bRetVal = pCSPObject->SendCommand(cCommand, 13 + 16, NULL, NULL, &wSW);
		//老的文件系统中没有预先安装SSF33密钥
		if(bRetVal == FALSE){
			if(wSW != 0x9403) return FALSE;
			memcpy(cCommand, "\x80\xd4\x00\x00\x18\x03\x01\x02\x0a\x0f\x00\x0f\xff", 13);
			memcpy(cCommand + 13, pbKey, 16);
			if(!pCSPObject->SendCommand(cCommand, 13 + 16))
				return FALSE;
		}

		//SSF33加解密
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
//	功能：
//		使用对称密钥对数据进行加/解密
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		HCRYPTPROV hProv			密钥容器句柄
//		ALG_ID algId				算法标识
//		LPBYTE pbKey				要做加/解密的密钥值
//		DWORD dwKeyLen				做加/解密的密钥长度
//		BOOL bEncrypt				加密(TRUE)/解密(FALSE)
//		LPBYTE pbInData				原始数据
//		DWORD dwInDataLen			原始数据长度
//		LPBYTE pbOutData			加解密后的数据
//		LPDWORD pdwOutDataLen		加解密后的数据长度
//		BOOL bPadding				是否填充数据
//
//  说明：
//		目前仅用ECB的模式
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
	//参数检测
	if(pbKey == NULL || pbInData == NULL || pdwOutDataLen == NULL)
		return FALSE;

	//输入长度为0无需处理
	if(dwInDataLen == 0){
		*pdwOutDataLen = 0;
		return TRUE;
	}

	//确定每个算法块的长度
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

	//加密
	if(bEncrypt){
		//计算密文的大小
		DWORD dwCipherTextLen;
		if(bPadding)
			dwCipherTextLen = (dwInDataLen / dwBlockSize + 1)*dwBlockSize;
		else{
			//如果不需要填充则输入数据必需是块长的整数倍
			if(dwInDataLen % dwBlockSize)
				return FALSE;
			dwCipherTextLen = dwInDataLen;
		}

		//确定输出空间是否足够
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

		//加密输出
		if(!SymmCipherBlock(hProv, algId, pbKey, TRUE, pbOutData, dwCipherTextLen, pbOutData))
			return FALSE;
		
		*pdwOutDataLen = dwCipherTextLen;

		return TRUE;
	}
	//解密
	else{
		//密文必须为dwBlockSize的整数倍
		if(dwInDataLen % dwBlockSize)
			return FALSE;

		//解密生成的明文放在临时空间中
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

		//确定输出空间是否足够
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
//	功能：
//		公钥加密
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		 HCRYPTPROV hProv			密钥容器句柄
//		 HCRYPTKEY hPubKey			公钥句柄
//		 LPBYTE pbInData			输入数据
//		 DWORD dwInDataLen			输入数据的长度
//		 LPBYTE pbOutData			输出数据
//		 LPDWORD pdwOutDataLen		输出数据的长度
//
//  说明：
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
	//参数检测
	if(pbInData == NULL || pdwOutDataLen == NULL)
		return FALSE;

	//输入长度为0无需处理
	if(dwInDataLen == 0){
		*pdwOutDataLen = 0;
		return TRUE;
	}

	//获取公钥的模长
	DWORD dwModulusLen;
	DWORD dwDataLen = sizeof(dwModulusLen);
	BOOL bRetVal = CPGetKeyParam(
		hProv, hPubKey, KP_BLOCKLEN, LPBYTE(&dwModulusLen), &dwDataLen,0
		);
	if(!bRetVal)
		return FALSE;

	//计算密文长度
	DWORD dwBlockSize = dwModulusLen / 8;
	DWORD dwCipherTextLen = (dwInDataLen / dwBlockSize + 1)*dwBlockSize;

	//判断输出空间是否足够
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

	//加密
	memcpy(pbOutData, pbInData, dwInDataLen);
	DWORD dwBufLen = *pdwOutDataLen;
	*pdwOutDataLen = dwInDataLen;

	bRetVal = CPEncrypt(
		hProv, hPubKey, NULL, TRUE, 0, pbOutData, pdwOutDataLen, dwBufLen
		);
	return bRetVal;
}

//-------------------------------------------------------------------
//	功能：
//		私钥解密
//
//	返回：
//		TRUE:成功		FALSE:失败
//
//  参数：
//		 HCRYPTPROV hProv			密钥容器句柄
//		 HCRYPTKEY hPrivateKey		私钥句柄
//		 LPBYTE pbInData			输入数据
//		 DWORD dwInDataLen			输入数据的长度
//		 LPBYTE pbOutData			输出数据
//		 LPDWORD pdwOutDataLen		输出数据的长度
//
//  说明：
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
	//参数检测
	if(pbInData == NULL || pdwOutDataLen == NULL)
		return FALSE;

	//输入长度为0无需处理
	if(dwInDataLen == 0){
		*pdwOutDataLen = 0;
		return TRUE;
	}

	//解密将明文放在临时空间中,明文大小不会超过密文
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

	//判断空间是否足够
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
//	功能：
//		Base64编码
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		LPBYTE pbInData			输入数据
//		DWORD dwInDataLen		输入数据的长度
//		LPBYTE pbOutData		输出的Base64编码
//		LPDWORD pdwOutDataLen	Base64编码后的长度
//
//  说明：
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
//	功能：
//		Base64解码
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		LPBYTE pbInData			Base64编码
//		DWORD dwInDataLen		Base64编码的长度
//		LPBYTE pbOutData		输出的数据
//		LPDWORD pdwOutDataLen	输出数据的长度
//
//  说明：
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
//	功能：
//		计算HASH
//
//	返回：
//		TRUE:成功	FALSE:失败
//
//  参数：
//		IN ALG_ID algId			HASH算法标识
//		IN LPBYTE pbInData		数据
//		IN DWORD dwInDataLen	数据的长度 
//		OUT LPBYTE pbDigest		摘要
//
//  说明：
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

