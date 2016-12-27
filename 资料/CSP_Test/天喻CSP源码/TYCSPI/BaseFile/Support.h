#ifndef __CSPBASEFILE_SUPPORT_H__
#define __CSPBASEFILE_SUPPORT_H__


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
	IN BOOL bCreateIfNoneExist = TRUE
	);

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
	);

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
//		密钥对必须是可被导出的
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
	);

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
	);

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
	);

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
	);

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
	);

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
	);

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
	);

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
	);

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
	);

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
	);

/////////////////////////////////////////////////////////////////////
//
//	UI

#ifndef USE_TYCSPI_STATIC_LIB

//-------------------------------------------------------------------
//	功能：
//		获取选择的读卡器或索引
//
//	返回：
//		读卡器索引, -1为失败
//
//  参数：
//		OUT CHAR* szReaderName 读卡器名称
//
//  说明：
//-------------------------------------------------------------------
int SelectSmartCardReader(CHAR* szReaderName);

#endif

#endif