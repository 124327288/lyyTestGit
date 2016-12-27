#ifndef __CSPBASEFILE_SUPPORT_H__
#define __CSPBASEFILE_SUPPORT_H__


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
	IN BOOL bCreateIfNoneExist = TRUE
	);

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
	);

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
//		��Կ�Ա����ǿɱ�������
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
	);

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
	);

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
	);

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
	);

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
	);

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
	);

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
	);

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
	);

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
	);

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
	);

/////////////////////////////////////////////////////////////////////
//
//	UI

#ifndef USE_TYCSPI_STATIC_LIB

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡѡ��Ķ�����������
//
//	���أ�
//		����������, -1Ϊʧ��
//
//  ������
//		OUT CHAR* szReaderName ����������
//
//  ˵����
//-------------------------------------------------------------------
int SelectSmartCardReader(CHAR* szReaderName);

#endif

#endif