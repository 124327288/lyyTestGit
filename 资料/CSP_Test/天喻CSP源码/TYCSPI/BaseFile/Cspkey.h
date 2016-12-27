#ifndef __CSP_KEY_H__
#define __CSP_KEY_H__

#include "HashObject.h"
#include "rsa.h"
#include "cbc.h"
#include "rc2.h"
#include "Ecc.h"
#define SHAdecoration		PKCS_DigestDecoration<SHA>::decoration
#define SHAdecorationlen	PKCS_DigestDecoration<SHA>::length
#define MD5decoration		PKCS_DigestDecoration<MD5>::decoration
#define MD5decorationlen	PKCS_DigestDecoration<MD5>::length
#define MD2decoration		PKCS_DigestDecoration<MD2>::decoration
#define MD2decorationlen	PKCS_DigestDecoration<MD2>::length

#define DEFAULT_BLOB_VERSION 0x02

///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////

class CCSPKey;

class CCSPSymmetricalKey;
class CCSPAsymmetricalKey;

class CCSPRsaPrk;
class CCSPRsaPuk;
class CCSPRc2Key;
class CCSPRc4Key;

typedef CArrayTemplate<BYTE, BYTE> byteArray;

#define DEFAULT_AUTH_ID		g_cPathTable.eitherNeed
/////////////////////////////////////////////////////////////////////
//	class CCSPKey
//
class CCSPKey {
	///////////////////////////////////////////////////
	// the attributes of the keys
protected:
	//包含该密钥的密钥容器
	CCSPKeyContainer* m_pKeyContainer;
	
	ULONG m_ulIndex;
	HCRYPTKEY m_hHandle;		//the handle of the keys

	BOOL m_bHandleValid;			//if the handle is valid

	BOOL m_RealObjReaded;
	
	BOOL m_bToken;				//whether the key is a token object,that is this key 
								//is a permanent key store on the card
	DWORD m_dwFlags;

	BYTE m_bAuthId;				//如果是token对象，保存token对象需要认证的外部认证密钥的id
	BYTE m_RealObjPath[2];		//如果是token对象,保存对象实际保存的路径

	//BOOL m_bExtractable;		//whether the key can be extracte;

	//BOOL m_bPrivate;			//whether the key need to access with a user account

	BOOL m_bLogged;				//whether the user has entered the user account

	ALG_ID m_ulAlgId;			//The algorithm identifier (ALG_ID) used by this key
								//object.

	DWORD m_dwBlockLen;			//If hKey is a session key, a DWORD value indicating 
								//the block length in bits. 
								//If hKey is a public/private key pair, a DWORD value
								//indicating the key pair's granularity. For RSA key 
								//pairs, this is the size of the modulus.
								//If the public-key algorithm does not support 
								//encryption, the NTE_BAD_TYPE error code is returned.

	ULONG m_ulKeyLen;			//The actual length of the key in bits
	
	

	byteArray m_arbSalt;		//A BYTE array containing the key's current salt value. 
								//This parameter does not apply to public/private key
								//pairs. If hKey references a public/private key pair,
								//the NTE_BAD_TYPE error code is returned.
								//this attribute is only used by session keys 
	ULONG m_ulSaltLen;
	
	DWORD m_dwPermissions;		//A DWORD value indicating the permission to be 
								//associated with the key. See Remarks for a table
								//of permission flags
								/*	Permission flag		Description							Value
									CRYPT_ENCRYPT		Allows encryption					0x0001 
									CRYPT_DECRYPT		Allows decryption					0x0002 
									CRYPT_EXPORT		Allows key to be exported			0x0004 
									CRYPT_READ			Allows parameters to be read		0x0008 
									CRYPT_WRITE			Allows parameters to be set			0x0010 
									CRYPT_MAC			Allows MACs to be used with key		0x0020 */

	//-------------------------------------------------------------------------
	//these attributes only used by block cipher keys
	byteArray m_arbIv;			//A BYTE array containing the key's current 
								//initialization vector (IV).

	ULONG m_ulIvLen;

	DWORD m_dwPadding;			//A DWORD value indicating the padding method used.
								//Currently, PKCS5_Padding is defined

	DWORD m_dwMode;				//A DWORD value indicating the cipher mode used
								/*	Cipher mode			Description				Value 
									CRYPT_MODE_ECB		Electronic codebook		2 
									CRYPT_MODE_CBC		Cipher block chaining	1 
									CRYPT_MODE_OFB		Output feedback mode	3 
									CRYPT_MODE_CFB		Cipher feedback mode	4 */

	DWORD m_dwModeBits;			//A DWORD value indicating the feedback width in bits.
								//This is used only with OFB and CFB cipher modes.
	//---------------------------------------------------------------------------

	DWORD m_dwEffectiveKeyLen;	//A DWORD value indicating 
								//the effective key length of an RC2 key

//	CString m_szUserName;
//	CString m_szUserAccount;
	/////////////////////////////////////////////////////////////////////////
	//functions
public:
	//构造函数
	CCSPKey(){};
	CCSPKey(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	= FALSE
		//BOOL bExtractable = TRUE,
		//BOOL bPrivate = FALSE
		);

	CCSPKey(
		CCSPKey & srcCSPKey
		);


	//析构函数
	virtual ~CCSPKey();

public:
	CCSPKeyContainer* GetKeyContainer() const
	{
		return m_pKeyContainer;
	}

	CTYCSP* GetCSPObject() const;
	
	HCRYPTKEY GetHandle()
	{
		return m_hHandle;
	}

	BOOL IsHandleValid()
	{
		return m_bHandleValid;
	}

	void ValidateHandle(BOOL flag = TRUE)
	{
		m_bHandleValid = flag;
	}

	ALG_ID GetAlgId()
	{
		return m_ulAlgId;
	}

	DWORD GetBlockLen()
	{
		return m_dwBlockLen;
	}

	BOOL IsPermanent()
	{
		return m_bToken;
	}

	BOOL IsExtractable()
	{
		return m_dwPermissions&CRYPT_EXPORT;
	}

	BOOL IsPrivate()
	{
		return m_dwFlags&CRYPT_USER_PROTECTED;
	}

	BOOL IsLogged()
	{
		if (IsPrivate())
			return m_bLogged;
		return TRUE;
	}

	//Create the object on the card
	virtual BOOL CreateOnToken(
		ULONG ulIndex
		);

	//Destroy the object on the card
	virtual BOOL DestroyOnToken();

	//------------------------------------------------------
	/*
	功能：产生密钥
	输入：	bitlen－key的长度
			dwFlags

	输入：
	说明：
	*/
	//------------------------------------------------------
	virtual BOOL Create(
		DWORD bitlen,
		DWORD dwFlags
		);
	virtual BOOL LoadFromToken(
		//BYTE* DEREncodedStr,
		//ULONG ulDEREncodedStrLen,
		ULONG ulIndex
		);

	
	virtual BOOL SetParam(
		DWORD dwParam,           // in
		BYTE *pbData,            // in
		DWORD dwFlags            // in
		);

	virtual BOOL GetParam(
		DWORD dwParam,          // in
		BYTE *pbData,           // out
		DWORD *pdwDataLen,      // in, out
		DWORD dwFlags			// in
		);

	/*virtual BOOL Duplicate(
		DWORD *pdwReserved,		// in
		DWORD dwFlags,			// in
		CCSPKey * pKey			// out
		);*/


	/*virtual BOOL GetKeyBlob(
		DWORD dwBlobType,			// in
		BYTE *pbKeyBlob,			// out
		DWORD *dwKeyBlobLen			// in, out
		);*/

	

	virtual BOOL Export(
		CCSPKey *pPubKey,				// in
		DWORD dwBlobType,				// in
		DWORD dwFlags,					// in
		BYTE *pbKeyBlob,				// out
		DWORD *dwKeyBlobLen			// in, out
		);

	virtual BOOL Import(
		CONST BYTE *pbData,     // in
		DWORD  dwDataLen,       // in
		CCSPKey *pPubKey,      // in
		DWORD dwFlags          // in
		);

	virtual BOOL DeriveKey(
		DWORD dwBitLen,
		CCSPHashObject* pHash,		// in
		DWORD       dwFlags      // in
		);

	virtual BOOL Encrypt(
		CCSPHashObject* pHash,		// in
		BOOL Final,					// in
		DWORD dwFlags,				// in
		BYTE *pbData,				// in, out
		DWORD *pdwDataLen,			// in, out
		DWORD dwBufLen				// in
		);

	virtual BOOL Decrypt(
		CCSPHashObject* pHash,			// in
		BOOL Final,						// in
		DWORD dwFlags,					// in
		BYTE *pbData,					// in, out
		DWORD *pdwDataLen				// in, out
		);


	virtual BOOL SignHash(
		CCSPHashObject* pHash,           // in
		LPCWSTR sDescription,			// in
		DWORD dwFlags,					// in
		BYTE *pbSignature,				// out
		DWORD *pdwSigLen				// in, out
		);

	virtual BOOL VerifySignature(
		CCSPHashObject* pHash,			// in
		CONST BYTE *pbSignature,		// in
		DWORD dwSigLen,					// in
		LPCWSTR sDescription,			// in
		DWORD dwFlags					// in
		);

	virtual BOOL SignRecover(
		LPBYTE pbData,
		DWORD dwDataLen,
		DWORD dwFlags,
		LPBYTE pbSignature,     
		LPDWORD pdwSigLen       
		);

	virtual BOOL VerifyRecover(
		CONST LPBYTE pbSignature,  
		DWORD dwSigLen,     
		DWORD dwFlags,
		LPBYTE pbData,
		LPDWORD pdwDataLen
		);

	virtual BOOL GetKeyMaterial(
		BYTE * pOutData,
		DWORD * dwOutDataLen
		);

	void SetIndex(
		ULONG ulIndex);

	ULONG GetIndex();

	virtual BOOL RSARawEncrypt(
		LPBYTE pbInData,
		DWORD dwInDataLen,
		LPBYTE pbOutData,
		LPDWORD pdwOutDataLen
		);

	virtual BOOL RSARawDecrypt(
		LPBYTE pbInData,
		DWORD dwInDataLen,
		LPBYTE pbOutData,
		LPDWORD pdwOutDataLen
		);
	
protected:
	void CopyByteToArray(
		byteArray & array,
		BYTE * pData,
		DWORD dwDataLen
		);

	BOOL FillDataBuffer(
		BYTE *pbData,           // out
		DWORD *pdwDataLen,      // in, out
		BYTE *pbsrcData,
		DWORD dwNeedLen			// in
		);

	BOOL WriteFileEx(
		FILEHANDLE hFile, 
		SHARE_XDF * pXdfRec, 
		ULONG ulUpdateOffset, 
		ULONG ulUpdateLen, 
		BYTE* pNewData, 
		ULONG ulNewDataLen, 
		ULONG ulFileLen
		);

	//swap an integer from big-eddian to little-eddian,
	//or form little-eddian to big-eddian
	void SwapInt(
		BYTE * pInt,
		DWORD dwLen
		);
	virtual void CreatebyBlob(
		BYTE * pBlob,
		DWORD dwBlobLen
		);

	virtual BOOL ReadRealObject(
		);
};

/////////////////////////////////////////////////////////////////////
//	class CCSPSymmetricalKey
//
class CCSPSymmetricalKey : public CCSPKey{
protected:
	byteArray m_arbKeyContent;		//the content of the key
	BOOL m_bFinished;
	CBCPaddedEncryptor * m_pCBCPaddedEncryptor;
	CBCPaddedDecryptor * m_pCBCPaddedDecryptor;
	/////////////////////////////////////////////////////////////////////////
	//functions
	void CreatebyBlob(
		BYTE * pBlob,
		DWORD dwBlobLen
		);
public:
	//构造函数
	CCSPSymmetricalKey(){};
	CCSPSymmetricalKey(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	= FALSE
		//BOOL bExtractable = TRUE,
		//BOOL bPrivate = FALSE
		);

	CCSPSymmetricalKey(
		CCSPSymmetricalKey & src
		);
	//------------------------------------------------------
	/*
	功能：产生密钥
	输入：	bitlen－key的长度
			dwFlags

	输入：
	说明：
	*/
	//------------------------------------------------------
	virtual BOOL Create(
		DWORD bitlen,
		DWORD dwFlags
		);
	//析构函数
	virtual ~CCSPSymmetricalKey();


		//Create the object on the card
	virtual BOOL CreateOnToken(
		ULONG ulIndex
		);

	//Destroy the object on the card
	virtual BOOL DestroyOnToken();

	virtual BOOL LoadFromToken(
		//BYTE* DEREncodedStr,
		//ULONG ulDEREncodedStrLen,
		ULONG ulIndex
		);

	
	virtual BOOL SetParam(
		DWORD dwParam,           // in
		BYTE *pbData,            // in
		DWORD dwFlags            // in
		);

	virtual BOOL GetParam(
		DWORD dwParam,          // in
		BYTE *pbData,           // out
		DWORD *pdwDataLen,      // in, out
		DWORD dwFlags			// in
		);

	/*virtual BOOL Duplicate(
		DWORD *pdwReserved,		// in
		DWORD dwFlags,			// in
		CCSPKey * pKey			// out
		);*/


	/*virtual BOOL GetKeyBlob(
		DWORD dwBlobType,			// in
		BYTE *pbKeyBlob,			// out
		DWORD *dwKeyBlobLen			// in, out
		);*/

	virtual BOOL Export(
		CCSPKey *pPubKey,				// in
		DWORD dwBlobType,				// in
		DWORD dwFlags,					// in
		BYTE *pbKeyBlob,				// out
		DWORD *dwKeyBlobLen			// in, out
		);


	virtual BOOL Encrypt(
		CCSPHashObject* pHash,		// in
		BOOL Final,					// in
		DWORD dwFlags,				// in
		BYTE *pbData,				// in, out
		DWORD *pdwDataLen,			// in, out
		DWORD dwBufLen				// in
		);

	virtual BOOL Decrypt(
		CCSPHashObject* pHash,			// in
		BOOL Final,						// in
		DWORD dwFlags,					// in
		BYTE *pbData,					// in, out
		DWORD *pdwDataLen				// in, out
		);


	virtual BOOL SignHash(
		CCSPHashObject* pHash,           // in
		LPCWSTR sDescription,			// in
		DWORD dwFlags,					// in
		BYTE *pbSignature,				// out
		DWORD *pdwSigLen				// in, out
		);

	virtual BOOL VerifySignature(
		CCSPHashObject* pHash,			// in
		CONST BYTE *pbSignature,		// in
		DWORD dwSigLen,					// in
		LPCWSTR sDescription,			// in
		DWORD dwFlags					// in
		);

	virtual BOOL GetKeyMaterial(
		BYTE * pOutData,
		DWORD * dwOutDataLen
		);
};

/////////////////////////////////////////////////////////////////////
//	class CCSPAsymmetricalKey
//
class CCSPAsymmetricalKey : public CCSPKey{
protected:
	
	/////////////////////////////////////////////////////////////////////////
	//functions
	
public:
	//构造函数
	CCSPAsymmetricalKey(){};
	CCSPAsymmetricalKey(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	= FALSE
		//BOOL bExtractable = TRUE,
		//BOOL bPrivate = FALSE
		);
	CCSPAsymmetricalKey(
		CCSPAsymmetricalKey & src
		);


	//析构函数
	virtual ~CCSPAsymmetricalKey();

	//------------------------------------------------------
	/*
	功能：产生密钥
	输入：	bitlen－key的长度
			dwFlags

	输入：
	说明：
	*/
	//------------------------------------------------------
	virtual BOOL Create(
		DWORD bitlen,
		DWORD dwFlags
		);

	virtual BOOL Encrypt(
		CCSPHashObject* pHash,		// in
		BOOL Final,					// in
		DWORD dwFlags,				// in
		BYTE *pbData,				// in, out
		DWORD *pdwDataLen,			// in, out
		DWORD dwBufLen				// in
		);

	virtual BOOL Decrypt(
		CCSPHashObject* pHash,			// in
		BOOL Final,						// in
		DWORD dwFlags,					// in
		BYTE *pbData,					// in, out
		DWORD *pdwDataLen				// in, out
		);


	virtual BOOL SignHash(
		CCSPHashObject* pHash,           // in
		LPCWSTR sDescription,			// in
		DWORD dwFlags,					// in
		BYTE *pbSignature,				// out
		DWORD *pdwSigLen				// in, out
		);

	virtual BOOL VerifySignature(
		CCSPHashObject* pHash,			// in
		CONST BYTE *pbSignature,		// in
		DWORD dwSigLen,					// in
		LPCWSTR sDescription,			// in
		DWORD dwFlags					// in
		);

};


/////////////////////////////////////////////////////////////////////
//	class CCSPRsaPuk
//
class CCSPRsaPuk : public CCSPAsymmetricalKey{
protected:
	/*byteArray m_arbModolus;
	DWORD m_dwPubexp;*/
	RSAFunction * m_pRsa;
	DWORD m_dwBitLen;
	BYTE m_pubID[2];
	/////////////////////////////////////////////////////////////////////////
	//functions
public:
	//构造函数
	CCSPRsaPuk(){};
	CCSPRsaPuk(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	= FALSE
		//BOOL bExtractable = TRUE,
		//BOOL bPrivate = FALSE
		);
	
	CCSPRsaPuk (
		CCSPRsaPuk & src
		);
	//------------------------------------------------------
	/*
	功能：传人密钥的值
	输入：	bitlen－模长
			pubexp－e
			modulus－n
	输入：
	说明：该函数自动按照模长取modulus的长度
	*/
	//------------------------------------------------------
	BOOL Create(
		DWORD bitlen,
		DWORD pubexp,
		CONST BYTE* modulus
		);
	//析构函数
	virtual ~CCSPRsaPuk();

	virtual BOOL Encrypt(
		CCSPHashObject* pHash,		// in
		BOOL Final,					// in
		DWORD dwFlags,				// in
		BYTE *pbData,				// in, out
		DWORD *pdwDataLen,			// in, out
		DWORD dwBufLen				// in
		);

	virtual BOOL VerifySignature(
		CCSPHashObject* pHash,			// in
		CONST BYTE *pbSignature,		// in
		DWORD dwSigLen,					// in
		LPCWSTR sDescription,			// in
		DWORD dwFlags					// in
		);

	virtual BOOL VerifyRecover(
		CONST LPBYTE pbSignature,  
		DWORD dwSigLen,     
		DWORD dwFlags,
		LPBYTE pbData,
		LPDWORD pdwDataLen
		);
	
	virtual BOOL Import(
		CONST BYTE *pbData,     // in
		DWORD  dwDataLen,       // in
		CCSPKey *pPubKey,      // in
		DWORD dwFlags          // in
		);
	virtual BOOL Export(
		CCSPKey *pPubKey,				// in
		DWORD dwBlobType,				// in
		DWORD dwFlags,					// in
		BYTE *pbKeyBlob,				// out
		DWORD *dwKeyBlobLen			// in, out
		);

	virtual BOOL RSARawEncrypt(
		LPBYTE pbInData,
		DWORD dwInDataLen,
		LPBYTE pbOutData,
		LPDWORD pdwOutDataLen
		);

protected:

	BOOL SWRawRSAEncryption(
		BYTE * pData
		);
	BOOL HWRawRSAEncryption(
		BYTE * pData
		);

	BOOL IsNeedHWCalc();
};

/////////////////////////////////////////////////////////////////////
//	class CCSPRsaPrk
//
class CCSPRsaPrk : public CCSPRsaPuk{
protected:
	//byteArray m_arbModolus;
	/*byteArray m_arbPrime1;
	byteArray m_arbPrime2;
	byteArray m_arbExponent1;
	byteArray m_arbExponent2;
	byteArray m_arbCoefficient;
	byteArray m_arbPrivateExponent;*/
	byteArray m_arbCert;
	BYTE m_CertPath[2];
	FILEHANDLE hPubFile;
	InvertableRSAFunction* m_pInvertableRsa;
	ULONG m_ulExFilePath;
	//DWORD m_dwPubexp;
	//DWORD m_dwBitLen;
	/////////////////////////////////////////////////////////////////////////
	//functions
public:
	//构造函数
	CCSPRsaPrk(){};
	CCSPRsaPrk(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	= FALSE
		//BOOL bExtractable = TRUE,
		//BOOL bPrivate = FALSE
		);
	CCSPRsaPrk(
		CCSPRsaPrk & src
		);

	//Create the object on the card
	virtual BOOL CreateOnToken(
		ULONG ulIndex
		);

	//Destroy the object on the card
	virtual BOOL DestroyOnToken();

	virtual BOOL LoadFromToken(
		//BYTE* DEREncodedStr,
		//ULONG ulDEREncodedStrLen,
		ULONG ulIndex
		);
	
	//------------------------------------------------------
	/*
	功能：传人密钥的值
	输入：	bitlen－模长
			pubexp－e
			modulus－n
			prime1 - p
			prime2 - q
			exponent1 - dp
			exponent2 - dq
			coefficient - qinv
			privateExponent - d 
	输入：
	说明：该函数自动按照模长取modulus等的长度
	*/
	//------------------------------------------------------
	BOOL Create(
		DWORD bitlen,
		DWORD pubexp = 65537,
		CONST BYTE* modulus = NULL,
		CONST BYTE* prime1 = NULL,
		CONST BYTE* prime2 = NULL,
		CONST BYTE* exponent1 = NULL,
		CONST BYTE* exponent2 = NULL,
		CONST BYTE* coefficient = NULL,
		CONST BYTE* privateExponent = NULL
		);
	//------------------------------------------------------

	//------------------------------------------------------
	/*
	功能：产生密钥
	输入：	bitlen－key的长度
			dwFlags

	输入：
	说明：
	*/
	//------------------------------------------------------
	virtual BOOL Create(
		DWORD bitlen,
		DWORD dwFlags
		);

	BOOL SWGenKey(
		DWORD bitlen,
		DWORD pubexp = 65537
		);

	BOOL HWGenKey(
		DWORD bitlen,
		DWORD pubexp = 65537
		);

	//析构函数
	virtual ~CCSPRsaPrk();

	virtual BOOL SignHash(
		CCSPHashObject* pHash,           // in
		LPCWSTR sDescription,			// in
		DWORD dwFlags,					// in
		BYTE *pbSignature,				// out
		DWORD *pdwSigLen				// in, out
		);

	virtual BOOL SignRecover(
		LPBYTE pbData,
		DWORD dwDataLen,
		DWORD dwFlags,
		LPBYTE pbSignature,     
		LPDWORD pdwSigLen       
		);

	virtual BOOL Decrypt(
		CCSPHashObject* pHash,			// in
		BOOL Final,						// in
		DWORD dwFlags,					// in
		BYTE *pbData,					// in, out
		DWORD *pdwDataLen				// in, out
		);

	virtual BOOL Import(
		CONST BYTE *pbData,     // in
		DWORD  dwDataLen,       // in
		CCSPKey *pPubKey,      // in
		DWORD dwFlags          // in
		);

	virtual BOOL Export(
		CCSPKey *pPubKey,				// in
		DWORD dwBlobType,				// in
		DWORD dwFlags,					// in
		BYTE *pbKeyBlob,				// out
		DWORD *dwKeyBlobLen			// in, out
		);
	virtual BOOL SetParam(
		DWORD dwParam,           // in
		BYTE *pbData,            // in
		DWORD dwFlags            // in
		);
	BOOL SetCertPath(
		BYTE* pPath);
	virtual BOOL GetParam(
		DWORD dwParam,          // in
		BYTE *pbData,           // out
		DWORD *pdwDataLen,      // in, out
		DWORD dwFlags			// in
		);
	
	virtual BOOL RSARawEncrypt(
		LPBYTE pbInData,
		DWORD dwInDataLen,
		LPBYTE pbOutData,
		LPDWORD pdwOutDataLen
		);

	virtual BOOL RSARawDecrypt(
		LPBYTE pbInData,
		DWORD dwInDataLen,
		LPBYTE pbOutData,
		LPDWORD pdwOutDataLen
		);

protected:
	BOOL SWRawRSADecryption(
		BYTE * pData
		);
	BOOL HWRawRSADecryption(
		BYTE * pData
		); 
	BOOL GetKeyOffsetInXdf(
		SHARE_XDF *pXdfRec,
		ULONG ulIndex,
		ULONG& ulOffset,
		ULONG& ulLen
		);

	virtual BOOL ReadRealObject(
		);
	BOOL ReadCert();
	BOOL IsNeedHWGenKey();
};
class CCSPEccPuk : public CCSPAsymmetricalKey{
protected:

	DWORD m_dwBitLen;
	BYTE m_pubID[2];
	ECCFunction * m_pEcc;
	/////////////////////////////////////////////////////////////////////////
	//functions
public:
	//构造函数
	CCSPEccPuk(){};
	CCSPEccPuk(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	= FALSE
		);
	
	CCSPEccPuk (
		CCSPEccPuk & src
		);

	//析构函数
	virtual ~CCSPEccPuk();

	virtual BOOL Encrypt(
		CCSPHashObject* pHash,		// in
		BOOL Final,					// in
		DWORD dwFlags,				// in
		BYTE *pbData,				// in, out
		DWORD *pdwDataLen,			// in, out
		DWORD dwBufLen				// in
		);

	virtual BOOL VerifySignature(
		CCSPHashObject* pHash,			// in
		CONST BYTE *pbSignature,		// in
		DWORD dwSigLen,					// in
		LPCWSTR sDescription,			// in
		DWORD dwFlags					// in
		);
	virtual BOOL Import(
		CONST BYTE *pbData,     // in
		DWORD  dwDataLen,       // in
		CCSPKey *pPubKey,      // in
		DWORD dwFlags          // in
		);
	virtual BOOL Export(
		CCSPKey *pPubKey,				// in
		DWORD dwBlobType,				// in
		DWORD dwFlags,					// in
		BYTE *pbKeyBlob,				// out
		DWORD *dwKeyBlobLen			// in, out
		);
protected:

	BOOL SWRawEccEncryption(
		BYTE * pData,
		BYTE *pDataOut,
		DWORD *dwOutDataLen
		);
	BOOL HWRawEccEncryption(
		BYTE * pData,
		BYTE *pDataOut,
		DWORD *dwOutDataLen
		);

	BOOL SWRawEccVerify(
		BYTE * pData,
		BYTE *pDataOut,
		DWORD *dwOutDataLen
		);
	BOOL HWRawEccVerify(
		BYTE * pData,
		BYTE *pDataOut,
		DWORD *dwOutDataLen
		);

	BOOL IsNeedHWCalc();
};

/////////////////////////////////////////////////////////////////////
//	class CCSPEccPrk
//
class CCSPEccPrk : public CCSPEccPuk{
protected:
	byteArray m_arbCert;
	BYTE m_CertPath[2];

	ULONG m_ulExFilePath;
	InvertableECCFunction* m_pInvertableEcc;
	/////////////////////////////////////////////////////////////////////////
	//functions
public:
	//构造函数
	CCSPEccPrk(){};
	CCSPEccPrk(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	= FALSE
		);
	CCSPEccPrk(
		CCSPEccPrk & src
		);

	//Create the object on the card
	virtual BOOL CreateOnToken(
		ULONG ulIndex
		);

	//Destroy the object on the card
	virtual BOOL DestroyOnToken();

	virtual BOOL LoadFromToken(
		//BYTE* DEREncodedStr,
		//ULONG ulDEREncodedStrLen,
		ULONG ulIndex
		);
	
	//------------------------------------------------------
	/*
	功能：产生密钥
	输入：	bitlen－key的长度
			dwFlags

	输入：
	说明：
	*/
	//------------------------------------------------------
	virtual BOOL Create(
		DWORD bitlen,
		DWORD dwFlags
		);

	BOOL SWGenKey(
		DWORD bitlen
		);

	BOOL HWGenKey(
		DWORD bitlen
		);

	//析构函数
	virtual ~CCSPEccPrk();

	virtual BOOL SignHash(
		CCSPHashObject* pHash,           // in
		LPCWSTR sDescription,			// in
		DWORD dwFlags,					// in
		BYTE *pbSignature,				// out
		DWORD *pdwSigLen				// in, out
		);

	virtual BOOL Decrypt(
		CCSPHashObject* pHash,			// in
		BOOL Final,						// in
		DWORD dwFlags,					// in
		BYTE *pbData,					// in, out
		DWORD *pdwDataLen				// in, out
		);

	virtual BOOL Import(
		CONST BYTE *pbData,     // in
		DWORD  dwDataLen,       // in
		CCSPKey *pPubKey,      // in
		DWORD dwFlags          // in
		);

	virtual BOOL Export(
		CCSPKey *pPubKey,				// in
		DWORD dwBlobType,				// in
		DWORD dwFlags,					// in
		BYTE *pbKeyBlob,				// out
		DWORD *dwKeyBlobLen			// in, out
		);
	virtual BOOL SetParam(
		DWORD dwParam,           // in
		BYTE *pbData,            // in
		DWORD dwFlags            // in
		);
	virtual BOOL GetParam(
		DWORD dwParam,          // in
		BYTE *pbData,           // out
		DWORD *pdwDataLen,      // in, out
		DWORD dwFlags			// in
		);
protected:
	BOOL SWRawEccDecryption(
		BYTE * pData,
		BYTE *pDataOut,
		DWORD *dwOutDataLen
		);
	BOOL HWRawEccDecryption(
		BYTE * pData,
		BYTE *pDataOut,
		DWORD *pdwOutDataLen
		); 

	BOOL SWRawEccSign(
		BYTE * pData,
		BYTE *pDataOut,
		DWORD *dwOutDataLen
		);
	BOOL HWRawEccSign(
		BYTE * pData,
		BYTE *pDataOut,
		DWORD *pdwOutDataLen
		);

	BOOL GetKeyOffsetInXdf(
		SHARE_XDF *pXdfRec,
		ULONG ulIndex,
		ULONG& ulOffset,
		ULONG& ulLen
		);

	virtual BOOL ReadRealObject(
		);
	BOOL ReadCert();
	BOOL IsNeedHWGenKey();
};

/////////////////////////////////////////////////////////////////////
//	class CCSPRc2Key
//
class CCSPRc2Key : public CCSPSymmetricalKey{
protected:
	RC2Encryption* m_pRC2Encryption;
	RC2Decryption* m_pRC2Decryption;
	

	/////////////////////////////////////////////////////////////////////////
	//functions
public:
	//构造函数
	CCSPRc2Key(){};
	CCSPRc2Key(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	= FALSE
		//BOOL bExtractable = TRUE,
		//BOOL bPrivate = FALSE
		);

	CCSPRc2Key(
		CCSPRc2Key &src
		);


	//析构函数
	virtual ~CCSPRc2Key();

		//Create the object on the card
	virtual BOOL CreateOnToken(
		ULONG ulIndex
		);
	virtual BOOL Import(
		CONST BYTE *pbData,     // in
		DWORD  dwDataLen,       // in
		CCSPKey *pPubKey,      // in
		DWORD dwFlags          // in
		);

	virtual BOOL DeriveKey(
		DWORD dwBitLen,
		CCSPHashObject* pHash,		// in
		DWORD       dwFlags      // in
		);
	//Destroy the object on the card
	virtual BOOL DestroyOnToken();

	virtual BOOL LoadFromToken(
		//BYTE* DEREncodedStr,
		//ULONG ulDEREncodedStrLen,
		ULONG ulIndex
		);

	//------------------------------------------------------
	/*
	功能：产生密钥
	输入：	bitlen－key的长度
			dwFlags

	输入：
	说明：
	*/
	//------------------------------------------------------
	virtual BOOL Create(
		DWORD bitlen,
		DWORD dwFlags
		);

	
	virtual BOOL SetParam(
		DWORD dwParam,           // in
		BYTE *pbData,            // in
		DWORD dwFlags            // in
		);

	virtual BOOL GetParam(
		DWORD dwParam,          // in
		BYTE *pbData,           // out
		DWORD *pdwDataLen,      // in, out
		DWORD dwFlags			// in
		);

	/*virtual BOOL Duplicate(
		DWORD *pdwReserved,		// in
		DWORD dwFlags,			// in
		CCSPKey * pKey			// out
		);*/


	/*virtual BOOL GetKeyBlob(
		DWORD dwBlobType,			// in
		BYTE *pbKeyBlob,			// out
		DWORD *dwKeyBlobLen			// in, out
		);*/

	virtual BOOL Export(
		CCSPKey *pPubKey,				// in
		DWORD dwBlobType,				// in
		DWORD dwFlags,					// in
		BYTE *pbKeyBlob,				// out
		DWORD *dwKeyBlobLen			// in, out
		);


	virtual BOOL Encrypt(
		CCSPHashObject* pHash,		// in
		BOOL Final,					// in
		DWORD dwFlags,				// in
		BYTE *pbData,				// in, out
		DWORD *pdwDataLen,			// in, out
		DWORD dwBufLen				// in
		);

	virtual BOOL Decrypt(
		CCSPHashObject* pHash,			// in
		BOOL Final,						// in
		DWORD dwFlags,					// in
		BYTE *pbData,					// in, out
		DWORD *pdwDataLen				// in, out
		);


	virtual BOOL SignHash(
		CCSPHashObject* pHash,           // in
		LPCWSTR sDescription,			// in
		DWORD dwFlags,					// in
		BYTE *pbSignature,				// out
		DWORD *pdwSigLen				// in, out
		);

	virtual BOOL VerifySignature(
		CCSPHashObject* pHash,			// in
		CONST BYTE *pbSignature,		// in
		DWORD dwSigLen,					// in
		LPCWSTR sDescription,			// in
		DWORD dwFlags					// in
		);

	/*virtual BOOL GetKeyMaterial(
		BYTE * pOutData,
		DWORD * dwOutDataLen
		);*/
protected:
	/*virtual void CreatebyBlob(
		BYTE * pBlob,
		DWORD dwBlobLen
		);*/
};

/////////////////////////////////////////////////////////////////////
//	class CCSPRc4Key
//
class CCSPRc4Key : public CCSPSymmetricalKey{
protected:
	UINT m_x;
	UINT m_y;
	UINT m_pData[256];
	/////////////////////////////////////////////////////////////////////////
	//functions
	void Crypt(
		ULONG len,
		CONST BYTE *indata,
		BYTE *outdata
		);
	void ResetKey();
public:
	//构造函数

	CCSPRc4Key(){};

	CCSPRc4Key(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	= FALSE
		//BOOL bExtractable = TRUE,
		//BOOL bPrivate = FALSE
		);

	//析构函数
	virtual ~CCSPRc4Key();

	CCSPRc4Key(
		CCSPRc4Key &src
		);
	BOOL Create(
		DWORD bitlen,
		DWORD dwFlags
		);

	BOOL SetParam(
		DWORD dwParam,           // in
		BYTE *pbData,            // in
		DWORD dwFlags            // in
		);

	BOOL DeriveKey(
		DWORD dwBitLen,
		CCSPHashObject* pHash,		// in
		DWORD       dwFlags      // in
		);

	BOOL Import(
		CONST BYTE *pbData,     // in
		DWORD  dwDataLen,       // in
		CCSPKey *pPubKey,      // in
		DWORD dwFlags          // in
		);

	BOOL Export(
		CCSPKey *pPubKey,				// in
		DWORD dwBlobType,				// in
		DWORD dwFlags,					// in
		BYTE *pbKeyBlob,				// out
		DWORD *dwKeyBlobLen			// in, out
		);

	BOOL Encrypt(
		CCSPHashObject* pHash,		// in
		BOOL Final,					// in
		DWORD dwFlags,				// in
		BYTE *pbData,				// in, out
		DWORD *pdwDataLen,			// in, out
		DWORD dwBufLen				// in
	);

	BOOL Decrypt(
		CCSPHashObject* pHash,			// in
		BOOL Final,						// in
		DWORD dwFlags,					// in
		BYTE *pbData,					// in, out
		DWORD *pdwDataLen				// in, out
		);
};

template <class E,class D>
class CCSPDesTmpl : public CCSPSymmetricalKey{
protected:
	E *m_pDESEncryption;
	D *m_pDESDecryption;
public:
	//构造函数

	CCSPDesTmpl(){};

	CCSPDesTmpl(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	= FALSE
		//BOOL bExtractable = TRUE,
		//BOOL bPrivate = FALSE
		);

	//析构函数
	virtual ~CCSPDesTmpl();

	CCSPDesTmpl(
		CCSPDesTmpl &src
		);

	BOOL Create(
		DWORD bitlen,
		DWORD dwFlags
		);

	BOOL SetParam(
		DWORD dwParam,           // in
		BYTE *pbData,            // in
		DWORD dwFlags            // in
		);

	BOOL DeriveKey(
		DWORD dwBitLen,
		CCSPHashObject* pHash,		// in
		DWORD       dwFlags      // in
		);

	BOOL Import(
		CONST BYTE *pbData,     // in
		DWORD  dwDataLen,       // in
		CCSPKey *pPubKey,      // in
		DWORD dwFlags          // in
		);

	BOOL Export(
		CCSPKey *pPubKey,				// in
		DWORD dwBlobType,				// in
		DWORD dwFlags,					// in
		BYTE *pbKeyBlob,				// out
		DWORD *dwKeyBlobLen			// in, out
		);

	BOOL Encrypt(
		CCSPHashObject* pHash,		// in
		BOOL Final,					// in
		DWORD dwFlags,				// in
		BYTE *pbData,				// in, out
		DWORD *pdwDataLen,			// in, out
		DWORD dwBufLen				// in
	);

	BOOL Decrypt(
		CCSPHashObject* pHash,			// in
		BOOL Final,						// in
		DWORD dwFlags,					// in
		BYTE *pbData,					// in, out
		DWORD *pdwDataLen				// in, out
		);
};

#include "CSPDes.cpp"
#include "des.h"
#include "sf33.h"
#include "scb2.h"
typedef CCSPDesTmpl <DESEncryption,DESDecryption>				CCSPDesKey;
typedef CCSPDesTmpl <DES_EDE_Encryption,DES_EDE_Decryption>		CCSP2DesKey;
typedef CCSPDesTmpl <TripleDES_Encryption,TripleDES_Decryption>	CCSP3DesKey;
typedef CCSPDesTmpl <SF33_Encryption,SF33_Decryption>			CCSPSSF33Base;
typedef CCSPDesTmpl <SCB2_Encryption,SCB2_Decryption>			CCSPSCB2Base;

class CCSPSSF33Key : public CCSPSSF33Base
{
public:
	CCSPSSF33Key();
	
	CCSPSSF33Key(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	= FALSE
		//BOOL bExtractable = TRUE,
		//BOOL bPrivate = FALSE
		);
	
	//析构函数
	virtual ~CCSPSSF33Key();
	BOOL Encrypt(
		CCSPHashObject* pHash,		// in
		BOOL Final,					// in
		DWORD dwFlags,				// in
		BYTE *pbData,				// in, out
		DWORD *pdwDataLen,			// in, out
		DWORD dwBufLen				// in
		);
	
	BOOL Decrypt(
		CCSPHashObject* pHash,			// in
		BOOL Final,						// in
		DWORD dwFlags,					// in
		BYTE *pbData,					// in, out
		DWORD *pdwDataLen				// in, out
		);
};

class CCSPSCB2Key : public CCSPSCB2Base
{
public:
	CCSPSCB2Key();
	
	CCSPSCB2Key(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken	= FALSE
		//BOOL bExtractable = TRUE,
		//BOOL bPrivate = FALSE
		);
	
	//析构函数
	virtual ~CCSPSCB2Key();
	BOOL Encrypt(
		CCSPHashObject* pHash,		// in
		BOOL Final,					// in
		DWORD dwFlags,				// in
		BYTE *pbData,				// in, out
		DWORD *pdwDataLen,			// in, out
		DWORD dwBufLen				// in
		);
	
	BOOL Decrypt(
		CCSPHashObject* pHash,			// in
		BOOL Final,						// in
		DWORD dwFlags,					// in
		BYTE *pbData,					// in, out
		DWORD *pdwDataLen				// in, out
		);
};
#endif