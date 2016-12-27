#include <stdio.h>
#include <malloc.h>
#include <windows.h>
#include <wincrypt.h>

#include "cspdk.h"
#include "../include/loaddll/load_tsp.h"

#define CSP_FLAG_NO_KEY 0x123
#define CSP_ALG_SMS4	0x124

#ifdef _DEBUG
	#define OUTSTRING1(x, y) printf(x,y)
	#define OUTSTRING2(x)	printf(x)
#else
	#define OUTSTRING1(x, y) 
	#define OUTSTRING2(x)	
#endif


TSM_RESULT initcm(TSM_HCONTEXT hContext);
TSM_RESULT initsp(TSM_HCONTEXT *hContext);
void UnloadBlob(DWORD *offset, DWORD size, BYTE *Blob, BYTE *Section);
void LoadBlob(DWORD *offset, DWORD size, BYTE *Blob, BYTE *Section);
extern TSM_HKEY hSMK;

typedef struct _PROV_CTX {
	DWORD dwProvType;				/**<  Provider Type. CSP-eleven is a FULL RSA Provider (0x01) */
	HANDLE containerHnd;            /**< Handle to the container which is using this context. */
    HANDLE heap;					/**< The handle to the allocated heap.*/
    unsigned long currentAlg;		/**< The latest enumerated alg
                                     (CPGetProvParam with PP_ENUMFLAGS) */
    char *cachedKeyExchangePin;		/**< Cached exchange keys user PIN.*/
    char *cachedSigPin;				/**< Cached signature keys user PIN.*/
    BOOL    nocache;				/**< If set, no data caching is performed.*/
    BOOL    silent;					/**< If set, no UI is to be used.*/
    HWND    uiHandle;				/**< Windows handle to interact with the user.*/
    HINSTANCE csp11hInstance;		/**< csp11 instance.*/
	// add the sector
	TSM_HCONTEXT hContext;
	LPSTR ContainerName;
	DWORD dwFlags; 
	HCRYPTKEY	hExchangeKey;	// 保存常驻密钥
	HCRYPTKEY	hSignKey;	
} PROV_CTX;

/** \brief Hash information
 *
 *  This structure is an attempts to gather all necessary information in order
 *  to handle a hash.
 */
typedef struct  _HASH_INFO {
    ALG_ID              Algid;   /**< Used Hash mechanism.*/
    BYTE                *data;  /**< Hashed (or to be) data.*/
    BYTE                *value;     /**< Pointer to hashed value.*/
    DWORD               lenth;      /**< Lenth in BYTE of the data.*/
    BOOL                finished;   /**< Boolean flag to know if the hash is
                                         finished or not.*/
	TSM_HHASH			hHash;	// hash handle for TSM
} HASH_INFO;

/** \brief Key information
 *
 *  This structure is an attempts to gather all necessary information in order
 *  to handle a key.
 *
 *  A '-1' or NULL value means 'unset'.
 */
typedef struct  _KEY_INFO {
    ALG_ID              algId;  /**< Used key algId.*/
    DWORD           dwKeySpec;  /**< The key usage specification (signature or
                                     key exchange.*/
    DWORD            blockLen;  /**< Granularity of a key pair. For RSA, that
                                     means modulus. In bits.*/
    DWORD              length;  /**< The total key length in bits, without any other
                                     data (like parity bits).*/
    DWORD             saltLen;  /**< Key salt value length in Bytes (salt_ex).*/
    BYTE                *salt;  /**< Key salt value.*/
    DWORD         permissions;  /**< CAPI key permissions.*/
    DWORD               ivLen;  /**< Length of initialisation vector. Depends on
                                     Alg and mode. In Bytes.*/
    BYTE                  *iv;  /**< Initialisation vector.*/
    DWORD             padding;  /**< Padding method. Only PKCS #5 method used
                                     (PKCS5_Padding).*/
    DWORD                mode;  /**< Used cipher mode, if applicable one of:
                                     - CRYPT_MODE_ECB,
                                     - CRYPT_MODE_CBC,
                                     - CRYPT_MODE_OFB,
                                     - CRYPT_MODE_CFB.*/
    DWORD                fLen;  /**< If mode is OFB or CFB, feedback length in
                                     bits.*/
    DWORD        effectiveLen; /**< if key use RC2 algorithm, effective
                                    key length in bits.*/
    HANDLE    hKeyInformation;  /**< dwContainerType specific information.*/
} KEY_INFO;

/** \brief Algorithm helper structure.
 *
 *  Special thanks to the OpenCSP, this is a copy/paste.
 */
// typedef struct _ALGORITHM {
//     ALG_ID  algId;  /**< The Algorithm ID.*/
//     DWORD   dwBits; /**< Algorithm key lenth.*/
//     unsigned char *cName; /**< Algorith Name.*/
// } ALGORITHM;

typedef struct _MIGKEYBLOB{
	DWORD	EncKeyLen;		// 被SMS4加密的原始密钥数据的数据长度；
	BYTE*	pbEncKey;		// 被SMS4加密的原始密钥数据；
	DWORD	SMS4DataLen;	// 被加密的SMS4数据的数据长度；
	BYTE*	pbSMS4Data;		// 被加密的SMS4数据；
	ALG_ID	Algid;			// 密钥类别；
}MIGKEYBLOB;

#define MD2_NAME "MD2"
#define MD2_BITS 128
#define MD5_NAME "MD5"
#define MD5_BITS 128
#define SHA_NAME "SHA-1"
#define SHA_BITS 160
#define SSL3_SHAMD5_NAME "SSL3 SHAMD5"
#define SSL3_SHAMD5_BITS 288
#define RSA_SIGN_NAME "RSA_SIGN"
#define RSA_SIGN_BITS 1024
#define RSA_KEYX_NAME "RSA_KEYX"
#define RSA_KEYX_BITS 1024
#define DES_NAME "DES"
#define DES_BITS 56
#define DES3_112_NAME "3DES TWO KEY"
#define DES3_112_BITS 112
#define DES3_NAME "3DES"
#define DES3_BITS 168
#define RC2_NAME "RC2"
#define RC2_BITS 128
#define RC4_NAME "RC4"
#define RC4_BITS 128


