#ifndef __TSM_CRYPTO_HEADER_
#define __TSM_CRYPTO_HEADER_

#undef STDCALL
#ifdef WIN32
#define STDCALL __stdcall
#else
#define
#define STDCALL
#endif

#define CRYPTO_OK                               ((INT32)0)
#define CRYPTO_FAILED                           ((INT32)-1)
#define CRYPTO_INPROGRESS                       ((INT32)-2)
#define CRYPTO_INVALID_HANDLE                   ((INT32)-3)
#define CRYPTO_INVALID_CONTEXT                  ((INT32)-4)
#define CRYPTO_INVALID_SIZE                     ((INT32)-5)
#define CRYPTO_NOT_INITIALIZED                  ((INT32)-6)
#define CRYPTO_NO_MEM                           ((INT32)-7)
#define CRYPTO_INVALID_ALG                      ((INT32)-8)
#define CRYPTO_INVALID_KEY_SIZE                 ((INT32)-9)
#define CRYPTO_INVALID_ARGUMENT                 ((INT32)-10)
#define CRYPTO_MODULE_DISABLED                  ((INT32)-11)
#define CRYPTO_NOT_IMPLEMENTED                  ((INT32)-12)
#define CRYPTO_INVALID_BLOCK_ALIGNMENT          ((INT32)-13)
#define CRYPTO_INVALID_MODE                     ((INT32)-14)
#define CRYPTO_INVALID_KEY                      ((INT32)-15)
#define CRYPTO_AUTHENTICATION_FAILED            ((INT32)-16)
#define CRYPTO_INVALID_IV_SIZE                  ((INT32)-17)
#define CRYPTO_INVALID_PACKET                   ((INT32)-18)
#define CRYPTO_INVALID_SIGNATURE                ((INT32)-19)

#define KEY_SIZEVAL_256BIT                      (0x0100)
#define KEY_SIZEVAL_384BIT                      (0x0180)
#define ECC_CRYPTOMODE    KEY_SIZEVAL_256BIT
#define SCH_OW256	      0x08
#define SCH_OW192	      0x06
#define SCH_OW160	      0x05

#pragma pack(push)
#pragma pack(1)

typedef struct tdSCHContext
{
	unsigned long hash_len;
	unsigned long hashed_len;
	unsigned long last_bytes;
	unsigned long SCH_V[8];
	unsigned long W[68];
	unsigned long WP[64];
	unsigned char workspace[64];
} SCHContext;

#pragma pack(pop)

#ifdef  __cplusplus
extern "C" {
#endif
	
INT32 STDCALL ecc_crypto_init();
// 解密
int STDCALL ecc_decrypt(
    // 指定加密时的曲线
    unsigned long           keysize,            // in
    // 密文
    const unsigned char*    cipher_text,        // in
    // 密文长度
    unsigned long           cipher_len,         // in
    // 私钥
    const unsigned char*    prikey,             // in
    // 明文
    unsigned char*          plain_text,         // out
    // 明文长度
    unsigned long*          plain_len           // out
    );

// 加密
int STDCALL ecc_encrypt(
    // 选择密钥的曲线, 相当于指定密钥长度, 当前 keysize == KEY_SIZE_256BIT
    unsigned long          keysize,             // in
    // 明文
    const unsigned char*   plain_text,          // in
    // 明文长度
    unsigned long          plain_len,           // in
    // 公钥
    const unsigned char*   pubkey,              // in
    // 密文
    unsigned char*         cipher_text,         // out
    // 密文长度
    unsigned long*         cipher_len           // out
    );

// 签名
int STDCALL ecc_sign(
    // 选择产生密钥所用的曲线,
    unsigned long           keysize,            // in
    // hash数据
    const unsigned char*    hash,               // in
    // hash数据长度
    unsigned long           hash_len,           // in
    // 私钥
    const unsigned char*    prikey,             // in
    // 签名数据
    unsigned char*          sig                 // out
    );

// 验证
int STDCALL ecc_verify(
    // 选择签名所用密钥的曲线
    unsigned long           keysize,            // in
    // hash数据
    const unsigned char*    hash,               // in
    // hash数据长度
    unsigned long           hash_len,           // in
    // 公钥
    const unsigned char*    pubkey,             // in
    // 签名数据
    const unsigned char*    sig                 // in
    );

// 产生密钥对
int STDCALL ecc_make_key(
    // 选择密钥的曲线, 相当于指定密钥长度, 当前 keysize == KEY_SIZE_256BIT
    unsigned long           keysize,            // in
    // 私钥
    unsigned char*          prikey,             // out
    // 公钥
    unsigned char*          pubkey              // out
    );

#define SMS4_MOD_ECB    0  //这种模式下，按照PKCS#5的方式填充
#define SMS4_MOD_ECB1		1  //使用3des的填充方式，密文和明文的长度相同
#define SMS4_MOD_CBC    2  //按照PKCS#5的方式填充

	/*
	Use SMS4 to encrypt data.
	Parameter:
	key:		start address of the key(128bits).
	iv:			start address of the initial vector, 
	should be zeros if mod equals SMS4_MOD_ECB
	plain_data:	start address of the original data;
	plain_len:	the length of the original data, in bytes.
	enc_data:	start address of the encrypted data;
	*enc_len:	the length of the encrypted data, in bytes.
	mod:		encrypt mode, should be: SMS4_MOD_ECB, SMS4_MOD_CBC, SMS4_MOD_ECB1, others illegal
*/
int STDCALL SMS4_Encrypt(unsigned char *key, unsigned char *iv,
						 unsigned char *plain_data, int plain_len, 
						 unsigned char *enc_data, int *enc_len, 
						 int mod);

						 /*
						 Use SMS4 to decrypt data.
						 Parameter:
						 key:	start address of the key(128bits).
						 iv:	start address of the initial vector, 
						 should be zeros if mod equals SMS4_MOD_ECB
						 enc_data:	start address of the encrypted data;
						 enc_len:	the length of the encrypted data, in bytes.
						 plain_data: start address of the original data;
						 *plain_len: the length of the original data, in bytes.
						 mod:		 encrypt mode, should be: SMS4_MOD_ECB, SMS4_MOD_CBC, SMS4_MOD_ECB1, others illegal
*/									
int STDCALL SMS4_Decrypt(unsigned char *key, unsigned char *iv,
						 unsigned char *enc_data, int enc_len, 
						 unsigned char *plain_data, int *plain_len, 
				 int mod);

/************************************************************************
SCH Hash Init                                                           

  Parameter:
  1.out_width: the expected length of the result (in 4 bytes), 
  could be RES_256_BITS, RES_192_BITS, RES_160_BITS
  2.SCHContext: a pointer to a SCHContext struct
  
	Return value:
	0 for success, others failed
************************************************************************/
int STDCALL sch_init(int out_width, SCHContext *ctx);


/************************************************************************
SCH Hash Update                                                           

  Parameter:
  1.data: the pointer to the data to be hashed.
  2.lenth: the length of the data, should be a multiple of 64
  3.SCHContext: a pointer to a SCHContext struct
  
	Return value:
	0 for success, others failed
************************************************************************/
int STDCALL sch_update(unsigned char *data, int lenth, SCHContext *ctx);

/************************************************************************
SCH Hash Complete                                                           

  Parameter:
  1.data: the pointer to the data to be hashed.
  2.lenth: the length of the data, should be less than 64
  3.hash: the pointer to the hash value.
  3.SCHContext: a pointer to a SCHContext struct
  
	Return value:
	0 for success, others failed
************************************************************************/
int STDCALL sch_complete(unsigned char *digit, SCHContext *ctx);

/************************************************************************
SCH Hash                                                             

  Parameter:
  1.msg: The raw data ;
  2.len: length of the raw data (in bytes);
  3.hash: The space to store the hash value of msg
  4.hash_len: the expected length of the result (in 4 bytes), 
  could be RES_256_BITS, RES_192_BITS, RES_160_BITS
  Return value:
  0 for success, others failed
************************************************************************/
int STDCALL sch(unsigned char* msg, long len, unsigned char* digit, long hash_len);


/************************************************************************
HMAC use SCH

  Parameter:
  1.key: the pointer to the key;
  2.key_len: length of the key (in bytes);
  3.txt: the raw data;
  4.len: length of the raw data (in bytes);
  4.dig: mac value of the raw data;
  
	Return value:
	0 for success, others failed
************************************************************************/
int STDCALL hmac_sch(unsigned char *key, int key_len, unsigned char *txt, int len, unsigned long *dig);


int STDCALL kdf(const unsigned char *z, const long zlen,  unsigned char *k, long klen);
int STDCALL crypto_rand(unsigned char *random,int randlen);
#ifdef  __cplusplus
}
#endif

#endif