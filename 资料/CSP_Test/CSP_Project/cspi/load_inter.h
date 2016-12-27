//#include "cspdk.h"


#pragma pack(push)                                      
#pragma pack(1)
typedef struct _csp_module
{
	void *hModule;
	BOOL (* load)(struct _csp_module *m, const char* name);
	BOOL (* free)(struct _csp_module *m);
	char name[256];

BOOL (* CPAcquireContext_Internal)(
  HCRYPTPROV		*phProv,
  LPCSTR			szContainer,
  DWORD				dwFlags,
  PVTableProvStruc	pVTable);
/**/
  BOOL  
(* CPReleaseContext_Internal)(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwFlags);
  
  BOOL  
(* CPGenKey_Internal)(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey);

  BOOL  
(* CPDeriveKey_Internal)(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey);

  BOOL  
(* CPDestroyKey_Internal)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey);

  BOOL  
(* CPSetKeyParam_Internal)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags);

  BOOL  
(* CPGetKeyParam_Internal)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags);

  BOOL  
(* CPSetProvParam_Internal)(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags);

  BOOL  
(* CPGetProvParam_Internal)(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags);

  BOOL  
(* CPSetHashParam_Internal)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags);

  BOOL  
(* CPGetHashParam_Internal)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags);

  BOOL  
(* CPExportKey_Internal)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwBlobType,
    IN  DWORD dwFlags,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen);

  BOOL  
(* CPImportKey_Internal)(
    IN  HCRYPTPROV hProv,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey);

  BOOL  
(* CPEncrypt_Internal)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD cbBufLen);

  BOOL  
(* CPDecrypt_Internal)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen);

  BOOL  
(* CPCreateHash_Internal)(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash);

  BOOL  
(* CPHashData_Internal)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  DWORD dwFlags);

  BOOL  
(* CPHashSessionKey_Internal)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags);

  BOOL  
(* CPSignHash_Internal)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwKeySpec,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags,
    OUT LPBYTE pbSignature,
    IN OUT LPDWORD pcbSigLen);

  BOOL  
(* CPDestroyHash_Internal)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash);

  BOOL  
(* CPVerifySignature_Internal)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbSignature,
    IN  DWORD cbSigLen,
    IN  HCRYPTKEY hPubKey,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags);

  BOOL  
(* CPGenRandom_Internal)(
    IN  HCRYPTPROV hProv,
    IN  DWORD cbLen,
    OUT LPBYTE pbBuffer);

  BOOL  
(* CPGetUserKey_Internal)(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwKeySpec,
    OUT HCRYPTKEY *phUserKey);
/**/
} CSP_MOD;

#pragma pack(pop)

extern CSP_MOD g_CspMod;