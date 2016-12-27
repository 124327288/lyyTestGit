//-------------------------------------------------------------------
//	本文件为 TY Cryptographic Service Provider 的组成部分
//
//
//	版权所有 天喻信息产业有限公司 (c) 1996 - 2001 保留一切权利
//-------------------------------------------------------------------
#ifndef __TYCSP_CRYPTSPI_H__
#define __TYCSP_CRYPTSPI_H__

#ifdef __cplusplus
extern "C" {
#endif
	
//-------------------------------------------------------------------
//
//	Service Provider Functions
//
//-------------------------------------------------------------------

BOOL WINAPI CPAcquireContext(
	HCRYPTPROV *phProv,
	CHAR *pszContainer,
	DWORD dwFlags,
	PVTableProvStruc pVTable
	);

BOOL WINAPI CPReleaseContext(
	HCRYPTPROV hProv,
	DWORD dwFlags
	);

BOOL WINAPI CPGetProvParam(
	HCRYPTPROV hProv,  
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD *pdwDataLen, 
	DWORD dwFlags      
	);

BOOL WINAPI CPSetProvParam(
	HCRYPTPROV hProv,  
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD dwFlags      
	);
 
//-------------------------------------------------------------------
//
//	Key Generation and Exchange Functions
//
//-------------------------------------------------------------------

BOOL WINAPI CPGenKey(
	HCRYPTPROV hProv, 
	ALG_ID Algid,     
	DWORD dwFlags,    
	HCRYPTKEY *phKey  
	);

BOOL WINAPI CPDuplicateKey(
	HCRYPTPROV hProv,    
	HCRYPTKEY hKey,      
	DWORD *pdwReserved,  
	DWORD dwFlags,       
	HCRYPTKEY* phKey     
	);

BOOL WINAPI CPDeriveKey(
	HCRYPTPROV hProv,      
	ALG_ID Algid,          
	HCRYPTHASH hBaseData,  
	DWORD dwFlags,         
	HCRYPTKEY *phKey       
	);

BOOL WINAPI CPDestroyKey(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey     
	);

BOOL WINAPI CPGetKeyParam(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey,    
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD *pdwDataLen, 
	DWORD dwFlags      
	);

BOOL WINAPI CPSetKeyParam(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey,    
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD dwFlags      
	);

BOOL WINAPI CPExportKey(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey,    
	HCRYPTKEY hExpKey, 
	DWORD dwBlobType,  
	DWORD dwFlags,     
	BYTE *pbData,      
	DWORD *pdwDataLen  
	);

BOOL WINAPI CPImportKey(
	HCRYPTPROV hProv,   
	CONST BYTE *pbData, 
	DWORD dwDataLen,    
	HCRYPTKEY hImpKey,  
	DWORD dwFlags,      
	HCRYPTKEY *phKey    
	);

BOOL WINAPI CPGetUserKey(
	HCRYPTPROV hProv,     
	DWORD dwKeySpec,      
	HCRYPTKEY *phUserKey  
	);

BOOL WINAPI CPGenRandom(
	HCRYPTPROV hProv,  
	DWORD dwLen,       
	BYTE *pbBuffer     
	);
 
//-------------------------------------------------------------------
//
//	Data Encryption Functions
//
//-------------------------------------------------------------------

BOOL WINAPI CPDecrypt(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey,    
	HCRYPTHASH hHash,  
	BOOL Final,        
	DWORD dwFlags,     
	BYTE *pbData,      
	DWORD *pdwDataLen  
	);
 
BOOL WINAPI CPEncrypt(
	HCRYPTPROV hProv,  
	HCRYPTKEY hKey,    
	HCRYPTHASH hHash,  
	BOOL Final,        
	DWORD dwFlags,     
	BYTE *pbData,      
	DWORD *pdwDataLen, 
	DWORD dwBufLen     
	);

//-------------------------------------------------------------------
//
//	Hashing and Digital Signature Functions
//
//-------------------------------------------------------------------

BOOL WINAPI CPCreateHash(
	HCRYPTPROV hProv,  
	ALG_ID Algid,      
	HCRYPTKEY hKey,    
	DWORD dwFlags,     
	HCRYPTHASH *phHash 
	);

BOOL WINAPI CPDuplicateHash(
	HCRYPTPROV hProv,    
	HCRYPTHASH hHash,    
	DWORD *pdwReserved,  
	DWORD dwFlags,       
	HCRYPTHASH* phHash    
	);

BOOL WINAPI CPDestroyHash(
	HCRYPTPROV hProv, 
	HCRYPTHASH hHash  
	);

BOOL WINAPI CPGetHashParam(
	HCRYPTPROV hProv,  
	HCRYPTHASH hHash,  
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD *pdwDataLen, 
	DWORD dwFlags      
	);

BOOL WINAPI CPSetHashParam(
	HCRYPTPROV hProv,  
	HCRYPTHASH hHash,  
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD dwFlags      
	);

BOOL WINAPI CPHashData(
	HCRYPTPROV hProv,    
	HCRYPTHASH hHash,    
	CONST BYTE *pbData,  
	DWORD dwDataLen,     
	DWORD dwFlags        
	);

BOOL WINAPI CPHashSessionKey(
	HCRYPTPROV hProv,  
	HCRYPTHASH hHash,  
	HCRYPTKEY hKey,    
	DWORD dwFlags      
	);

BOOL WINAPI CPSignHash(
	HCRYPTPROV hProv,      
	HCRYPTHASH hHash,      
	DWORD dwKeySpec,       
	LPCWSTR sDescription,  
	DWORD dwFlags,         
	BYTE *pbSignature,     
	DWORD *pdwSigLen       
	);

BOOL WINAPI CPVerifySignature(
	HCRYPTPROV hProv,      
	HCRYPTHASH hHash,      
	CONST BYTE *pbSignature,  
	DWORD dwSigLen,        
	HCRYPTKEY hPubKey,     
	LPCWSTR sDescription,  
	DWORD dwFlags          
	);

#ifdef __cplusplus
}       // Balance extern "C" above
#endif

#endif	// #ifndef __TYCSP_CRYPTSPI_H__