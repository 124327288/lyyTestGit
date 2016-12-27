/////////////////////////////////////////////////////////////////////////////
//  FILE          : csp.c                                                  //
//  DESCRIPTION   : Crypto API interface                                   //
//  AUTHOR        :                                                        //
//  HISTORY       :                                                        //
//                                                                         //
//  Copyright (C) 1993 Microsoft Corporation   All Rights Reserved         //
/////////////////////////////////////////////////////////////////////////////
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#undef UNICODE                  // ## Not Yet

#include "info.h"

// global variable
static HANDLE	g_ContextHand = (HANDLE)NULL;	// context object head of link
static int		g_ContextLen = 0;				// counts of context objects

static HANDLE	g_KeyHand = (HANDLE)NULL;
static int		g_KeyLen = 0;

static HANDLE	g_HashHand = (HANDLE)NULL;
static int		g_HashLen = 0;

HINSTANCE g_instance;		// instance handle

extern TSM_HKEY	hSMK;
extern UINT32	g_uTcmSecretSize;	// tcm auth data size
extern UINT32	g_uSMKSecretSize;	// smk auth data size
extern BYTE		g_TcmAuth[32];		// TCM auth data
extern BYTE		g_SMKAuth[32];		// SMK auth data

//////////////////////////////////////////////////////////////////////////
// fuctions declare
//////////////////////////////////////////////////////////////////////////
DWORD CreateKeyObj(TSM_HCONTEXT hContext, TSM_HKEY* phKey, TSM_FLAG initFlags);
BOOL InitKey(PROV_CTX *pProvCtx, KEY_INFO *pKey, ALG_ID algId);
BOOL ClearHashMemory(HCRYPTPROV);
BOOL ClearKeyMemory(HCRYPTPROV);
DWORD UnLoadMigBlob(MIGKEYBLOB *migblob, BYTE* buff);
DWORD LoadMigBlob(MIGKEYBLOB *migblob, BYTE *buff);

int FindGrantedHandle(HANDLE *grantedHandles, int max_len, HANDLE wantedHandle);
BOOL GrantHandle(HANDLE **grantedHandles, int *length, HANDLE handle);
BOOL ValidateHandle(HANDLE *grantedHandles, int length, HANDLE handle);
BOOL RemoveHandle(HANDLE **grantedHandles, int *length, HANDLE handle);


BOOL WINAPI
DllMain(
		HINSTANCE hinstDLL,  // handle to the DLL module
		DWORD fdwReason,     // reason for calling function
		LPVOID lpvReserved)  // reserved
{
	if(0 != gTspModule.load(&gTspModule, "Jtsp.dll"))
	{
		if (gTspModule.load(&gTspModule, "Jtsp.dll") != 0)
		{
			return FALSE;
		}		
	}

	g_instance = hinstDLL;

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);
	}

    return TRUE;
}

/*
 -  CPAcquireContext
 -
 *  Purpose:
 *               The CPAcquireContext function is used to acquire a context
 *               handle to a cryptographic service provider (CSP).
 *
 *
 *  Parameters:
 *               OUT phProv         -  Handle to a CSP
 *               IN  szContainer    -  Pointer to a string which is the
 *                                     identity of the logged on user
 *               IN  dwFlags        -  Flags values
 *               IN  pVTable        -  Pointer to table of function pointers
 *
 *  Returns:
 */

BOOL 
CPAcquireContext_Internal(
     HCRYPTPROV *phProv,
      LPCSTR szContainer,
      DWORD dwFlags,
      PVTableProvStruc pVTable)
{
	HANDLE			heapHandle;			// Handle to the context heap object. 
	HCRYPTKEY		hKey;             // Handle to the created key set if
	UINT32			TestResultLength = 0;
	BYTE			*prgbTestResult  = NULL;
	UINT32			ulPublicKeyLength = 0;
	LPBYTE			rgbPublicKey = NULL;
	PROV_CTX		*pProvCtx = NULL;		// Provider context 
	DWORD			nameSize = 0;			// Size of the provided container name.
	LPSTR			cName = NULL;			// Local copy of szContainer C string pointer 
	int				verifyOnly  = FALSE;    // If TRUE, the function only verify Cryptographic Context acquirement 
	TSM_HCONTEXT	hContext = 0;

    OUTSTRING2("_-_-_-_-_-_-_-_-_Acquiring Context-_-_-_-_-_-_-_-_-\n");

	// - Nullify the returned hProv.
    *phProv = (HCRYPTPROV)NULL; 
    
    // - Test if dwFlags are correct 
    if (dwFlags & ~(CRYPT_SILENT|CRYPT_VERIFYCONTEXT|CRYPT_NEWKEYSET|CRYPT_MACHINE_KEYSET|CRYPT_DELETEKEYSET))
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
	
	heapHandle = HeapCreate(0, sizeof(PROV_CTX), 0);
    // - Test if CRYPT_VERIFYCONTEXT flag is set. 
    if (dwFlags & CRYPT_VERIFYCONTEXT)
    {
        cName = NULL;
        // - In VERIFYCONTEXT mode, container name must be set to NULL. 
        if (szContainer !=NULL)
        {
            SetLastError(NTE_BAD_KEYSET_PARAM);
            return FALSE;
        }
        verifyOnly = TRUE;
    }
    else
    {
        // - If szContainer contains string address 
        if (szContainer != NULL)
        {
            // - Test if the container name is valid 
            // \note Cannot use StringCbLength, not supported in Cygwin/minGW
            // if FAILED(StringCbLength(szContainer, MAX_PATH, nameSize))
            nameSize = strlen(szContainer);

            // - Test if the name is not too long.
            if(nameSize >= MAX_PATH)
            {
                SetLastError(NTE_BAD_KEYSET_PARAM);
                return FALSE;
            }

            // - Test if the name is not empty.
            if(!szContainer[0])
            {
                szContainer = NULL;
            }
        }

        // - Copy name into local variable.
		cName = HeapAlloc(heapHandle, HEAP_ZERO_MEMORY, nameSize);
        memcpy(cName, szContainer, nameSize);
    }

    // - Fill with zero to be clean.
    pProvCtx = HeapAlloc(heapHandle, HEAP_ZERO_MEMORY, sizeof(PROV_CTX));

    // - Test if allocation succeed.
    if (pProvCtx == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }

    // - Fill provider context handle pointer by the
    //  pointer to the acquired provider context.
    *phProv = (HCRYPTPROV) pProvCtx;

    // - Grant the context.
    OUTSTRING2("===provCtx:");
    GrantHandle((HANDLE **) &g_ContextHand,&g_ContextLen, (HANDLE) *phProv);

    // - Fill context heap handle and provider type 
    pProvCtx->heap = heapHandle;	
    pProvCtx->cachedKeyExchangePin = NULL;
    pProvCtx->cachedSigPin = NULL;
    pProvCtx->nocache = FALSE;
    pProvCtx->silent = FALSE;
    pProvCtx->currentAlg = 0;
    pProvCtx->uiHandle = NULL;
	pProvCtx->ContainerName = cName;

	// init tsp and tcm
	{
		TSM_RESULT m_result;
		m_result = initsp(&hContext);
		if (TSM_SUCCESS != m_result)
		{
			OUTSTRING1("initsp = %x\n",m_result);
			return FALSE;
		}

		m_result = initcm(hContext);
		if (TSM_SUCCESS != m_result)
		{
			OUTSTRING1("initcm = %x\n",m_result);
			return FALSE;
		}
	}

	pProvCtx->hContext = hContext;
	if (dwFlags & CRYPT_NEWKEYSET)
	{
		hKey = 0;
		if (!CPGenKey_Internal((HCRYPTPROV)pProvCtx, AT_KEYEXCHANGE, 0, &hKey))
		{
			OUTSTRING2("Genkey failed __ EXE \n");
			return FALSE;
		}
		pProvCtx->hExchangeKey = hKey;

		if (!CPGenKey_Internal((HCRYPTPROV)pProvCtx, AT_SIGNATURE, 0, &hKey))
		{
			OUTSTRING2("Genkey failed __ Sign \n");
		}
		pProvCtx->hSignKey = hKey;
	}

    //- Return TRUE.
    OUTSTRING2("+++++++++++++++++Context acquired+++++++++++++++++\n");
    return TRUE;

}


//
//    CPReleaseContext
//  
//    Purpose:
//             The CPReleaseContext function is used to release a
//             context created by CryptAcquireContext.
//  
//   Parameters:
//             IN  phProv        -  Handle to a CSP
//             IN  dwFlags       -  Flags values
//  
//  Returns:
//  

BOOL
CPReleaseContext_Internal(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwFlags)
{
	HANDLE  heapHandle;             // Handle to the context heap object 
	TSM_HCONTEXT hContext;
    PROV_CTX *pProvCtx = NULL;      // Provider context 
	TSM_RESULT result;

    // - Local good typed provider context pointer 
    pProvCtx = (PROV_CTX *) hProv;
    
    // - Test if flags are set 
    if(dwFlags)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    // - Test if the context has been granted 
    if(!ValidateHandle((HANDLE *) g_ContextHand, g_ContextLen, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
	OUTSTRING2("-_-_-_-_-_-_-_-_-Context released-_-_-_-_-_-_-_-_-\n");    
    
    // - Revoke the context handle 
    heapHandle = pProvCtx->heap;
	hContext = pProvCtx->hContext;
  
	// destroy hash and key object
	ClearHashMemory(hProv);
	ClearKeyMemory(hProv);

	OUTSTRING2("===provCtx:");
    if(!RemoveHandle((HANDLE **) &g_ContextHand, &g_ContextLen, (HANDLE) hProv))
    {
        return FALSE;
    }
    pProvCtx->heap = NULL;
    if(pProvCtx->cachedKeyExchangePin != NULL)
    {
        HeapFree(heapHandle, 0, pProvCtx->cachedKeyExchangePin);
    }
    if(pProvCtx->cachedSigPin != NULL)
    {
        HeapFree(heapHandle, 0, pProvCtx->cachedSigPin);
    }
	if (pProvCtx->ContainerName != NULL)
	{
		HeapFree(heapHandle, 0, pProvCtx->ContainerName);
	}

	result = gTspModule.Tspi_Context_Close(hContext);
	if (result != TSM_SUCCESS)
	{
		return FALSE;	
	}
	
	// - Free context  
    HeapFree(heapHandle, 0, pProvCtx);

    // - Destroy context heap handle 
    HeapDestroy(heapHandle);
	OUTSTRING2("+++++++++++++++++Context released+++++++++++++++++\n");
    return TRUE;
}


//
//CPGenKey
//
//Purpose:
//              Generate cryptographic keys
//
//
//Parameters:
//             IN      hProv   -  Handle to a CSP
//             IN      Algid   -  Algorithm identifier
//             IN      dwFlags -  Flags values
//             OUT     phKey   -  Handle to a generated key
//
//Returns:
//

BOOL
CPGenKey_Internal(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
	TSM_HCONTEXT hContext;
	TSM_RESULT m_result;
	TSM_FLAG objectType;
	TSM_FLAG initFlags;
	TSM_HKEY hTsmKey;
	PROV_CTX *pProvCtx = NULL;      // Provider context
    HANDLE hKeyInformation = NULL;  // Pointer to the adress where key info will be written 
    KEY_INFO *pKeyInfo;				// Handle to the generated key 
    DWORD keySize = 0;				// Given key size 

    // - Local copy of the crypto handler 
    pProvCtx = (PROV_CTX *) hProv;

    // - Test if the context has been granted 
    if(!ValidateHandle((HANDLE *) g_ContextHand, g_ContextLen, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    hContext = pProvCtx->hContext;

    // - Test if flags are supported 
    if (dwFlags & (CRYPT_NO_SALT | CRYPT_CREATE_SALT | CRYPT_PREGEN |
                 CRYPT_EXPORTABLE ) && dwFlags != CSP_FLAG_NO_KEY)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    // - Allocate memory for key information 
    pKeyInfo = (KEY_INFO *) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,
                                      sizeof(KEY_INFO));
    if(pKeyInfo == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    // - Prefill the key information structure 
    if(!InitKey(pProvCtx, pKeyInfo, Algid))
    {
        return FALSE;
    }
 
    // - Switch on Algid 
    switch(Algid)
    {
        //  - AT_SIGNATURE or AT_KEYEXCHANGE: same keys pair (from a techno
       //     point of view) 
        case AT_SIGNATURE:
        case AT_KEYEXCHANGE:
            //  - Get the key size if applicable 
            keySize = dwFlags>16;
    
            //  - If no size specified, set 2048 
            if(!keySize)
            {
                keySize = 2048;
            }
            //  - Fill blockLen with key size 
            pKeyInfo->blockLen = keySize;
            //  - Fill correct key algId 
            if(Algid == AT_SIGNATURE)
            {
                pKeyInfo->algId = CALG_RSA_SIGN;
            }
            else
            {
                pKeyInfo->algId = CALG_RSA_KEYX;
            }
            //  - Fill correct key dwKeySpec 
            pKeyInfo->dwKeySpec = Algid;
            break;
		case CSP_ALG_SMS4:
			keySize = dwFlags>16;
			
            //  - If no size specified, set 2048 
            if(!keySize)
            {
                keySize = 2048;
            }
            //  - Fill blockLen with key size 
            pKeyInfo->blockLen = keySize;
            //  - Fill correct key algId             
            {
                pKeyInfo->algId = CSP_ALG_SMS4;
            }
            //  - Fill correct key dwKeySpec 
            pKeyInfo->dwKeySpec = Algid;
            break;
        case CALG_RC2:
        case CALG_RC4:
        case CALG_DES:
        default:
            SetLastError(NTE_BAD_ALGID);
            return FALSE;
    }
    
//////////////////////////////////////////////////////////////////////////
//			Create Key
//////////////////////////////////////////////////////////////////////////
	//Load SMK Key by UUID
	m_result = gTspModule.Tspi_Context_LoadKeyByUUID(hContext, TSM_PS_TYPE_SYSTEM, *TSM_SMK_UUID, &hSMK);
	if(TSM_SUCCESS != m_result)
	{
		OUTSTRING1("Tspi_Context_LoadKeyByUUID %x\n",m_result);
		goto func_end;
	}

	// create tsm key
    {
		objectType = TSM_OBJECT_TYPE_KEY;
		if (Algid == AT_SIGNATURE)
		{
			initFlags = TSM_KEY_AUTHORIZATION	// 使用需授权的密钥
					| TSM_SM2KEY_TYPE_SIGNING	// SM2 加密密钥
					| TSM_KEY_TSP_SMK			// 使用 TCM SMK 模板(用于SMK的TSM密钥对象)
					;
		}
		else if (Algid == AT_KEYEXCHANGE)
		{
			initFlags = TSM_KEY_AUTHORIZATION
						| TSM_SM2KEY_TYPE_BIND
						| TSM_KEY_TSP_SMK
						| TSM_KEY_MIGRATABLE
						;
		}
		else if (Algid == CSP_ALG_SMS4)
		{
			initFlags = TSM_KEY_AUTHORIZATION
						| TSM_SMS4KEY_TYPE_BIND
						| TSM_KEY_TSP_SMK	
						| TSM_KEY_MIGRATABLE
						;
		}
				
		m_result = CreateKeyObj(hContext,&hTsmKey, initFlags);
		if(TSM_SUCCESS != m_result)
		{
			goto func_end;
		}

		//Create the hSm2Key with the hSmk wrapping key
		if (dwFlags != CSP_FLAG_NO_KEY)
		{
			m_result = gTspModule.Tspi_Key_CreateKey(hTsmKey, hSMK, 0);
			if(TSM_SUCCESS != m_result)
			{
				goto func_end;
			}
		}
		
		pKeyInfo->hKeyInformation =(HANDLE)hTsmKey;
	}

	//  - Fill key handle 
	*phKey = (HCRYPTKEY)pKeyInfo;

    OUTSTRING2("===hKey:");
    GrantHandle((HANDLE **) &g_KeyHand, &g_KeyLen, (HANDLE) *phKey);
    return TRUE;

func_end:
	return FALSE;
}


/*
 -  CPDeriveKey
 -
 *  Purpose:
 *                Derive cryptographic keys from base data
 *
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      Algid      -  Algorithm identifier
 *               IN      hBaseData -   Handle to base data
 *               IN      dwFlags    -  Flags values
 *               OUT     phKey      -  Handle to a generated key
 *
 *  Returns:
 */

BOOL 
CPDeriveKey_Internal(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
	PROV_CTX *pProvCtx = NULL;      // Provider context 
    HASH_INFO *pHash = NULL;        // Hash information 
    HANDLE hKeyInformation = NULL;  // Pointer to the adress where key info will be written 
    KEY_INFO *pKeyInfo;				// Handle to the generated key 
    
    // - Nullify the returned pointer to the key handler 
    *phKey = (HCRYPTKEY)NULL;    
   
    // - Local copy of the crypto handler 
    pProvCtx = (PROV_CTX *) hProv;

    // - Local copy of the hash handle 
    pHash = (HASH_INFO *) hHash;

    // - Test if the context has been granted 
    if(!ValidateHandle((HANDLE *) g_ContextHand, g_ContextLen, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    // - Test if hash handle has been granted 
    if(!ValidateHandle((HANDLE *) g_HashHand, g_HashLen, (HANDLE) hHash))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }

    // - If hash is finished. Error 
    // warning This could be an error, perphas it have to be handled case by case 
    if(pHash->finished)
    {
        SetLastError(NTE_BAD_HASH_STATE);
        return FALSE;
    }
    
    // - Test if ALG_ID is supported 
    if(!((Algid == CALG_RC2) || (Algid == CALG_RC4)))
    {
        SetLastError(NTE_BAD_ALGID);
        return FALSE;
    }
    
    // - Test dwFlags are supported 
    if (dwFlags & ~(CRYPT_CREATE_SALT|CRYPT_EXPORTABLE|CRYPT_NO_SALT|CRYPT_USER_PROTECTED))
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }

    // - Allocate memory for key information 
    pKeyInfo = (KEY_INFO *) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,sizeof(KEY_INFO));
    if(pKeyInfo == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }

    // - Prefill the key information structure 
    if(!InitKey(pProvCtx, pKeyInfo, Algid))
    {
        return FALSE;
    }

    // - Fill service specific key information 
    pKeyInfo->hKeyInformation = hKeyInformation;

    // - Fill key handle
    *phKey = (HCRYPTKEY) pKeyInfo;

    // - Grant hit
    OUTSTRING2("===hKey:");
    GrantHandle((HANDLE **) &g_KeyHand, &g_KeyLen, (HANDLE) *phKey);    
	OUTSTRING2("CPDeriveKey");
    return TRUE;
}


/*
 -  CPDestroyKey
 -
 *  Purpose:
 *                Destroys the cryptographic key that is being referenced
 *                with the hKey parameter
 *
 *
 *  Parameters:
 *               IN      hProv  -  Handle to a CSP
 *               IN      hKey   -  Handle to a key
 *
 *  Returns:
 */

BOOL  
CPDestroyKey_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey)
{
	PROV_CTX *pProvCtx = NULL;      // Provider context 
    KEY_INFO *pKeyInfo;				// Handle to the generated key 
	TSM_HKEY tsmKey;
	TSM_RESULT tsmResult;
	TSM_HCONTEXT hContext;
	
    // - Local copy of the crypto handler 
    pProvCtx = (PROV_CTX *) hProv;
    
    // - Local copy of the key handler 
    pKeyInfo = (KEY_INFO *) hKey;
	
    // - Test if tha handle has been granted 
    if(!ValidateHandle((HANDLE *) g_ContextHand, g_ContextLen, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    // - Test if key handle has been granted 
    if(!ValidateHandle((HANDLE *) g_KeyHand, g_KeyLen, (HANDLE) hKey))
    {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }

	tsmKey = (TSM_HKEY)pKeyInfo->hKeyInformation;
	hContext = pProvCtx->hContext;
	tsmResult = gTspModule.Tspi_Context_CloseObject(hContext, tsmKey);
	if (tsmResult != TSM_SUCCESS)
	{
		OUTSTRING2("Close Key Object failed\n");
	}

    // - Destroy them 
    if(1/*destroyKeys(pProvCtx, pKeyInfo->hKeyInformation)*/)
    {
        // - Revoke handle 
        OUTSTRING2("===hKey:");
        if(RemoveHandle((HANDLE **) &g_KeyHand, &g_KeyLen, (HANDLE) hKey))
        {
            // - Free key info 
            if(!HeapFree(pProvCtx->heap, 0, pKeyInfo))
            {
                SetLastError(NTE_BAD_KEY);
                return FALSE;
            }
            return TRUE;
        }
        else
        {
            SetLastError(NTE_BAD_KEY);
            return FALSE;
        }
    }
	OUTSTRING2("CPDestroyKey");
    return TRUE;
}


/*
 -  CPSetKeyParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a key
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      hKey    -  Handle to a key
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL 
CPSetKeyParam_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{  
	PROV_CTX *pProvCtx = NULL;      // Provider context 
    KEY_INFO *pKeyInfo; // Handle to the generated key 
   
    // - Local copy of the crypto handler 
    pProvCtx = (PROV_CTX *) hProv;
    
    // - Local copy of the key handler 
    pKeyInfo = (KEY_INFO *) hKey;

    // - Test if tha handle has been granted 
    if(!ValidateHandle((HANDLE *) g_ContextHand, g_ContextLen, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    // - Test if key handle has been granted 
    if(!ValidateHandle((HANDLE *) g_KeyHand, g_KeyLen, (HANDLE) hKey))
    {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }
    
    // - Test Flags validity 
    if (dwFlags)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    if(pbData == NULL)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    // - Switch on word parameter 
    switch(dwParam)
    {
        case KP_SALT:
        case KP_SALT_EX:       
        case KP_PERMISSIONS:        
        case KP_IV:
        case KP_PADDING:
        case KP_MODE:
        case KP_MODE_BITS:
        case KP_EFFECTIVE_KEYLEN:
			break;
        default:
            SetLastError(NTE_BAD_TYPE);
            return FALSE;
    }
	OUTSTRING2("CPSetKeyParam\n");
    return TRUE;
}


/*
 -  CPGetKeyParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a key
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      hKey       -  Handle to a key
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN      pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL  
CPGetKeyParam_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
	PROV_CTX *pProvCtx = NULL;		// Provider context 
    KEY_INFO *pKeyInfo;				// Handle to the generated key 
   
    // - Local copy of the crypto handler 
    pProvCtx = (PROV_CTX *) hProv;
    
    // - Local copy of the key handler 
    pKeyInfo = (KEY_INFO *) hKey;
   
    // - Test if tha handle has been granted 
    if(!ValidateHandle((HANDLE *) g_ContextHand, g_ContextLen, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    // - Test if key handle has been granted 
    if(!ValidateHandle((HANDLE *) g_KeyHand, g_KeyLen, (HANDLE) hKey))
    {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }
    
    // - Test Flags validity 
    if (dwFlags)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    if(pbData == NULL)
    {
        // - Switch on word parameter 
        switch(dwParam)
        {
            case KP_ALGID:
            //  - KP_ALGID: size of DWORD in Byte 
                *pcbDataLen = sizeof(DWORD)/8;
                break;
            case KP_BLOCKLEN:
            //  - KP_BLOCKLEN: size of DWORD 
                *pcbDataLen = sizeof(DWORD)/8;
                break;
            case KP_KEYLEN:
            //  - KP_KEYLEN: size of DWORD 
                *pcbDataLen = sizeof(DWORD)/8;
                break;
            case KP_SALT:
            //  - KP_SALT: size of salt bytes array 
                *pcbDataLen = pKeyInfo->saltLen;
                break;
            case KP_PERMISSIONS:
            //  - KP_PERMISSIONS: size of DWORD 
                *pcbDataLen = sizeof(DWORD)/8;
                break;
            case KP_IV:
            //  - KP_IV: size of iv bytes array 
                *pcbDataLen = pKeyInfo->ivLen;
                break;
            case KP_PADDING:
            //  - KP_PADDING: size of DWORD 
                *pcbDataLen = sizeof(DWORD)/8;
                break;
            case KP_MODE:
            //  - KP_MODE: size of DWORD 
                *pcbDataLen = sizeof(DWORD)/8;
                break;
            case KP_MODE_BITS:
            //  - KP_MODE_BITS: size of DWORD 
                *pcbDataLen = sizeof(DWORD)/8;
                break;
            case KP_EFFECTIVE_KEYLEN:
            //  - KP_EFFECTIVE_KEYLEN: size of DWORD 
                //   - If key is a RC2 key,
                if(pKeyInfo->algId==CALG_RC2)
                {
                    *pcbDataLen = sizeof(DWORD)/8;
                }
                else
                {
                    SetLastError(NTE_BAD_FLAGS);
                    return FALSE;
                }
                break;
            default:
                SetLastError(NTE_BAD_TYPE);
                return FALSE;
        }
    }
    else
    // - If second call retrieving data 
    {
        // - Switch on word parameter 
        switch(dwParam)
        {
            case KP_ALGID:
            case KP_KEYLEN:  
            case KP_BLOCKLEN:
            case KP_SALT:
            case KP_PERMISSIONS:    
            case KP_IV:
            case KP_PADDING:
            case KP_MODE:
            case KP_MODE_BITS:
            case KP_EFFECTIVE_KEYLEN:
                break;
            default:
                SetLastError(NTE_BAD_TYPE);
                return FALSE;
        }
    }
    
	OUTSTRING2("CPGetKeyParam");    
    return TRUE;
}


/*
 -  CPSetProvParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a provider
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL /*WINAPI*/
CPSetProvParam_Internal(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{
	DWORD   dataLen = 0; // Returned data lenth in bytes 
    char *localPin = NULL; // The transmitted cached PIN 
    PROV_CTX *pProvCtx = NULL; // The local casted copy of the provider context pointer 
    
    // - Local copy of the crypto handle 
    pProvCtx = (PROV_CTX *) hProv;

    // - Test if c handle has been granted 
    if(!ValidateHandle(g_ContextHand, g_ContextLen, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    // - Test flag existenz 
    if(dwFlags)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    // todo Code the busy test ! 
    switch(dwParam)
    {
        case PP_KEYEXCHANGE_PIN: 
        case PP_SIGNATURE_PIN: 
            break;
        default:
            SetLastError(NTE_BAD_TYPE);
            return FALSE;
    }
	OUTSTRING2("CPSetProvParam\n");
    return TRUE;
}


/*
 -  CPGetProvParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a provider
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN OUT  pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL /*WINAPI*/
CPGetProvParam_Internal(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{ 
	DWORD   dataLen = 0; // Returned data lenth in bytes 
    PROV_ENUMALGS *enumAlg = NULL; // The enumerated Alg 
    char *localPin = NULL; // The transmitted cached PIN 
    PROV_CTX *pProvCtx = NULL; // The local casted copy of the provider context pointer 
    
    // - Local copy of the crypto handle 
    pProvCtx = (PROV_CTX *) hProv;

    // - Test if c handle has been granted 
    if(!ValidateHandle(g_ContextHand, g_ContextLen, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    // - Test flag colours 
    if(dwFlags && (dwFlags & ~(CRYPT_FIRST)))
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;

    }

    switch(dwParam)
    {
        case PP_CONTAINER: //  - PP_CONTAINER:           
			if (pProvCtx->ContainerName != NULL)
			{
				dataLen = strlen(pProvCtx->ContainerName);
			}
            break;
        case PP_ENUMALGS: //  - PP_ENUMALGS: 
            //	- Data len <= max lenth of the ENUMALGS structure.
			//	Currently, dword + alg_id + 16*uchar 
            dataLen = sizeof(PROV_ENUMALGS) + 15;
            break;
        case PP_IMPTYPE: 
			//  - PP_IMPTYPE: 
            //	- it is a DWORD 
            dataLen = sizeof(DWORD);
            break;
        case PP_KEYEXCHANGE_PIN: 
			// - PP_KEYEXCHANGE_PIN: 
            // - Length of the cached pin if != NULL
            if(pProvCtx->cachedKeyExchangePin != NULL)
            {
                dataLen = strlen(pProvCtx->cachedKeyExchangePin);
            }
            else
            {
                dataLen = 0;
            }
            break;
        case PP_KEYSPEC: //  - PP_KEYSPEC: 
            //   - DWORD 
            dataLen = sizeof(DWORD);
            break;
        case PP_KEYSTORAGE: //  - PP_KEYSTORAGE: 
            //   - DWORD 
            dataLen = sizeof(DWORD);
            break;
        case PP_NAME: //  - PP_NAME: 
            //	- Length of the csp name 
			//	dataLen = strlen(CSP_NAME);
            break;
        case PP_PROVTYPE: //  - PP_PROVTYPE: 
            //   - DWORD 
            dataLen = sizeof(DWORD);
            break;
        case PP_SIGNATURE_PIN: //  - PP_SIGNATURE_PIN: 
            //   - Length of the cached PIN if != NULL 
            if(pProvCtx->cachedSigPin != NULL)
            {
                dataLen = strlen(pProvCtx->cachedSigPin);
            }
            else
            {
                dataLen = 0;
            }
            break;
        case PP_VERSION: //  - PP_VERSION: 
            //   - DWORD 
            dataLen = sizeof(DWORD);
            break;
        default:
            SetLastError(NTE_BAD_TYPE);
            return FALSE;
    }

    // - First call 
    if(pbData == NULL)
    {
        *pcbDataLen = dataLen;
    }
    else	// - Second call 
    {
        if(*pcbDataLen < dataLen)
        {
            SetLastError(ERROR_MORE_DATA);
            return FALSE;
        }
        switch(dwParam)
        {
            case PP_CONTAINER: //  - PP_CONTAINER: 
                //   - If container name is not NULL 
				if (pProvCtx->ContainerName != NULL)
				{
					strcpy(pbData, pProvCtx->ContainerName);
				}else
				{
					SetLastError(NTE_FAIL);
					return FALSE;
				}
                break;
            case PP_ENUMALGS: //  - PP_ENUMALGS: 
                //   - If CRYPT_FIRST flagged 
                if(dwFlags & CRYPT_FIRST)
                {
                    //    - Set current Alg to 0 
                    pProvCtx->currentAlg = 0;
                }
                //   - Else,
                else
                {
                    //    - Next Algorithm 
                    pProvCtx->currentAlg++;
                }
                enumAlg = (PROV_ENUMALGS *)pbData;
                
            case PP_IMPTYPE: //  - PP_IMPTYPE: 
                //   - it is a Mixed implementation (token + openSSL) 
                *pbData = CRYPT_IMPL_MIXED;
                break;
            case PP_KEYEXCHANGE_PIN: //  - PP_KEYEXCHANGE_PIN: 
                //   - Cast pbData pointer to localPin 
                localPin = (char *)pbData;
                //   - Copy the cached pin if !=NULL 
                if(pProvCtx->cachedKeyExchangePin != NULL)
                {
                    strcpy(localPin, pProvCtx->cachedKeyExchangePin);
                }
                else
                {
                    *localPin = '\0';
                }
                break;
            case PP_KEYSPEC: //  - PP_KEYSPEC: 
                //   - AT_SIGNATURE | AT_KEYECHANGE are the only supported key
               //      specs. 
                *pbData = AT_SIGNATURE | AT_KEYEXCHANGE;
                break;
            case PP_KEYSTORAGE: //  - PP_KEYSTORAGE:            
                *pbData = 0;
                break;
            case PP_NAME: //  - PP_NAME: 
                //   - Cast pbData pointer to localPin 
                localPin = (char *)pbData;
                //   - Copy the container name 
                strcpy(localPin, pProvCtx->ContainerName);
                break;
            case PP_PROVTYPE: //  - PP_PROVTYPE: 
                //   - PROV_RSA_FULL 
                *pbData = PROV_RSA_FULL;
                break;
            case PP_SIGNATURE_PIN: //  - PP_SIGNATURE_PIN: 
                //   - Cast pcbData pointer to localPin 
                localPin = (char *)pbData;
                //   - Copy the cached pin if !=NULL 
                if(pProvCtx->cachedSigPin)
                {
                    strcpy(localPin, pProvCtx->cachedSigPin);
                }
                else
                {
                    *localPin = '\0';
                }
                break;
            case PP_VERSION: //  - PP_VERSION: 
                //   - DWORD 
//                *pbData = (BYTE) CSP_VERSION;
                break;
            default:
                SetLastError(NTE_BAD_TYPE);
                return FALSE;
        }
    }

	OUTSTRING2("CPGetProvParam");
    return TRUE;
}


/*
 -  CPSetHashParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a hash
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      hHash   -  Handle to a hash
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL 
CPSetHashParam_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{  
	PROV_CTX *pProvCtx = NULL;      // Provider context 
	HASH_INFO *pHash = NULL;        // Hash information 
	DWORD     hashValLen=0;                    // Hashval lenth 
	BYTE* pbValue = NULL;

	// - Local copy of the crypto handle 
	pProvCtx = (PROV_CTX *) hProv;

	// - Local copy of the hash handle 
	pHash = (HASH_INFO *) hHash;

	// - Test if c handle has been granted 
	if(!ValidateHandle(g_ContextHand, g_ContextLen, (HANDLE) hProv))
	{
		SetLastError(NTE_BAD_UID);
		return FALSE;
	}

	// - Test if hash handle has been granted 
	if(!ValidateHandle((HANDLE *) g_HashHand, g_HashLen, (HANDLE) hHash))
	{
		SetLastError(NTE_BAD_HASH);
		return FALSE;
	}

	// - Test if flags has been set 
	if(dwFlags)
	{
		SetLastError(NTE_BAD_FLAGS);
		return FALSE;
	}

	// - Test if flag is  HP_HASHVAL (only existing in API) 
	if(dwParam != HP_HASHVAL)
	{
		SetLastError(NTE_BAD_TYPE);
		return FALSE;
	}

	// - Test if pbData is not NULL 
	if(pbData == NULL)
	{
		SetLastError(NTE_BAD_FLAGS);
		return FALSE;
	}

	//   - If hash size < 0, bad hash 
	hashValLen = 32;
	if(hashValLen < 0)
	{
		SetLastError(NTE_BAD_HASH);
		return FALSE;
	}

	pbValue = HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY, 32);
	memcpy(pbValue, pbData, hashValLen);
	pHash->value = pbValue;

	OUTSTRING2("CPSetHashParam\n");
    return TRUE;
}


/*
 -  CPGetHashParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a hash
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      hHash      -  Handle to a hash
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN      pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL /*WINAPI*/
CPGetHashParam_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
    PROV_CTX *pProvCtx = NULL;      // Provider context 
    HASH_INFO *pHash = NULL;        // Hash information 
    DWORD     i=0;                  // Iterator 
    DWORD   hashLen = 0;            // Hash lenth in Bytes 
	TSM_RESULT m_result;
	BYTE* pbHashData = NULL;
	BYTE* pbTemp = NULL;
    
    // - Local copy of the crypto handle 
    pProvCtx = (PROV_CTX *) hProv;
    // - Local copy of the hash handle 
    pHash = (HASH_INFO *) hHash;

    // - Test if c handle has been granted 
    if(!ValidateHandle(g_ContextHand, g_ContextLen, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    // - Test if hash handle has been granted 
    if(!ValidateHandle((HANDLE *) g_HashHand, g_HashLen, (HANDLE) hHash))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
 
    // - Test if flags has been set 
    if(dwFlags)
    {
        // \todo support CRYPT_USERDATA 
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    // - If first call to learn the pcbDataLen*/
    // \warning size is returned in BYTES 
    if(pbData == NULL)
    {
        switch(dwParam)
        {
            case HP_ALGID:
                //  - ALGID: data lenth to size of DWORD 
                *pcbDataLen = sizeof(DWORD)/8;
                break;
            case HP_HASHSIZE:
                //  - HASHSIZE: data lenth to DWORD 
                *pcbDataLen = sizeof(DWORD)/8;
                break;
            case HP_HASHVAL:
                //  - HashVal: test if hash has been already finished 
                //   - Get hash size 
				hashLen = 32; 
                //   - If hash size < 0, bad hash 
                if(hashLen < 0)
                {
                    SetLastError(NTE_BAD_HASH);
                    return FALSE;
                }
                //   - Fill hash lenth 
                *pcbDataLen = hashLen;          
                break;
            default:
                //  - Every else bad type 
                SetLastError(NTE_BAD_TYPE);
                return FALSE;
        }
    }
    // - Second call to feed pbData[pcbDataLen] buffer 
    else
    {
        switch(dwParam)
        {
            case HP_ALGID:
                //  - algid, test if data len is not under 4 
                if(*pcbDataLen <4)
                {
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }
                //   - Fill data with Alg ID 
                *pbData = pHash->Algid;
                break;
            case HP_HASHSIZE:
                //  - hashsize, test if data len is not under 4 
                if(*pcbDataLen <4)
                {
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }
                //   - Get hash size 
                //   - If hash size < 0, bad hash 
				hashLen = 32;		// add in 2011-7-11 9:27:44
                if(hashLen < 0)
                {
                    SetLastError(NTE_BAD_HASH);
                    return FALSE;
                }
                //   - Fill data with hash size 
                
				memcpy(pbData, &hashLen, sizeof(hashLen));
                break;
            case HP_HASHVAL:
                //  - Hash value 
                if(pcbDataLen == NULL)
                {
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }

                //   - If hash not finished 
                if(!pHash->finished)
                {			
					if (pHash->data == NULL)
					{
						SetLastError(NTE_FAIL);
						return FALSE;
					}

					m_result = gTspModule.Tspi_Hash_UpdateHashValue(pHash->hHash, pHash->lenth, pHash->data);
					if (m_result != TSM_SUCCESS)
					{
						OUTSTRING1("SethashValue: %x\n",m_result);
						return FALSE;
					}
					pbHashData = HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY, 32);

					m_result = gTspModule.Tspi_Hash_GetHashValue(pHash->hHash, &hashLen, &pbTemp);
					if (m_result != TSM_SUCCESS)
					{
						OUTSTRING1("GetHashValue: %x\n",m_result);
						return FALSE;
					}
					memcpy(pbHashData, pbTemp, hashLen);
					pHash->value = pbHashData;
                    
					// - Finish him 
                    pHash->finished = 1;
                }

                //   - Get hash size 
                //   - If hash size < 0, bad hash 
                if(hashLen < 0)
                {
                    SetLastError(NTE_BAD_HASH);
                    return FALSE;
                }      
                
                //   - Test if data lenth is no under hash lenth 
                if(*pcbDataLen < hashLen)
                {
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }
				*pcbDataLen = hashLen;
				
                //   - Copy hash value to data 
				memset(pbData, 0, hashLen);
				memcpy(pbData, pHash->value, hashLen);
                break;
            default:
                //  - Everything else: bad type 
                SetLastError(NTE_BAD_TYPE);
                return FALSE;
        }
    }
	OUTSTRING2("CPGetHashParam\n");
    return TRUE;
}


/*
 -  CPExportKey
 -
 *  Purpose:
 *                Export cryptographic keys out of a CSP in a secure manner
 *
 *
 *  Parameters:
 *               IN  hProv         - Handle to the CSP user
 *               IN  hKey          - Handle to the key to export
 *               IN  hPubKey       - Handle to exchange public key value of
 *                                   the destination user
 *               IN  dwBlobType    - Type of key blob to be exported
 *               IN  dwFlags       - Flags values
 *               OUT pbData        -     Key blob data
 *               IN OUT pdwDataLen - Length of key blob in bytes
 *
 *  Returns:
 */

BOOL /*WINAPI*/
CPExportKey_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwBlobType,
    IN  DWORD dwFlags,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen)
{
	TSM_HCONTEXT hContext;
	TSM_HTCM hTcm;

	TSM_RESULT m_result = 0;	
	TSM_HKEY hProtectKey = 0;				// in 密钥对象句柄，该密钥属于迁移的目标平台，其公钥用于保护被迁移密钥。
	TSM_MIGRATE_SCHEME migrationScheme = 0; // in 迁移方案标识，为TSM_MS_MIGRATE或者是TSM_MS_REWRAP
	UINT32 pulMigrationKeyAuthSize = 0;		// out ppulMigrationKeyAuth 的数据长度
	BYTE* ppulMigrationKeyAuth = NULL;		// out 指向MigrationKey 的授权数据
	
	UINT32 pulMigratedDataSize = 0;			// out prgbMigratedData 的数据长度
	BYTE* prgbMigratedData = NULL;			// out 在成功执行这个命令的情况下这个参数返回迁移数据
	UINT32 pulEncSymKeySize = 0;			// out 指向被加密的对称密钥的数据长度的指针
	BYTE* prgbEncSymKey = NULL;				// out 指向对称密钥数据的指针，该对称密钥已被Tspi_Key_AuthorizeMigrationKey()所认证的公钥加密保护
	
	TSM_HKEY hKey2Mig = 0;					// 需要迁移的密钥句柄
	TSM_HPOLICY hMigKeyPolicy = 0;			// 修改TSM_HKEY -> TSM_HPOLICY	in 2011-6-7
	TSM_HPOLICY hSms4KeyPolicy = 0;
	TSM_HPOLICY hSm2KeyPolicy = 0;
	TSM_HPOLICY hPolicy = 0;
	
	TSM_FLAG objectType = 0;
    TSM_FLAG initFlags = 0;
	
	PROV_CTX *pProvCtx = NULL;      /* Provider context */
	KEY_INFO *pPubKey = NULL;
	KEY_INFO *pKey	= NULL;
	MIGKEYBLOB *MigBlob = NULL;
	DWORD offset = 0;
	// - Nullify the returned data lenth & the  
	//*pcbDataLen = 0;

	// - Local copy of the crypto handler 
	pProvCtx = (PROV_CTX *) hProv;
	
	// - Test if the context has been granted 
	if(!ValidateHandle((HANDLE *) g_ContextHand, g_ContextLen, (HANDLE) hProv))
	{
	   SetLastError(NTE_BAD_UID);
	   return FALSE;
	}
	hContext = pProvCtx->hContext;

	// - Test if the key handle has been granted 
	if(!ValidateHandle((HANDLE *) g_KeyHand, g_KeyLen, (HANDLE) hKey))
	{
	   SetLastError(NTE_BAD_KEY);
	   return FALSE;
	}
	
	if (!ValidateHandle((HANDLE*)g_KeyHand, g_KeyLen, (HANDLE)hKey))
	{
		SetLastError(NTE_BAD_KEY);
		return FALSE;
	}
	if (dwFlags)
	{
		SetLastError(NTE_BAD_FLAGS);
		return FALSE;
	}

	//////////////////////////////////////////////////////////////////////////
	//			Create The MigBlob											//
	//////////////////////////////////////////////////////////////////////////
	migrationScheme = TSM_MS_MIGRATE;
	m_result = gTspModule.Tspi_Context_GetTCMObject(hContext, &hTcm);
	pPubKey = (KEY_INFO* )hPubKey;
	hProtectKey =(TSM_HKEY) pPubKey->hKeyInformation;

	//创建迁移授权
	m_result = gTspModule.Tspi_Key_AuthorizeMigrationKey(
		hTcm,
		hProtectKey,
		migrationScheme,
		&pulMigrationKeyAuthSize,
		&ppulMigrationKeyAuth
		);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	////////////////////////////////////////////////////////////////////////////////
	objectType = TSM_OBJECT_TYPE_POLICY;//策略对象
	initFlags = TSM_POLICY_MIGRATION;	//用于密钥迁移的策略对象
	m_result = gTspModule.Tspi_Context_CreateObject(hContext, objectType, initFlags, &hMigKeyPolicy);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}
	 	
 	pKey = (KEY_INFO* )hKey;
 	hKey2Mig = (TSM_HKEY)pKey->hKeyInformation;

	m_result = gTspModule.Tspi_Policy_AssignToObject(hMigKeyPolicy,hKey2Mig);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}
	
	//Get Policy Object for the hKey
	m_result = gTspModule.Tspi_GetPolicyObject(hKey2Mig, TSS_POLICY_MIGRATION, &hSms4KeyPolicy);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}
	
	//Set Secret for the hKeyPolicy
	m_result = gTspModule.Tspi_Policy_SetSecret(hSms4KeyPolicy, TSM_SECRET_MODE_PLAIN, g_uSMKSecretSize, g_SMKAuth);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	// Load key
	m_result = gTspModule.Tspi_Key_LoadKey(hKey2Mig,hSMK);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}
	
	/////////////////////////////////////////////////////////////////////////////////////////
	//创建迁移密钥数据块	
	m_result = gTspModule.Tspi_Key_CreateMigrationBlob(
		hKey2Mig,
		hSMK,
		pulMigrationKeyAuthSize,
		ppulMigrationKeyAuth,
		&pulMigratedDataSize,
		&prgbMigratedData,			// part 1
		&pulEncSymKeySize,
		&prgbEncSymKey				// part 2
		);
	if(TSM_SUCCESS != m_result)
	{	
		OUTSTRING1("CreateMigBlob %x\n",m_result);
		m_result = gTspModule.Tspi_Key_UnloadKey(hKey2Mig);
		if(TSM_SUCCESS != m_result)
		{
			return m_result;
		}
		return m_result;
	}

	MigBlob = (MIGKEYBLOB *)malloc(sizeof(MIGKEYBLOB));
	MigBlob->EncKeyLen = pulMigratedDataSize;
	MigBlob->pbEncKey = prgbMigratedData;
	MigBlob->SMS4DataLen = pulEncSymKeySize;
	MigBlob->pbSMS4Data = prgbEncSymKey;
	MigBlob->Algid = pKey->dwKeySpec;

	*pcbDataLen = sizeof(DWORD)*2 + MigBlob->EncKeyLen + MigBlob->SMS4DataLen + sizeof(ALG_ID);
	if(pbData == NULL)
	{
		SetLastError(NTE_BAD_DATA);
		return FALSE;
	}

	*pcbDataLen = LoadMigBlob(MigBlob, pbData);

	// free memory from tsp
	if (prgbMigratedData)
	{ 
		//free(prgbMigratedData); // tsp中对byte**参数应该加入到内存管理中 对byte*参数不能随便释放
		gTspModule.Tspi_Context_FreeMemory(hContext,prgbMigratedData);
	}

	if (prgbEncSymKey)
	{
		gTspModule.Tspi_Context_FreeMemory(hContext,prgbEncSymKey);
	}

	if (ppulMigrationKeyAuth)
	{
		gTspModule.Tspi_Context_FreeMemory(hContext,ppulMigrationKeyAuth);
	}

	if (MigBlob)
	{ 
		free(MigBlob);
	}
	
	m_result = gTspModule.Tspi_Key_UnloadKey(hKey2Mig);
	if(TSM_SUCCESS != m_result)
	{
		return m_result;
	}
	
	//////////////////////////////////////////////////////////////////////////
	OUTSTRING2("CPExportKey\n");
    return TRUE;
func_end:
	return FALSE;
}


/*
 -  CPImportKey
 -
 *  Purpose:
 *                Import cryptographic keys
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the CSP user
 *               IN  pbData    -  Key blob data
 *               IN  dwDataLen -  Length of the key blob data
 *               IN  hPubKey   -  Handle to the exchange public key value of
 *                                the destination user
 *               IN  dwFlags   -  Flags values
 *               OUT phKey     -  Pointer to the handle to the key which was
 *                                Imported
 *
 *  Returns:
 */

BOOL /*WINAPI*/
CPImportKey_Internal(
    IN  HCRYPTPROV hProv,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
	TSM_HCONTEXT hContext;
	TSM_RESULT m_result = 0;
	TSM_HOBJECT hObject = 0;
	TSM_FLAG persistentStorageType = TSS_PS_TYPE_SYSTEM;
	
	TSM_HKEY hProtectKey = 0;				// in 密钥对象句柄，该密钥属于迁移的目标平台，其公钥用于保护被迁移密钥。
	TSM_MIGRATE_SCHEME migrationScheme = 0; // in 迁移方案标识，为TSM_MS_MIGRATE或者是TSM_MS_REWRAP
	
	UINT32 pulMigratedDataSize = 0;			// out prgbMigratedData 的数据长度
	BYTE* prgbMigratedData = NULL;			// out 在成功执行这个命令的情况下这个参数返回迁移数据
	UINT32 pulEncSymKeySize = 0;			// out 指向被加密的对称密钥的数据长度的指针
	BYTE* prgbEncSymKey = NULL;				// out 指向对称密钥数据的指针，该对称密钥已被Tspi_Key_AuthorizeMigrationKey()所认证的公钥加密保护
	
	TSM_HKEY hKey2Mig = 0;					// 需要迁移的密钥句柄
	TSM_HPOLICY hMigKey = 0;				// 修改TSM_HKEY -> TSM_HPOLICY	in 2011-6-7
	TSM_HPOLICY hSms4KeyPolicy = 0;
	TSM_HPOLICY hSm2KeyPolicy = 0;
	TSM_HPOLICY hMigKeyPolicy = 0;
	TSM_HPOLICY hPolicy = 0;
	
	TSM_FLAG objectType = 0;
    TSM_FLAG initFlags = 0;
	
	PROV_CTX *pProvCtx = NULL;      /* Provider context */
	KEY_INFO *pPubKey = NULL;
	KEY_INFO *pKeyInfo	= NULL;
	MIGKEYBLOB *MigBlob = NULL;
	ALG_ID algid;

	// - Local copy of the crypto handler 
	pProvCtx = (PROV_CTX *) hProv;

	// - Test if the context has been granted 
	if(!ValidateHandle((HANDLE *) g_ContextHand, g_ContextLen, (HANDLE) hProv))
	{
		SetLastError(NTE_BAD_UID);
		return FALSE;
	}
	
	// - Test if the key handle has been granted 
	if(!ValidateHandle((HANDLE *) g_KeyHand, g_KeyLen, (HANDLE) hPubKey))
	{
		SetLastError(NTE_BAD_KEY);
		return FALSE;
	}
	
	if (dwFlags )	
	{
		SetLastError(NTE_BAD_FLAGS);
		return FALSE;
	}

	if (pbData == NULL)
	{
		SetLastError(NTE_PERM);
		return FALSE;
	}

//////////////////////////////////////////////////////////////////////////
	migrationScheme = TSM_MS_MIGRATE;
	hContext = pProvCtx->hContext;
	pPubKey = (KEY_INFO* )hPubKey;
	hProtectKey = (TSM_HKEY)pPubKey->hKeyInformation;
	MigBlob = (MIGKEYBLOB *)malloc(cbDataLen);
	memset(MigBlob, 0, cbDataLen);
	UnLoadMigBlob(MigBlob, pbData);
	algid = MigBlob->Algid;

	if(!CPGenKey_Internal(hProv, algid, CSP_FLAG_NO_KEY, phKey))
	{
		goto func_end;
	}
	
	pKeyInfo = (KEY_INFO *)phKey;
	hKey2Mig = (TSM_HKEY) pKeyInfo->hKeyInformation;

	m_result = gTspModule.Tspi_Key_LoadKey(hProtectKey,hSMK);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}	

	pulEncSymKeySize = MigBlob->SMS4DataLen;
	pulMigratedDataSize = MigBlob->EncKeyLen;
	prgbEncSymKey = MigBlob->pbSMS4Data;
	prgbMigratedData = MigBlob->pbEncKey;

	//导入迁移密钥数据块	
	m_result = gTspModule.Tspi_Key_ConvertMigrationBlob(
		hProtectKey,
		hSMK,
		hKey2Mig,
		pulMigratedDataSize,
		prgbMigratedData,
		pulEncSymKeySize,
		prgbEncSymKey
		);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	m_result = gTspModule.Tspi_Key_UnloadKey(hProtectKey);
	if (m_result != TSM_SUCCESS)
	{
		return FALSE;
	}

	// free memory
	if (MigBlob)
	{
		free(MigBlob->pbEncKey);
		free(MigBlob->pbSMS4Data);
		free(MigBlob);
	}

	OUTSTRING2("CPImportKey\n");
    return TRUE;
func_end:
	return FALSE;
}


/*
 -  CPEncrypt
 -
 *  Purpose:
 *                Encrypt data
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the CSP user
 *               IN  hKey          -  Handle to the key
 *               IN  hHash         -  Optional handle to a hash
 *               IN  Final         -  Boolean indicating if this is the final
 *                                    block of plaintext
 *               IN  dwFlags       -  Flags values
 *               IN OUT pbData     -  Data to be encrypted
 *               IN OUT pdwDataLen -  Pointer to the length of the data to be
 *                                    encrypted
 *               IN dwBufLen       -  Size of Data buffer
 *
 *  Returns:
 */

BOOL /*WINAPI*/
CPEncrypt_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD cbBufLen)
{
	TSM_HCONTEXT	hContext;
	TSM_RESULT		m_result = TSM_SUCCESS;
	TSM_HOBJECT		hEncData = 0;
	BYTE			rgbEncData[512] = {0};
	UINT32			ulDataLength = 0;	
	UINT32			i = 0;
	TSM_HPOLICY		hEncPolicy = 0;
	TSM_HKEY		hBindSm2Key;	//
	HASH_INFO*		pHash = NULL;
	PROV_CTX *		pProv  = NULL;
	KEY_INFO *		pKey = NULL;
	BYTE *			pEncData = NULL;
	
	if (!ValidateHandle((HANDLE*)g_ContextHand, g_ContextLen, (HANDLE)hProv))
	{
		SetLastError(NTE_BAD_UID);
		return FALSE;
	}

	if (!ValidateHandle((HANDLE*)g_KeyHand, g_KeyLen, (HANDLE)hKey))
	{
		SetLastError(NTE_BAD_KEY);
		return FALSE;
	}

	if (!ValidateHandle((HANDLE*)g_HashHand, g_HashLen, (HANDLE)hHash))
	{
		SetLastError(NTE_BAD_HASH);
		return FALSE;
	}	

	pHash = (HASH_INFO*)hHash;
	if (pHash->finished)
	{
		SetLastError(NTE_BAD_HASH_STATE);
		return FALSE;
	}
	if (dwFlags)
	{
		SetLastError(NTE_BAD_FLAGS);
		return FALSE;
	}

 	if (pbData == NULL)
	{
		return FALSE;
	}

	OUTSTRING2("-_-_-_-_-_-_-_-_-_-_-_-_-ENC_-_-_-_-_-_-_-_-_-_-_-_-_-_\n");
	pProv = (PROV_CTX *)hProv;
	hContext = pProv->hContext;

	pKey = (KEY_INFO *)hKey;
	hBindSm2Key =(TSM_HKEY) pKey->hKeyInformation;

	m_result = gTspModule.Tspi_Key_LoadKey(hBindSm2Key, hSMK);
	if(TSM_SUCCESS != m_result)
	{
		
		OUTSTRING1("LoadKey %x\n",m_result);
		goto func_end;
	}

	m_result = gTspModule.Tspi_Context_CreateObject(hContext, TSM_OBJECT_TYPE_ENCDATA, TSM_ENCDATA_BIND, &hEncData);
	if(TSM_SUCCESS != m_result)
	{
		OUTSTRING1("Create %x\n", m_result);
		goto func_end;
	}

	m_result = gTspModule.Tspi_Data_Encrypt(hEncData, hBindSm2Key, TRUE, NULL, pbData, *pcbDataLen);
	if(TSM_SUCCESS != m_result)
	{
		OUTSTRING1("Encrypt %x\n", m_result);
		goto func_end;
	}
	
	m_result = gTspModule.Tspi_GetAttribData(hEncData, TSM_TSPATTRIB_ENCDATA_BLOB, TSM_TSPATTRIB_ENCDATABLOB_BLOB, pcbDataLen, &pEncData);
	if (m_result != TSM_SUCCESS)
	{
		OUTSTRING1("GetEncData: %x\n",m_result);
		return FALSE;
	}

	m_result = gTspModule.Tspi_Key_UnloadKey(hBindSm2Key);
	if(TSM_SUCCESS != m_result)
	{
		OUTSTRING2("UnLoad\n");
		goto func_end;
	}

	if (*pcbDataLen > cbBufLen)
	{
		SetLastError(NTE_NO_MEMORY);		
		return FALSE;
	}

	memset(pbData, 0, *pcbDataLen);
	memcpy(pbData, pEncData, *pcbDataLen);
	OUTSTRING2("\t-------------------Encrypt Successfully!----------------\n");
    return TRUE;

func_end:
	return FALSE; 

}


/*
 -  CPDecrypt
 -
 *  Purpose:
 *                Decrypt data
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the CSP user
 *               IN  hKey          -  Handle to the key
 *               IN  hHash         -  Optional handle to a hash
 *               IN  Final         -  Boolean indicating if this is the final
 *                                    block of ciphertext
 *               IN  dwFlags       -  Flags values
 *               IN OUT pbData     -  Data to be decrypted
 *               IN OUT pdwDataLen -  Pointer to the length of the data to be
 *                                    decrypted
 *
 *  Returns:
 */

BOOL /*WINAPI*/
CPDecrypt_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen)
{
	TSM_HCONTEXT	hContext;
	TSM_HKEY		hBindSm2Key;
	TSM_RESULT		m_result = TSM_SUCCESS;
	TSM_HOBJECT hEncData = 0;
	BYTE rgbEncData[512] = {0};
	UINT32 ulDataLength = 0;
	BYTE* rgbDecData = NULL;
	PROV_CTX * pProv = NULL;
	HASH_INFO* pHash = NULL;
	KEY_INFO* pKey	= NULL;
	UINT32 i = 0;
	TSM_HPOLICY hEncPolicy = 0;

	pProv = (PROV_CTX *)hProv;
	pHash = (HASH_INFO*)hHash;
	pKey = (KEY_INFO*)hKey;

	if (!ValidateHandle((HANDLE*)g_ContextHand, g_ContextLen, (HANDLE)hProv))
	{
		SetLastError(NTE_BAD_UID);
		return FALSE;
	}

	if (!ValidateHandle((HANDLE*)g_KeyHand, g_KeyLen, (HANDLE)hKey))
	{
		SetLastError(NTE_BAD_KEY);
		return FALSE;
	}

	if (!ValidateHandle((HANDLE*)g_HashHand, g_HashLen, (HANDLE)hHash))
	{
		SetLastError(NTE_BAD_HASH);
		return FALSE;
	}

	if (dwFlags)
	{
		SetLastError(NTE_BAD_FLAGS);
		return FALSE;
	}

	if (pHash->finished)
	{
		SetLastError(NTE_BAD_HASH_STATE);
		return FALSE;
	}

	if (pbData == NULL || pcbDataLen == NULL)
	{
		return FALSE;
	}

	pProv = (PROV_CTX *)hProv;
	pKey = (KEY_INFO*)hKey;
	pHash = (HASH_INFO*)hHash;

	hContext = pProv->hContext;
	hBindSm2Key = (TSM_HKEY)pKey->hKeyInformation;
	OUTSTRING2("====================================DEC=============================\n");

	m_result = gTspModule.Tspi_Key_LoadKey(hBindSm2Key, hSMK); 
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	m_result = gTspModule.Tspi_Context_CreateObject(hContext, TSM_OBJECT_TYPE_ENCDATA, TSM_ENCDATA_BIND, &hEncData);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	m_result = gTspModule.Tspi_SetAttribData(hEncData, TSM_TSPATTRIB_ENCDATA_BLOB, TSM_TSPATTRIB_ENCDATABLOB_BLOB, *pcbDataLen, pbData);
	if (m_result != TSM_SUCCESS)
	{
		OUTSTRING1("SetEnc: %x\n",m_result);
		return FALSE;
	}

	m_result = gTspModule.Tspi_Data_Decrypt(hEncData, hBindSm2Key, TRUE, NULL, &ulDataLength, &rgbDecData);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	memset(pbData, 0, sizeof(pbData));
 	memcpy(pbData, rgbDecData, ulDataLength);
	*pcbDataLen = ulDataLength;

	m_result = gTspModule.Tspi_Key_UnloadKey(hBindSm2Key);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	OUTSTRING2("\t+++++++++++++++Dec successfully+++++++++++++++++++\n");
	return TRUE;

func_end:
	return FALSE; 
}


/*
 -  CPCreateHash
 -
 *  Purpose:
 *                initate the hashing of a stream of data
 *
 *
 *  Parameters:
 *               IN  hUID    -  Handle to the user identifcation
 *               IN  Algid   -  Algorithm identifier of the hash algorithm
 *                              to be used
 *               IN  hKey   -   Optional handle to a key
 *               IN  dwFlags -  Flags values
 *               OUT pHash   -  Handle to hash object
 *
 *  Returns:
 */

BOOL /*WINAPI*/
CPCreateHash_Internal(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash)
{    
	PROV_CTX *pProvCtx = NULL;      // Provider context 
    HASH_INFO *pHash; // Local hash pointer copy 
    TSM_HCONTEXT hContext;
	TSM_RESULT m_result;
	TSM_HHASH hHash;

    // - Nullify hHash 
    *phHash = (HCRYPTHASH)NULL;  

    // - Local copu of the crypto handler 
    pProvCtx = (PROV_CTX *) hProv;
	hContext = pProvCtx->hContext;
    
    // - If context handle is granted 
    if(!ValidateHandle(g_ContextHand, g_ContextLen, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

	if (!ValidateHandle(g_KeyHand, g_KeyLen, (HANDLE)hKey))
	{
		SetLastError(NTE_BAD_KEY);
		return FALSE;
	}
    
    // -  If no flag set 
    if(dwFlags)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    // \todo complete hash algs 
    // If algid is supported 
    if(!((Algid==CALG_SHA) || (Algid == CALG_SHA1) || (Algid == CALG_MD5)))
    {
        SetLastError(NTE_BAD_ALGID);
        return FALSE;
    }
    
    // - Allocate memory for hash information 
    pHash = (HASH_INFO *) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,sizeof(HASH_INFO));
    if (pHash == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }

    // - Initialize hash structure: everything to 0/NULL, Algid set 
    pHash->Algid = Algid;
    pHash->finished = 0;
    pHash->lenth = 0;
    pHash->data = NULL;
    pHash->value = NULL;

	//////////////////////////////////////////////////////////////////////////
	//add HASH  handle 
	m_result = gTspModule.Tspi_Context_CreateObject(hContext, TSM_OBJECT_TYPE_HASH, TSM_HASH_SM3, &hHash);
	if(TSM_SUCCESS != m_result)
	{
		return FALSE;
	}
	pHash->hHash = hHash;
	//////////////////////////////////////////////////////////////////////////
    
    // Copy cast pHash to hHash 
	
    *phHash = (HCRYPTHASH) pHash;
    
    // Return the grant handle function result 
    OUTSTRING2("===hHash:");
    return GrantHandle((HANDLE **) &g_HashHand,&g_HashLen, (HANDLE) *phHash);
}


/*
 -  CPHashData
 -
 *  Purpose:
 *                Compute the cryptograghic hash on a stream of data
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *               IN  pbData    -  Pointer to data to be hashed
 *               IN  dwDataLen -  Length of the data to be hashed
 *               IN  dwFlags   -  Flags values
 *
 *  Returns:
 */

BOOL /*WINAPI*/
CPHashData_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  DWORD dwFlags)
{
	PROV_CTX *pProvCtx = NULL;     //  Provider context 
    HASH_INFO *pHash = NULL;        // Hash information 
    BYTE    *localValue = NULL;     // Local copy of the value 
    DWORD   newLenth = 0;           // The new to-hash value lenth in bytes 
    DWORD	i=0;                    // Iterator 
    
    // - Local copy of the crypto handle 
    pProvCtx = (PROV_CTX *) hProv;
    // - Local copy of the hash handle 
    pHash = (HASH_INFO *) hHash;

    // - If c handle is granted 
    if(!ValidateHandle(g_ContextHand, g_ContextLen, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    // - If h handle is granted 
    if(!ValidateHandle((HANDLE *) g_HashHand, g_HashLen, (HANDLE) hHash))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
 
    // - If no flag set 
    if(dwFlags)
    {
        // \todo support CRYPT_USERDATA 
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    // - If CPGetHashParam has not been called yet => unfinished state, ok to
   //    eat more 
    if(pHash->finished)
    {
        SetLastError(NTE_BAD_HASH_STATE);
        return FALSE;
    }
    
    // - the new to-hash value 
    newLenth = pHash->lenth + cbDataLen;

    // - Allocate memory for hash value 
    localValue = (BYTE *) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,newLenth);
    if (localValue == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    
    // - Copy to-hash value in the new allocated place 
    for(i=0; i <  pHash->lenth; i++)
    {
        localValue[i] = pHash->data[i];
    }
    
    // - Copy to-hash value at the end of the old value 
    for(i=pHash->lenth; i<newLenth; i++)
    {
        localValue[i] = pbData[i];
    }
    
	
    // - Free old to-hash value if non NULL 
    if(pHash->data != NULL)
    {
        if(!HeapFree(pProvCtx->heap, 0, pHash->data))
        {
            SetLastError(NTE_FAIL);
            return FALSE;
        }
    }
 
    // - Store new lenth 
    pHash->lenth = newLenth;
    
    // - Store new value 
    pHash->data = localValue;
    
    // - Ok, end 
	OUTSTRING2("CPHashData\n");
    return TRUE;
}


/*
 -  CPHashSessionKey
 -
 *  Purpose:
 *                Compute the cryptograghic hash on a key object.
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *               IN  hKey      -  Handle to a key object
 *               IN  dwFlags   -  Flags values
 *
 *  Returns:
 *               CRYPT_FAILED
 *               CRYPT_SUCCEED
 */

BOOL /*WINAPI*/
CPHashSessionKey_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags)
{
	    PROV_CTX *pProvCtx = NULL;     //  Provider context 
    HASH_INFO *pHash = NULL;        // Hash information 
    BYTE    *keyValue = NULL;     // Local copy of the key value 
    DWORD   keyValueLenth = 0;           // The lenth of the key value 
    
    // - Local copy of the crypto handle 
    pProvCtx = (PROV_CTX *) hProv;
    // - Local copy of the hash handle 
    pHash = (HASH_INFO *) hHash;

    // - If c handle is granted 
    if(!ValidateHandle(g_ContextHand, g_ContextLen, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    // - If h handle is granted 
    if(!ValidateHandle((HANDLE *) g_HashHand, g_HashLen, (HANDLE) hHash))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
 
    // - If no flag set 
    if(dwFlags)
    {
        // \todo support CRYPT_USERDATA 
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    // - If CPGetHashParam has not been called yet => unfinished state, ok to
   //    eat more 
    if(pHash->finished)
    {
        SetLastError(NTE_BAD_HASH_STATE);
        return FALSE;
    }
    // - Test if key handle has been granted 
    if(!ValidateHandle((HANDLE *) g_KeyHand, g_KeyLen, (HANDLE) hKey))
    {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }
 
    // - Get the specified key value lenth 
//     if(!getKeyValue(pProvCtx, hKey, NULL, &keyValueLenth))
//     {
//         SetLastError(NTE_BAD_KEY);
//         return FALSE;
//     }
    
    // - Allocate memory for the local copy of the key value 
    keyValue = (BYTE *) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,
                                            keyValueLenth);
    if(keyValue == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    
    // - Get the key value 
//     if(!getKeyValue(pProvCtx, hKey, keyValue, &keyValueLenth))
//     {
//         SetLastError(NTE_BAD_KEY);
//         return FALSE;
//     }
    
    // - Feed the key value 
	
    return CPHashData_Internal(hProv, hHash, keyValue, keyValueLenth, 0);
	
    
}


/*
 -  CPSignHash
 -
 *  Purpose:
 *                Create a digital signature from a hash
 *
 *
 *  Parameters:
 *               IN  hProv        -  Handle to the user identifcation
 *               IN  hHash        -  Handle to hash object
 *               IN  dwKeySpec    -  Key pair to that is used to sign with
 *               IN  sDescription -  Description of data to be signed
 *               IN  dwFlags      -  Flags values
 *               OUT pbSignature  -  Pointer to signature data
 *               IN OUT dwHashLen -  Pointer to the len of the signature data
 *
 *  Returns:
 */

BOOL /*WINAPI*/
CPSignHash_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwKeySpec,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags,
    OUT LPBYTE pbSignature,
    IN OUT LPDWORD pcbSigLen)
{
	TSM_RESULT m_result;
	TSM_HKEY hSignKey;
	TSM_HHASH tsmHash;
	PROV_CTX *pProvCtx = NULL;      // Provider context 
    HASH_INFO *pHash = NULL;        // Hash information 
    DWORD     sigLen=0;             // Signature lenth in bytes 
    DWORD   hashLen = 0;            // Hash lenth in Bytes 
    BYTE   *pHashValue = NULL;		// Hash value 
    HCRYPTKEY hKey = -1;			// Handle to the key to use 
    DWORD   hashSizeLen = 4;		// Size of an hash size data 
    KEY_INFO *pKeyInfo = NULL;		// Pointer to the key information structure 
	HASH_INFO *pHashInfo = NULL;
	
    
    // - Local copy of the crypto handle 
    pProvCtx = (PROV_CTX *) hProv;

    // - Local copy of the hash handle 
    pHash = (HASH_INFO *) hHash;

    // - Test if c handle has been granted 
    if(!ValidateHandle(g_ContextHand, g_ContextLen, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    // - Test if hash handle has been granted 
    if(!ValidateHandle((HANDLE *) g_HashHand, g_HashLen, (HANDLE) hHash))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
 
    // - Test if flags has been set 
    if(dwFlags)
    {      
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    // - Select key 
    if((dwKeySpec == AT_SIGNATURE) || (dwKeySpec == AT_KEYEXCHANGE))
    {
//         if(!CPGetUserKey_Internal(hProv, dwKeySpec, &hKey))
//         {
//             SetLastError(NTE_NO_KEY);
//             return FALSE;
//         }
    }

    //  - If hKey is still -1 here, NTE_NO_KEY 
//     if(hKey == -1)
//     {
//         SetLastError(NTE_NO_KEY);
//         return FALSE;
//     }
	
    if (!CPGetUserKey_Internal(hProv, AT_SIGNATURE, &hKey))
    {
		OUTSTRING2("GetUserKey Failed _(SIGNKEY) \n");
		return FALSE;
    }

    //  - Copy cast key handle 
    pKeyInfo = (KEY_INFO *) hKey;
	hSignKey = (TSM_HKEY) pKeyInfo->hKeyInformation;


    // - Finish the hash !
    //  - Get the hash lenth 
    if(!CPGetHashParam_Internal(hProv, hHash, HP_HASHSIZE,(LPBYTE) &hashLen, &hashSizeLen, 0))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }

    //  - Allocate memory for the hash 
    pHashValue = (BYTE *) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,hashLen);
    if(pHashValue == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    
    //  - Get the Hash value 
    if(!CPGetHashParam_Internal(hProv, hHash, HP_HASHVAL, pHashValue, &hashLen, 0))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
    
    // - Test if the call wait for the signature lenth in byte.
	//	pbSignature == NULL
    if(pbSignature == NULL)
    {        
        //  - Fill the lenth of the signature 
       // *pcbSigLen= sigLen; // modify in 2011-7-11 9:28:31
		*pcbSigLen = 1024;
		return FALSE;
    }
    else // - If the call wait for the signature data 
    {
		LPBYTE SignData = NULL;
		m_result = gTspModule.Tspi_Key_LoadKey(hSignKey, hSMK);
		if(TSM_SUCCESS != m_result)
		{
			OUTSTRING1("LoadKey %x\n",m_result);
			return FALSE;
		}

		pHashInfo = (HASH_INFO *)hHash;
		tsmHash = pHashInfo->hHash;
		m_result = gTspModule.Tspi_Hash_Sign(tsmHash, hSignKey, pcbSigLen, &SignData);
		if (TSM_SUCCESS != m_result)
		{
			OUTSTRING1("Sign %x\n",m_result);
			return FALSE;
		}

		memcpy(pbSignature, SignData, *pcbSigLen);
		m_result = gTspModule.Tspi_Key_UnloadKey(hSignKey);
		if (TSM_SUCCESS != m_result)
		{
			OUTSTRING1("UnLoadkey %x\n",m_result);
			return FALSE;
		}
    }

	OUTSTRING2("CPSignHash\n");
    return TRUE;
}


// 
//  CPDestroyHash
// 
//  Purpose:
//                Destroy the hash object
// 
// 
//  Parameters:
//               IN  hProv     -  Handle to the user identifcation
//               IN  hHash     -  Handle to hash object
// 
//  Returns:
BOOL CPDestroyHash_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash)
{
	   PROV_CTX *pProvCtx = NULL;      // Provider context 
	   HASH_INFO *pHash;			// Local hash pointer copy 
	   TSM_HCONTEXT hContext;
	   TSM_RESULT tsmResult;
	   TSM_HHASH tsmHash;
	   
	   // - Local copu of the crypto handle 
	   pProvCtx = (PROV_CTX *) hProv;

	   // - Local copy of the hash handle 
	   pHash = (HASH_INFO *) hHash;
	   
	   // - If c handle is granted 
	   if(!ValidateHandle((HANDLE *) g_ContextHand, g_ContextLen, (HANDLE) hProv))
	   {
		   SetLastError(NTE_BAD_UID);
		   return FALSE;
	   }
	   
	   // - if given handle is not NULL 
	   if(pHash == NULL)
	   {
		   SetLastError(NTE_BAD_HASH);
		   return FALSE;
	   }
	   // - If hhandle is granted 
	   if(!ValidateHandle((HANDLE *) g_HashHand, g_HashLen, (HANDLE) hHash))
	   {
		   SetLastError(NTE_BAD_HASH);
		   return FALSE;
	   }

	   hContext = pProvCtx->hContext;
	   tsmHash = pHash->hHash;
	   tsmResult = gTspModule.Tspi_Context_CloseObject(hContext, tsmHash);
	   if (tsmResult != TSM_SUCCESS)
	   {
		   OUTSTRING2("Close Hash Failed\n");
	   }
	   
	   // - if hash value is not NULL 
	   if(pHash->value != NULL)
	   {
		   //  - Free it 
		   if(!HeapFree(pProvCtx->heap, 0, pHash->value))
		   {
			   SetLastError(NTE_BAD_HASH);
			   return FALSE;
		   }
	   }

	   // - if data is not NULL 
	   if(pHash->data != NULL)
	   {
		   //  - Free it 
		   if(!HeapFree(pProvCtx->heap, 0, pHash->data))
		   {
			   SetLastError(NTE_BAD_HASH);
			   return FALSE;
		   }
	   }
	   
	   // - Revoke handle to the hash object 
	   OUTSTRING2("===hHash:");
	   if(RemoveHandle((HANDLE **) &g_HashHand, &g_HashLen, (HANDLE) hHash))
	   {
		   //  - Free hash structure memory 
		   if(!HeapFree(pProvCtx->heap, 0, pHash))
		   {
			   SetLastError(NTE_BAD_HASH);
			   return FALSE;
		   }
		   return TRUE;
	   }
	   else
	   {
		   SetLastError(NTE_BAD_HASH);
		   return FALSE;
	   }

	OUTSTRING2("CPDestroyHash");
    return TRUE;
}


/*
 -  CPVerifySignature
 -
 *  Purpose:
 *                Used to verify a signature against a hash object
 *
 *
 *  Parameters:
 *               IN  hProv        -  Handle to the user identifcation
 *               IN  hHash        -  Handle to hash object
 *               IN  pbSignture   -  Pointer to signature data
 *               IN  dwSigLen     -  Length of the signature data
 *               IN  hPubKey      -  Handle to the public key for verifying
 *                                   the signature
 *               IN  sDescription -  String describing the signed data
 *               IN  dwFlags      -  Flags values
 *
 *  Returns:
 */

BOOL /*WINAPI*/
CPVerifySignature_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbSignature,
    IN  DWORD cbSigLen,
    IN  HCRYPTKEY hPubKey,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags)
{
	TSM_RESULT m_result;
	TSM_HCONTEXT hContext;
	TSM_HKEY hSignKey;
	TSM_HHASH tsmhash;
	KEY_INFO* pKeyInfo = NULL;
	HASH_INFO* pHashInfo = NULL;
	PROV_CTX* pProv = NULL;
	HCRYPTKEY hKeyinProv;

	if (!ValidateHandle(g_ContextHand, g_ContextLen, (HANDLE) hProv))
	{
		SetLastError(NTE_BAD_UID);
		return FALSE;
	}

	if (!ValidateHandle(g_KeyHand, g_KeyLen, (HANDLE)hPubKey))
	{
		SetLastError(NTE_BAD_KEY);
		return FALSE;
	}

	if (!ValidateHandle(g_HashHand, g_HashLen, (HANDLE)hHash))
	{
		SetLastError(NTE_BAD_HASH);
		return FALSE;
	}

	if (pbSignature == NULL)
	{
		return FALSE;
	}
	
	pKeyInfo = (KEY_INFO*) hPubKey;
	pHashInfo = (HASH_INFO*) hHash;
	pProv = (PROV_CTX*) hProv;

	hContext = pProv->hContext;
	if (!CPGetUserKey_Internal(hProv, AT_SIGNATURE, &hKeyinProv))
	{
		SetLastError(NTE_NO_KEY);
		return FALSE;
	}

	pKeyInfo = (KEY_INFO*)hKeyinProv;
	hSignKey = (TSM_HKEY)pKeyInfo->hKeyInformation;
	tsmhash = pHashInfo->hHash;
	m_result = gTspModule.Tspi_Key_LoadKey(hSignKey, hSMK);
	if (TSM_SUCCESS != m_result)
	{
		OUTSTRING1("LoadKey %x\n",m_result);
	}

	m_result = gTspModule.Tspi_Hash_VerifySignature(tsmhash, hSignKey, (UINT32)cbSigLen, (BYTE*)pbSignature);
	if (TSM_SUCCESS != m_result)
	{
		OUTSTRING1("VerifySign %x\n",m_result);
		return FALSE;
	}

	m_result = gTspModule.Tspi_Key_UnloadKey(hSignKey);
	if (TSM_SUCCESS != m_result)
	{
		OUTSTRING1("UnLoadKey %x\n", m_result);
		return FALSE;
	}

	OUTSTRING2("CPVerifySignature\n");
    return TRUE;
}


/*
 -  CPGenRandom
 -
 *  Purpose:
 *                Used to fill a buffer with random bytes
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the user identifcation
 *               IN  dwLen         -  Number of bytes of random data requested
 *               IN OUT pbBuffer   -  Pointer to the buffer where the random
 *                                    bytes are to be placed
 *
 *  Returns:
 */

BOOL /*WINAPI*/
CPGenRandom_Internal(
    IN  HCRYPTPROV hProv,
    IN  DWORD cbLen,
    OUT LPBYTE pbBuffer)
{
	TSM_HCONTEXT hContext;
	TSM_RESULT m_result;
	TSM_HTCM hTcm;
	PROV_CTX* pPro;

	if (!ValidateHandle(g_ContextHand, g_ContextLen, (HANDLE)hProv))
	{
		SetLastError(NTE_BAD_UID);
		return FALSE;
	}

	pPro = (PROV_CTX*) hProv;
	hContext = pPro->hContext;
	m_result = gTspModule.Tspi_Context_GetTCMObject(hContext, &hTcm);
	if (TSM_SUCCESS != m_result)
	{
		OUTSTRING1("GetTCM %x\n",m_result);
		return FALSE;
	}

	m_result = gTspModule.Tspi_TCM_GetRandom(hTcm, cbLen, &pbBuffer);
	if (TSM_SUCCESS != m_result)
	{
		OUTSTRING1("GetRandom %x\n",m_result);
		return FALSE;
	}
	OUTSTRING2("CPGenRandom\n");
    return TRUE;
}


/*
 -  CPGetUserKey
 -
 *  Purpose:
 *                Gets a handle to a permanent user key
 *
 *
 *  Parameters:
 *               IN  hProv      -  Handle to the user identifcation
 *               IN  dwKeySpec  -  Specification of the key to retrieve
 *               OUT phUserKey  -  Pointer to key handle of retrieved key
 *
 *  Returns:
 */

BOOL /*WINAPI*/
CPGetUserKey_Internal(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwKeySpec,
    OUT HCRYPTKEY *phUserKey)
{
	PROV_CTX *pProvCtx = NULL;      // Provider context 

	// - Local copy of the context handle 
	pProvCtx = (PROV_CTX *) hProv;

	// - Test if the context has been granted 
	if(!ValidateHandle((HANDLE *) g_ContextHand, g_ContextLen, (HANDLE) hProv))
	{
	   SetLastError(NTE_BAD_UID);
	   return FALSE;
	}   

	// - If requested key is not signature key, not implemented 
	if((dwKeySpec != AT_SIGNATURE) && (dwKeySpec != AT_KEYEXCHANGE))
	{
	   SetLastError(NTE_NO_KEY);
	   return FALSE;
	}  

	//  - Fill key handle 
	if (dwKeySpec == AT_SIGNATURE)
	{
	   *phUserKey = (HCRYPTKEY)pProvCtx->hSignKey;
	}
	else if (dwKeySpec == AT_KEYEXCHANGE)
	{
	   *phUserKey = (HCRYPTKEY)pProvCtx->hExchangeKey;
	}
	   
	OUTSTRING2("CPGetUserKey\n");
    return TRUE;
}


/*
 -  CPDuplicateHash
 -
 *  Purpose:
 *                Duplicates the state of a hash and returns a handle to it.
 *                This is an optional entry.  Typically it only occurs in
 *                SChannel related CSPs.
 *
 *  Parameters:
 *               IN      hUID           -  Handle to a CSP
 *               IN      hHash          -  Handle to a hash
 *               IN      pdwReserved    -  Reserved
 *               IN      dwFlags        -  Flags
 *               IN      phHash         -  Handle to the new hash
 *
 *  Returns:
 */

BOOL WINAPI
CPDuplicateHash_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  LPDWORD pdwReserved,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash)
{
    *phHash = (HCRYPTHASH)NULL;  // Replace NULL with your own structure.
	OUTSTRING2("CPDuplicateHash");
    return TRUE;
}


/*
 -  CPDuplicateKey
 -
 *  Purpose:
 *                Duplicates the state of a key and returns a handle to it.
 *                This is an optional entry.  Typically it only occurs in
 *                SChannel related CSPs.
 *
 *  Parameters:
 *               IN      hUID           -  Handle to a CSP
 *               IN      hKey           -  Handle to a key
 *               IN      pdwReserved    -  Reserved
 *               IN      dwFlags        -  Flags
 *               IN      phKey          -  Handle to the new key
 *
 *  Returns:
 */

BOOL WINAPI
CPDuplicateKey_Internal(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  LPDWORD pdwReserved,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
    *phKey = (HCRYPTKEY)NULL;    // Replace NULL with your own structure.
	OUTSTRING2("CPDuplicateKey");
    return TRUE;
}

// \brief Return the wanted handler index in the granted handlers list 
int FindGrantedHandle(HANDLE *grantedHandles, int max_len, HANDLE wantedHandle)
{
	HANDLE *current;    // Current handler index in the handlers list 
	int index;  // Position index in the handlers list 
	BOOL found; // If the handle is found 

	// - Copy the grantedHandles start pointer to a local copy 
	current = grantedHandles;
	index = 0;

	// - If not NULL 
	if(current == NULL)
	{
		return -1;
	}

	 
	// - Not found 
	found = FALSE;
	// - Check each entry until we found a empty one or end of list 
	while(!found && (index <max_len))
	{
		 
		//  - If not the same,next 
		if(*current != wantedHandle)
		{
			current++;
			index++;
		}	
		else	//  - Else found 
		{
			found = TRUE;
		}
	}
	// - If found 
	if (found)
	{
		//  - Return the index position 
		return index;
	}
	else
	{
		//  - Return negative value 
		return -1;
	}
}

// \brief Grants a handler 
BOOL GrantHandle(HANDLE **grantedHandles, int *length, HANDLE handle)
{
    int index, i;  // Position indexes in the handlers list 
    HANDLE *localList; // Local copy of the list 
    HANDLE *localTemp; // Local reciepient copy for the list 
    HANDLE *newList; // Address of the new list 

    // - NULL pointer given, error 
    if((grantedHandles == NULL) || (length == NULL))
    {
        SetLastError(E_INVALIDARG);
        return FALSE;
    }
    
    // - If given list lenth < 0, set to 0 
    if(*length<0)
    {
        *length = 0;
    }

    // - Copy the granted handlers list to the local copy 
    localList = *grantedHandles;
    
    // - Allocate space for the new handle      
    localTemp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                 sizeof(HANDLE) * ((*length)+1));
     
    // - Remember the new list address before changing it 
    newList = localTemp;
    //  - If cannot allocate, error 
    if(localTemp == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        *grantedHandles = localList;
        return FALSE;
    }
    
    //  - Copy old list to new list 
    for(i=0; i<*length; i++)
    {
        *localTemp = *localList;
        localTemp++;
        localList++;
    }
    //  - Index is set to the last position 
    index = *length;
        
    // - If the context index is valid 
    if (index>=0 && index<(*length)+1)
    {
        //  - Fill the new list with the provided context 
        newList[index] = handle;

        //  - Free old list if not NULL 
        if(*grantedHandles != NULL)
        {   
            HeapFree(GetProcessHeap(), 0, *grantedHandles);
        }

        //  - Copy new list address to the grantedHandles pointer 
        *grantedHandles = newList;

        //  - Now the list is 1 more lenth 
        *length=(*length) + 1;

         //  - Return TRUE 
		OUTSTRING1("+( %d )\n", *length);
        return TRUE;
    }
    else
    {
        // - Else, return FALSE 
        return FALSE;
    }
	
}

// \brief Revokes a granted cryptographic handler 
BOOL RemoveHandle(HANDLE **grantedHandles, int *length, HANDLE handle)
{
	int index, i;  // Position indexes in the handlers list 
	HANDLE *localList; // Local copy of the list 
	HANDLE *localTemp; // Local reciepient copy for the list 
	HANDLE *newList; // Local copy of the new list 

	// - NULL pointer given, error 
	if((grantedHandles == NULL) || (length == NULL))
	{
		SetLastError(E_INVALIDARG);
		return FALSE;
	}

	// - Find the revoked handler position index 
	index = FindGrantedHandle(*grantedHandles, *length, handle);

	// - If length is 0, no possible granted handles 
	if (*length <= 0)
	{
		SetLastError(E_INVALIDARG);
		return FALSE;
	}

	// - If index < 0, no such granted handle 
	if (index < 0)
	{
		SetLastError(E_INVALIDARG);
		return FALSE;
	}
	// - If there is more than one, after remove, it will some left 
	if(*length > 1)
	{
		// - Local granted handlers pointer copy 
		localList = *grantedHandles;

		// - Allocate for length handlers if there are still some 
		 
		localTemp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
			sizeof(HANDLE) * (*length)-1);

		// - Remember new list address before using it 
		newList = localTemp;
		 
		// - If cannot allocate, error 
		if(localTemp == NULL)
		{
			SetLastError(NTE_NO_MEMORY);
			*grantedHandles = localList;
			return FALSE;
		}
		// - Walk list and new list for copy left handles 
		for(i=0; i<*length; i++)
		{
			//  - If i different from revoked handler index, copy 
			if(i != index)
			{
				*localTemp = *localList;
				localTemp++;
			}
			localList++;
		}
	}
	// - Else, there will no more left after revoking 
	else
	{		 
		newList = NULL;
	}

	// - Now the list is 1 less length 
	*length=*length - 1;

	// - Free memory used by the old list 
	 
	HeapFree(GetProcessHeap(), 0, *grantedHandles);
	 
	// - Set the granted handlers pointer to the new list address 
	*grantedHandles = newList;
	OUTSTRING1("-( %d )\n", *length);
	return TRUE;
}

BOOL ValidateHandle(HANDLE *grantedHandles, int length, HANDLE handle)
{
	// - If the wanted handle has a position index >=0, it has been granted 
	if(FindGrantedHandle(grantedHandles, length, handle)>=0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

//////////////////////////////////////////////////////////////////////////
// 创建密钥对象
DWORD CreateKeyObj(TSM_HCONTEXT hContext, TSM_HKEY* phKey, TSM_FLAG initFlags)
{
	TSM_RESULT m_result = 0;
	TSM_HPOLICY hPolicy = 0;
	TSM_HKEY hKey = 0;
	
	m_result = gTspModule.Tspi_Context_CreateObject(hContext, TSM_OBJECT_TYPE_KEY, initFlags, &hKey);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	if(initFlags & TSM_KEY_MIGRATABLE)
	{
		//用于密钥迁移的策略对象
		TSM_HPOLICY hMigPolicy = 0;
		m_result = gTspModule.Tspi_Context_CreateObject(hContext, TSM_OBJECT_TYPE_POLICY, TSM_POLICY_MIGRATION, &hMigPolicy);
		if(TSM_SUCCESS != m_result)
		{
			goto func_end;
		}

		m_result = gTspModule.Tspi_Policy_AssignToObject(hMigPolicy, hKey);
		if(TSM_SUCCESS != m_result)
		{
			goto func_end;
		}
		
		//Get Migration Policy Object for the hKey
		m_result = gTspModule.Tspi_GetPolicyObject(hKey, TSS_POLICY_MIGRATION, &hPolicy);
		if(TSM_SUCCESS != m_result)
		{
			goto func_end;
		}

		//Set Secret for the Migration Policy
		m_result = gTspModule.Tspi_Policy_SetSecret(hPolicy, TSM_SECRET_MODE_PLAIN, g_uSMKSecretSize, g_SMKAuth);
		if(TSM_SUCCESS != m_result)
		{
			goto func_end;
		}
	}

	*phKey = hKey;

func_end:
	return m_result;
}

BOOL InitKey(PROV_CTX *pProvCtx, KEY_INFO *pKey, ALG_ID algId)
{
    // - Set the key algId to the given one 
    pKey->algId = algId;
    // - Set the key spec to AT_SIGNATURE 
    pKey->dwKeySpec = AT_SIGNATURE;
    // - blockLen set to unset 
    pKey->blockLen = -1 ;
    // - The total key length unset 
    pKey->length = -1; 
    // - salt length: 1 byte 
    pKey->saltLen = 1;
    // - salt defaut: 0 
    //  - Allocate memory for salt 
    pKey->salt = HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY, sizeof(BYTE));
    if(pKey->salt == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    //  - Set salt to 0 
    *(pKey->salt) = 0;
    //  - Permissions default to 0xFFFFFFFF 
    pKey->permissions = 0xFFFFFFFF;
    // - Initialization  vectors length set to eight 
    pKey->ivLen = 8;
    // - Initialization vectors set to 0 
    //  - Allocate memory for iv 
    pKey->iv = HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,
		sizeof(BYTE)*pKey->ivLen);
    if(pKey->iv == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    //  - Initialization vectors set to sixty four 0s 
    memset(pKey->iv,0,pKey->ivLen*sizeof(BYTE));
    //  - Padding method set ot PKCS5_PADDING 
    pKey->padding = PKCS5_PADDING;
    //  - Mode set to CRYPT_MODE_CBC 
    pKey->mode = CRYPT_MODE_CBC; 
    //  - Mode feedback length set to 8 bits 
    pKey->fLen = 8;
    //  - Effective length unset 
    pKey->effectiveLen = -1;
    //  - dwContainerType specific information to NULL 
    pKey->hKeyInformation = NULL;
    return TRUE;
}

BOOL ClearHashMemory(HCRYPTPROV hProv)
{
	HANDLE * local;
	local = g_HashHand;

	while (g_HashLen > 0)
	{
		if (CPDestroyHash_Internal(hProv, (HCRYPTHASH)*local))
		{
			RemoveHandle((HANDLE**)&g_HashHand, &g_HashLen, *local);
			local = g_HashHand;
		}else
			break;
	}		

	return TRUE ;
}

BOOL ClearKeyMemory(HCRYPTPROV hProv)
{
	HANDLE * local;
	local = g_KeyHand;

	while (g_KeyLen > 0)
	{
		if (CPDestroyKey_Internal(hProv, (HCRYPTKEY)*local))
		{
			RemoveHandle((HANDLE**)&g_KeyHand, &g_KeyLen, *local);
			local = g_KeyHand;
		}else
			break;
	}		
	
	return TRUE ;
}

DWORD LoadMigBlob(MIGKEYBLOB *migblob, BYTE *buff)
{	
	DWORD offset = 0;
	// Enckey length
	memcpy(buff, &migblob->EncKeyLen, sizeof(DWORD));
	offset = sizeof(DWORD);

	LoadBlob(&offset, migblob->EncKeyLen, buff, migblob->pbEncKey);		// EncKey data

	// SMS4Data Length
	memcpy(buff+offset, &migblob->SMS4DataLen, sizeof(DWORD));
	offset += sizeof(DWORD);

	LoadBlob(&offset, migblob->SMS4DataLen, buff, migblob->pbSMS4Data);	//SMS4Data

	memcpy(buff+offset, &migblob->Algid, sizeof(ALG_ID));
	offset +=  sizeof(ALG_ID);

	return offset;
}

DWORD UnLoadMigBlob(MIGKEYBLOB *migblob, BYTE* buff)
{
	DWORD offset = 0;

	memcpy(&migblob->EncKeyLen, buff, sizeof(DWORD));
	offset = sizeof(DWORD);
	
	migblob->pbEncKey = (BYTE*)malloc(migblob->EncKeyLen);
	memset(migblob->pbEncKey, 0, migblob->EncKeyLen);
	UnloadBlob(&offset, migblob->EncKeyLen, buff, migblob->pbEncKey);
	
	memcpy(&migblob->SMS4DataLen, buff+offset, sizeof(DWORD));
	offset += sizeof(DWORD);

	migblob->pbSMS4Data = (BYTE*)malloc(migblob->SMS4DataLen);
	memset(migblob->pbSMS4Data, 0, migblob->SMS4DataLen);
	UnloadBlob(&offset, migblob->SMS4DataLen, buff, migblob->pbSMS4Data);

	memcpy(&migblob->Algid, buff+offset, sizeof(ALG_ID));
	offset +=  sizeof(ALG_ID);

	return offset;
}