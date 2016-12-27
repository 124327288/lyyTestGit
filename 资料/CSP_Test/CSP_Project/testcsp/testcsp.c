/////////////////////////////////////////////////////////////////////////////
//  FILE          : param.c                                                //
//  DESCRIPTION   : Test to verify parameters of crypto API                //
//  USAGE         : Must have the provider defprov.dll and file "sign"     //
//                  which is the signature in the path.                    //
//                  Placing any charactor on the command line will create  //
//                  debug output from the program.                         //
//  AUTHOR        :                                                        //
//  HISTORY       :                                                        //
//      Dec 22 1994 larrys  New                                            //
//      Jan  5 1995 larrys  Added CryptGetLastError                        //
//      Mar  8 1995 larrys  Removed CryptGetLastError                      //
//      Mar 21 1995 larrys  Removed Certificate APIs                       //
//      Apr  7 1995 larrys  Update to new spec                             //
//                                                                         //
//  Copyright (C) 1993 Microsoft Corporation   All Rights Reserved         //
/////////////////////////////////////////////////////////////////////////////
#pragma comment(lib,"Advapi32")
#undef UNICODE					// ## Not Yet
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <windows.h>
#include <wincrypt.h>
/*#include "wincrypt.h"*/


#define UTILITY_BUF_SIZE	1000

#define PARAMETER1 10
#define PARAMETER2 9
#define PARAMETER3 8
#define PARAMETER4 7
#define PARAMETER5 6
#define PARAMETER6 5
#define PARAMETER7 4
#define PARAMETER8 3
#define PARAMETER9 2
#define PARAMETER10 1

// #define CRYPT_FAILED            FALSE
// #define CRYPT_SUCCEED           TRUE
// 
// #define RCRYPT_SUCCEEDED(rt)     ((rt) == CRYPT_SUCCEED)
// #define RCRYPT_FAILED(rt)        ((rt) == CRYPT_FAILED)
// typedef unsigned long HCRYPTPROV;
// typedef unsigned long HCRYPTKEY;
// typedef unsigned long HCRYPTHASH;
// typedef unsigned int ALG_ID;
// typedef unsigned long HCRYPTHASH;

char* GetLastErrorString();
#define  UserName "mtc"
int __cdecl main(int cArg, char *rgszArg[])
{
//    HANDLE         hEvent;
    HCRYPTPROV     hProv;
    HCRYPTKEY      hKey;
    HCRYPTKEY      hKey2;
    HCRYPTPROV     hHash;
    HCRYPTKEY      hPub;
    HCRYPTKEY      hUser;
    //CHAR           pszMyName[64];
//    HFILE          hFile;
//    OFSTRUCT       ImageInfoBuf;

    printf("Calling CryptAcquireContext - ");
// 	if (RCRYPT_FAILED(CryptAcquireContext(&hProv, pszMyName,
//                           /*"Gemplus GemSAFE Card CSP v1.0"*/NULL, /*900*/PROV_RSA_SIG, cArg)))
// 	{
//         printf("CryptAcquireConext returned error %x\n", GetLastError());
//         printf("FAILED\n");
// 		return(TRUE);
// 	}
// 	else
// 	    printf("SUCCEED\n");

	// provider context
//	 const char *UserName = "MyKeyContainer";
	// to be used
	//-------------------------------------------------------------------
	// Attempt to acquire a context and a key
	// container. The context will use the default CSP
	// for the RSA_FULL provider type. DwFlags is set to zero
	// to attempt to open an existing key container.
	
	if(CryptAcquireContext(
		&hProv,               // handle to the CSP
		/*UserName*/NULL,                  // container name 
		/*NULL*/"CSP Released",                      // use the default provider
		PROV_RSA_FULL,             // provider type
		0))                        // flag values
	{
		printf("A cryptographic context with the %s key container \n", 
			UserName);
		printf("has been acquired.\n\n");
	}
	else
	{ 
		//-------------------------------------------------------------------
		// An error occurred in acquiring the context. This could mean
		// that the key container requested does not exist. In this case,
		// the function can be called again to attempt to create a new key 
		// container. Error codes are defined in Winerror.h.
		if (GetLastError() == NTE_BAD_KEYSET)
		{		
			if(CryptAcquireContext(
				&hProv, 
				UserName, 
				NULL, 
				PROV_RSA_FULL, 
				CRYPT_NEWKEYSET)) 
			{
				printf("A new key container has been created.\n");
			}
			else
			{
				printf("Could not create a new key container.\n");
				exit(1);
			}
		}
			else
			{
				printf("error:%s(%x)\n",GetLastErrorString(),GetLastError());
				exit(1);
			}
			
	} // End of else.






    printf("Calling CryptGenKey - ");
	if (RCRYPT_FAILED(CryptGenKey(hProv,
				      (int) PARAMETER2,
				      PARAMETER3,
				      &hKey)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptDestroyKey - ");
	if (RCRYPT_FAILED(CryptDestroyKey(hKey)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

//
//	Create key for other calls to functions
//
    printf("Calling CryptGenKey - ");
	if (RCRYPT_FAILED(CryptGenKey(hProv,
				      (int) PARAMETER2,
				      PARAMETER3,
				      &hKey)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
	        printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptSetKeyParam - ");
	if (RCRYPT_FAILED(CryptSetKeyParam(hKey,
					   PARAMETER2,
					   (BYTE *) PARAMETER3,
					   PARAMETER4)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptGetKeyParam - ");
	if (RCRYPT_FAILED(CryptGetKeyParam(hKey,
					   PARAMETER2,
					   (BYTE *) PARAMETER3,
					   (DWORD *) PARAMETER4,
					   PARAMETER5)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptSetProvParam - ");
	if (RCRYPT_FAILED(CryptSetProvParam(hProv,
					    PARAMETER2,
					    (BYTE *) PARAMETER3,
					    PARAMETER4)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptGetProvParam - ");
	if (RCRYPT_FAILED(CryptGetProvParam(hProv,
					    PARAMETER2,
					    (BYTE *) PARAMETER3,
					    (DWORD *) PARAMETER4,
					    PARAMETER5)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }


    printf("Calling CryptGenRandom - ");
	if (RCRYPT_FAILED(CryptGenRandom(hProv,
					 PARAMETER2,
					 (BYTE *) PARAMETER3)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptGetUserKey - ");
    if (RCRYPT_FAILED(CryptGetUserKey(hProv,
				  PARAMETER2,
				  &hUser)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptGenKey - ");
	if (RCRYPT_FAILED(CryptGenKey(hProv,
				      (int) PARAMETER2,
				      PARAMETER3,
				      &hPub)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptExportKey - ");
	if (RCRYPT_FAILED(CryptExportKey(hKey,
					 hPub,
				         PARAMETER3,
					 PARAMETER4,
					 (BYTE *) PARAMETER5,
					 (DWORD *) PARAMETER6)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptImportKey - ");
	if (RCRYPT_FAILED(CryptImportKey(hProv,
					 (BYTE *) PARAMETER2,
					 PARAMETER3,
					 hUser,
					 PARAMETER5,
					 &hKey2)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptCreateHash - ");
	if (RCRYPT_FAILED(CryptCreateHash(hProv,
					  (int) PARAMETER2,
					  hKey,
					  PARAMETER4,
					  &hHash)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptSetHashParam - ");
	if (RCRYPT_FAILED(CryptSetHashParam(hHash,
					    PARAMETER2,
					    (BYTE *) PARAMETER3,
					    PARAMETER4)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptGetHashParam - ");
	if (RCRYPT_FAILED(CryptGetHashParam(hHash,
					    PARAMETER2,
					    (BYTE *) PARAMETER3,
					    (DWORD *) PARAMETER4,
					    PARAMETER5)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptHashData - ");
	if (RCRYPT_FAILED(CryptHashData(hHash,
				        (BYTE *) PARAMETER2,
					PARAMETER3,
					PARAMETER4)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptHashSessionKey - ");
	if (RCRYPT_FAILED(CryptHashSessionKey(hHash, hKey, PARAMETER3)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptEncrypt - ");
	if (RCRYPT_FAILED(CryptEncrypt(hKey,
				       hHash,
				       (BOOL) PARAMETER3,
				       PARAMETER4,
				       (BYTE *) PARAMETER5,
				       (DWORD *) PARAMETER6,
				       PARAMETER7)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptDecrypt - ");
	if (RCRYPT_FAILED(CryptDecrypt(hKey,
				       hHash,
				       (BOOL) PARAMETER3,
				       PARAMETER4,
				       (BYTE *) PARAMETER5,
				       (DWORD *) PARAMETER6)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptDeriveKey - ");
	if (RCRYPT_FAILED(CryptDeriveKey(hProv,
					 (int) PARAMETER2,
					 hHash,
					 PARAMETER4,
					 &hKey2)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptSignHash - ");
	if (RCRYPT_FAILED(CryptSignHash(hHash,
					PARAMETER2,
					"string",
					PARAMETER4,
					(BYTE *) PARAMETER5,
					(DWORD *) PARAMETER6)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptVerifySignature - ");
	if (RCRYPT_FAILED(CryptVerifySignature(hHash,
					       (BYTE *) PARAMETER2,
					       PARAMETER3,
					       hPub,
					       "string",
					       PARAMETER6)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptDestroyHash - ");
	if (RCRYPT_FAILED(CryptDestroyHash(hHash)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

	if (RCRYPT_FAILED(CryptReleaseContext(hProv, PARAMETER2)))
	{
        printf("CryptReleaseContext returned error %d\n", GetLastError());
        printf("FAILED\n");
	}
	else
	{
        printf("SUCCEED\n");
    }

	return(0);
}

char* GetLastErrorString()
{
	DWORD values = GetLastError();
	char *s = NULL;
	switch (values)
	{
	case 170L:
		s = "ERROR_BUSY";
		break;
	case 0x80090017L :
		s = "NTE_PROV_TYPE_NOT_DEF";
		break;
	case 0x80090006L :
		s = "NTE_BAD_SIGNATURE";
		break;
	default:
		break;
	}
	return s;
}