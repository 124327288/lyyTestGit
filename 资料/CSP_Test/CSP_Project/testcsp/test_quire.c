//-------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Example code using CryptAcquireContext.

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define CSP_FLAG_NO_KEY 0x123
#define CSP_ALG_SMS4	0x124

static HCRYPTPROV g_prov = 0;
void MyHandleError(char *s);

void main(void)
{
	//-------------------------------------------------------------------
	// Declare and initialize variables.
	HCRYPTPROV hCryptProv = 1230123;
	BYTE pbData[1024] = {0};       // 1000 will hold the longest 
	BOOL bRet;
	HCRYPTKEY hExKey;
	HCRYPTKEY hSignKey;
	DWORD cbDatalen;
	HCRYPTHASH hHash;

	//-------------------------------------------------------------------
	// Get a handle to a PROV_RSA_FULL provider.
	if(CryptAcquireContext(
		&hCryptProv, 
		NULL, 
		/*NULL*/"JetWay CSP Provider", 
		/*PROV_RSA_FULL*/1, 
		CRYPT_NEWKEYSET)) 
	{
		printf("CryptAcquireContext succeeded.\n");
	}
	else
	{
		printf("********Error***********\n");	
	}
	
	bRet = CryptGenKey(hCryptProv, AT_SIGNATURE, 0, &hSignKey);
 	bRet = CryptGenKey(hCryptProv, AT_KEYEXCHANGE, 0, &hExKey);
	bRet = CryptCreateHash(hCryptProv, CALG_SHA, hExKey, 0, &hHash);
	g_prov = hCryptProv;
	printf("hCryptProv: %x\n",hCryptProv);
	/************************************************************************/
	/*      ENC --- DEC             -ok                                        */
	/************************************************************************/
	{	
	
		DWORD i = 0;
		DWORD cbBufLen = 1024;
		DWORD cbDatalen = 100 ;
		
		memset(pbData, 0, strlen(pbData));
		for (; i< cbDatalen; i++ )
		{
			pbData[i] = (BYTE)i;
		}
		printf("\t************************************\n");
		printf("\tEncrypt and Decrypt data operation \n");
		printf("\t************************************\n");
		bRet = CryptEncrypt( hExKey, hHash, 1, 0, pbData, &cbDatalen, cbBufLen);
		printf("CPEncrypt----- %d\n",bRet);
//////////////////////////////////////////////////////////////////////////
	{
	// 	for (i = 0; i < cbDatalen; i++)
	// 	{
	// 		printf("%02x ", pbData[i]);
	// 	}
	// 	printf("\npcbDatalen: %d\n", cbDatalen);
	}
//////////////////////////////////////////////////////////////////////////
	
		bRet = CryptDecrypt( hExKey, hHash, 1, 0, pbData, &cbDatalen);
		printf("CPDecrypt ----- %x\n",bRet);
//////////////////////////////////////////////////////////////////////////
	{	
	// 	for (i = 0; i < cbDatalen; i++)
	// 	{
	// 		printf("%02x ", pbData[i]);
	// 	}
	// 	printf("\npcbDatalen: %d\n", cbDatalen);
	}
//////////////////////////////////////////////////////////////////////////
	}


// 	/************************************************************************/
// 	/*      import    -----    export                    ok                 */
// 	/************************************************************************/
	{ 	
		HCRYPTHASH newKey;
		HCRYPTKEY hOutKey;
		bRet = CryptGenKey(hCryptProv, AT_KEYEXCHANGE, 0, &hOutKey);
	
		memset(pbData, 0, strlen(pbData));
		printf("\t************************************\n");
		printf("\tImport and Export operation \n");
		printf("\t************************************\n");
		bRet = CryptExportKey(hOutKey, hExKey,SIMPLEBLOB, 0, pbData, &cbDatalen);
		printf("CryptExportKey-----%d\n",bRet);
		
		bRet = CryptImportKey(hCryptProv, pbData, cbDatalen, hExKey, 0, &newKey);
		printf("CPImportKey-----%d\n",bRet);
	}
	
	//-------------------------------------------------------------------
	// Read the name of the CSP.
	//if(CryptReleaseContext(hCryptProv, 0)) 
	if(CryptReleaseContext(hCryptProv, 0)) 
	{
		printf("CryptReleaseContext succeeded. \n");
	}
	else
	{
		MyHandleError("Error during CryptReleaseContext!\n");
	}

} // End of main

//-------------------------------------------------------------------
void MyHandleError(char *s)
{
	DWORD vals;
    printf("An error occurred in running the program.\n");
    printf("%s\n",s);
    printf("Error number 0x%x.\n",GetLastError());
	vals = GetLastError();
	switch (vals)
	{
	case 107L:
		s = "Some CSPs set this error if the CRYPT_DELETEKEYSET flag value is set and another thread or process is using this key container. ";
		break;
	case 87L:
		s = "One of the parameters contains an invalid value. This is most often an invalid pointer. ";
		break;
	case 8L:
		s = "The operating system ran out of memory during the operation. ";
		break;
	case 2L:
		s = "The profile of the user is not loaded and cannot be found. This happens when the application impersonates a user, for example, the IUSR_computer_name account. ";
		break;
	case 0x80090009L:
		s = "The dwFlags parameter has an invalid value. ";
		break;
	case 0x80090016L:
		s = "The key container could not be opened. A common cause of this error is that the key container does not exist. ";
		break;
	case 0x8009001FL:
		s = "The pszContainer or pszProvider parameter is set to an invalid value. ";
		break;
	case 0x80090014L:
		s = "The value of the dwProvType parameter is out of range. All provider types must be from 1 through 999, inclusive. ";
		break;
	case 0x80090006L:
		s = "The provider DLL signature could not be verified. Either the DLL or the digital signature has been tampered with. ";
		break;
	case 0x8009000FL:
		s = "The dwFlags parameter is CRYPT_NEWKEYSET, but the key container already exists. ";
		break;
	case 0x8009001AL:		
		s = "The pszContainer key container was found but is corrupt. ";
		break;
	case 0x80090019L:
		s = "The key container specified by pszContainer does not exist, or the requested provider does not exist. ";
		break;
	case 0x8009000EL:
		s = "The CSP ran out of memory during the operation. ";
		break;
// 	case 0x8009000EL:
// 		s = "( 0x8009000EL ) The CSP ran out of memory during the operation. ";
// 		break;
// 	case 0x8009000EL:
// 		s = "( 0x8009000EL ) The CSP ran out of memory during the operation. ";
// 		break;
// 	case 0x8009000EL:
// 			s = "( 0x8009000EL ) The CSP ran out of memory during the operation. ";
// 		break;
	case 0x8009001EL:
			s = "The provider DLL file does not exist or is not on the current path. ";
			break;
	case 0x80090018L:
		s = "The provider type specified by dwProvType is corrupt. This error can relate to either the user default CSP list or the computer default CSP list. ";
		break;
	case 0x8009001BL:
		s = "The provider type specified by dwProvType does not match the provider type found. Note that this error can only occur when pszProvider specifies an actual CSP name. ";
		break;
	case 0x80090017L:
		s = "No entry exists for the provider type specified by dwProvType. ";
		break;
	case 0x8009001DL:
		s = "The provider DLL file could not be loaded or failed to initialize. ";
		break;
	case 0x8009001CL:
		s = "An error occurred while loading the DLL file image, prior to verifying its signature. ";
		break;
	default:
		break;
	}
	printf("===============================\n");
	printf("%s\n",s);
	printf("===============================\n");
    printf("Program terminating.\n");
    exit(1);
}
