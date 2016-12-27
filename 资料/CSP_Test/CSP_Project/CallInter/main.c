#include "head.h"

int main()
{
	HCRYPTPROV hprov;
	BOOL bRet;
	HCRYPTKEY hSignKey;
	HCRYPTKEY hExKey;
	HCRYPTHASH hHash;
	HCRYPTKEY hSMS4Key;
	BYTE *pbData = NULL;
	DWORD cbDatalen = 0;
	pbData = (BYTE *)malloc(1024);
//	g_CspMod.load(&g_CspMod, "c:\\windows\\system32\\InterCsp.dll");
	if (!g_CspMod.load(&g_CspMod, "InterCsp.dll"))
	{
		printf("Load Dll Failed \n");
		return 1;
	}
	
	bRet = g_CspMod.CPAcquireContext_Internal(&hprov, "CSP Install Provider", CRYPT_NEWKEYSET, 0);
//  getchar();
// 	return;

	bRet = g_CspMod.CPGenKey_Internal(hprov, AT_SIGNATURE, 0, &hSignKey);
 	bRet = g_CspMod.CPGenKey_Internal(hprov, AT_KEYEXCHANGE, 0, &hExKey);
 	bRet = g_CspMod.CPGenKey_Internal(hprov, CSP_ALG_SMS4, 0, &hSMS4Key);
	bRet = g_CspMod.CPCreateHash_Internal(hprov, CALG_SHA, hSignKey, 0, &hHash);

	/************************************************************************/
	/*      ENC --- DEC             -ok                                     */
	/************************************************************************/
	{	
	
		DWORD i = 0;
		DWORD cbBufLen = 1024;
		cbDatalen = 200 ;
		
		memset(pbData, 0, 1024);
		for (; i< cbDatalen; i++ )
		{
			pbData[i] = (BYTE)i;
		}
		printf("\t************************************\n");
		printf("\tEncrypt and Decrypt data operation \n");
		printf("\t************************************\n");
		bRet = g_CspMod.CPEncrypt_Internal(hprov, hExKey, hHash, 1, 0, pbData, &cbDatalen, cbBufLen);
		printf("CPEncrypt_Internal----- %d\n",bRet);
		//////////////////////////////////////////////////////////////////////////
		// {	
		// 	for (i = 0; i < cbDatalen; i++)
		// 	{ 
		// 		printf("%02x ", pbData[i]);
		// 	}
		// 	printf("\npcbDatalen: %d\n", cbDatalen);
		// }
		//////////////////////////////////////////////////////////////////////////
	
		bRet = g_CspMod.CPDecrypt_Internal(hprov, hExKey, hHash, 1, 0, pbData, &cbDatalen);
		printf("CPDecrypt_Internal----- %d\n",bRet);
		//////////////////////////////////////////////////////////////////////////
		// {	
		// 	for (i = 0; i < cbDatalen; i++)
		// 	{
		// 		printf("%02x ", pbData[i]);
		// 	}
		// 	printf("\npcbDatalen: %d\n", cbDatalen);
		// }
		//////////////////////////////////////////////////////////////////////////
	}
	
	/************************************************************************/
	/*      import    -----    export                    ok                 */
	/************************************************************************/
	{
		HCRYPTHASH newKey;
		HCRYPTKEY hOutKey;
		bRet = g_CspMod.CPGenKey_Internal(hprov, AT_KEYEXCHANGE, 0, &hOutKey);
		memset(pbData, 0, strlen(pbData));
		printf("\t************************************\n");
		printf("\tImport and Export operation \n");
		printf("\t************************************\n");
		bRet = g_CspMod.CPExportKey_Internal(hprov, hOutKey,hSignKey,  SIMPLEBLOB, 0, pbData, &cbDatalen);
		printf("CPExportKey_Internal-----%d\n",bRet);
		
		bRet = g_CspMod.CPImportKey_Internal(hprov, pbData, cbDatalen, hSignKey, 0, &newKey);
		printf("CPImportKey_Internal-----%d\n",bRet);
	}


	/************************************************************************/
	/*                  HASH                             ok                 */
	/************************************************************************/
	{
		printf("\t************************************\n");
		printf("\t HASH Operation \n");
		printf("\t************************************\n");
	//	pbData = (BYTE*) malloc(100);
		memset(pbData, 0, strlen(pbData));
		memcpy(pbData, "1123sdasd123asd",strlen("1123sdasd123asd") );
		cbDatalen = strlen(pbData);
		bRet = g_CspMod.CPHashData_Internal(hprov, hHash, pbData, cbDatalen, 0);
		cbDatalen = 100;
		bRet = g_CspMod.CPHashSessionKey_Internal(hprov, hHash, hExKey, 0);
		bRet = g_CspMod.CPGetHashParam_Internal(hprov, hHash, HP_HASHVAL, pbData, &cbDatalen, 0);	
		printf("CPGetHashParam_Internal---------%d\n",bRet);
	}

	/************************************************************************/
	/*             Sign      and      VerifySign          ok                */
	/************************************************************************/
	{
		BYTE * pbSignData = NULL;
		DWORD cbSignLen = 32;
		memset(pbData, 0, strlen(pbData));
 		pbSignData = (BYTE *)malloc(1024);
 		memset(pbSignData, 0, strlen(pbSignData));
		printf("\t************************************\n");
		printf("\tSign and VerifySign operation \n");
		printf("\t************************************\n");
		bRet = g_CspMod.CPDestroyHash_Internal(hprov, hHash);
		bRet = g_CspMod.CPCreateHash_Internal(hprov, CALG_SHA, hSignKey, 0, &hHash);
		bRet = g_CspMod.CPHashData_Internal(hprov, hHash, "when the sky is dark.",strlen("when the sky is dark."),0);
		bRet = g_CspMod.CPSignHash_Internal(hprov, hHash, AT_SIGNATURE, NULL, 0, pbSignData, &cbSignLen);
		printf("1111----%d , pbSignData %x\n",bRet, pbSignData);
		bRet = g_CspMod.CPVerifySignature_Internal(hprov, hHash, pbSignData, cbSignLen, hSignKey, NULL, 0);
		printf("2222----%d , pbSignData %x\n",bRet, pbSignData);
	}

	/************************************************************************/
	/*				 GetParam      HASH- Key - PROV                         */
	/************************************************************************/
	{
		BYTE* outdata = NULL;
		DWORD dwOutlen = 32;
		outdata = (BYTE*)malloc(32);
		memset(outdata, 0, strlen(outdata));
		bRet = g_CspMod.CPDestroyHash_Internal(hprov, hHash);
		bRet = g_CspMod.CPCreateHash_Internal(hprov, CALG_SHA, hSignKey, 0, &hHash);
		bRet = g_CspMod.CPHashData_Internal(hprov, hHash, "you have the talent.", strlen("you have the talent."),0);
		bRet = g_CspMod.CPSetHashParam_Internal(hprov, hHash, HP_HASHVAL, pbData, 0);
		bRet = g_CspMod.CPGetHashParam_Internal(hprov, hHash, HP_HASHVAL, outdata, &dwOutlen, 0 );
		printf("1111----%d\n",bRet);
	}
	
	
	bRet = g_CspMod.CPDestroyHash_Internal(hprov, hHash);
	bRet = g_CspMod.CPDestroyKey_Internal(hprov, hSignKey);
	printf("End Now----- %d\n",bRet);
	bRet = g_CspMod.CPReleaseContext_Internal(hprov, 0);
	return 0;
}