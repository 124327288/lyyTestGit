
#include "head.h"
/**/
#undef GETPROCADDRESS
#define GETPROCADDRESS(f)                           \
{                                                   \
    void ** p = (void **)&(m->##f);                 \
    *p = GetProcAddress((HMODULE)m->hModule, #f);   \
    if(NULL == *p)                                  \
    {                                               \
        m->free(m);                                 \
		return FALSE;								\
    }                                               \
}                                                   \

BOOL freeInter(CSP_MOD* m)
{
	if (m == (void*)0)
	{
		return FALSE;
	}
	if (m->hModule != (void* )0)
	{
		FreeLibrary((HMODULE)m->hModule);
	}
	
	m->CPAcquireContext_Internal;
	m->CPCreateHash_Internal;
	
	m->CPDecrypt_Internal;
	m->CPDeriveKey_Internal;
	
	m->CPDestroyHash_Internal;
	m->CPDestroyKey_Internal;
	
	m->CPEncrypt_Internal;
	m->CPExportKey_Internal;
	
	m->CPGenKey_Internal;
	m->CPGenRandom_Internal;
	
	m->CPGetHashParam_Internal;
	m->CPGetKeyParam_Internal;
	
	m->CPGetProvParam_Internal;
	m->CPGetUserKey_Internal;
	
	m->CPHashData_Internal;
	m->CPHashSessionKey_Internal;
	
	m->CPImportKey_Internal;
	m->CPReleaseContext_Internal;
	
	m->CPSetHashParam_Internal;
	m->CPSetKeyParam_Internal;
	
	m->CPSetProvParam_Internal;
	m->CPSignHash_Internal;
	m->CPVerifySignature_Internal;
	
	
	return TRUE;
}

BOOL loadInter(CSP_MOD* m, const char* name)
{

	int len = 0;	
	if (m == NULL || name == 0)
	{	
		return FALSE;
	}
	len = strlen(name);
	if (len == 0 || len >255)
	{	
		return FALSE;
	}
	m->load = loadInter;
	m->free = freeInter;

	memset(m->name, 0, sizeof(m->name));
	memcpy(m->name, name, len);

	m->hModule = LoadLibraryA(name);
	if (m->hModule == NULL)
	{		
		return FALSE;
	}

	GETPROCADDRESS(CPAcquireContext_Internal);
	GETPROCADDRESS(CPReleaseContext_Internal);
 
	GETPROCADDRESS(CPGenKey_Internal);
	GETPROCADDRESS(CPDeriveKey_Internal);
	GETPROCADDRESS(CPDestroyKey_Internal);

	GETPROCADDRESS(CPSetKeyParam_Internal);
	GETPROCADDRESS(CPGetKeyParam_Internal);

	GETPROCADDRESS(CPExportKey_Internal);
	GETPROCADDRESS(CPImportKey_Internal);

	GETPROCADDRESS(CPEncrypt_Internal);
	GETPROCADDRESS(CPDecrypt_Internal);

	GETPROCADDRESS(CPCreateHash_Internal);
	GETPROCADDRESS(CPHashData_Internal);
	GETPROCADDRESS(CPHashSessionKey_Internal);

	GETPROCADDRESS(CPSetHashParam_Internal);
	GETPROCADDRESS(CPGetHashParam_Internal);
	GETPROCADDRESS(CPDestroyHash_Internal);

	GETPROCADDRESS(CPSignHash_Internal);
	GETPROCADDRESS(CPVerifySignature_Internal);

	GETPROCADDRESS(CPGenRandom_Internal);
	GETPROCADDRESS(CPGetUserKey_Internal);

	GETPROCADDRESS(CPSetProvParam_Internal);
	GETPROCADDRESS(CPGetProvParam_Internal);


	return TRUE;
}
#undef GETPROCADDRESS

  /**/
CSP_MOD g_CspMod = {
	(void*)0, loadInter, freeInter
};

