#ifndef LOAD_PCSCMETHOD_DLL_H
#define LOAD_PCSCMETHOD_DLL_H

#pragma pack(push, 1)

typedef struct _jw_pcsc_
{
	void * hModule;

    long (* load)(struct _jw_pcsc_* m, const char* name);
	long (* free)(struct _jw_pcsc_* m);
	
	char name[256];
	
	unsigned long
		(__stdcall* CreateAppObj)(
		OUT void** obj,
		IN void* property
		);
	
	unsigned long
		(__stdcall* DeleteAppObj)(
		IN void* obj
		);

}JW_PCSC;

#pragma pack(pop)

extern JW_PCSC gJwPcsc;

#endif