#ifndef LOAD_TDDL_H
#define LOAD_TDDL_H

#ifdef WIN32


#pragma comment (lib, "Kernel32.lib")

#else
#error linux load_tddl
#endif

#include "../jwtsm.h"

#pragma pack(push)
#pragma pack(1)

typedef struct _tddl_module_{
	void * hModule;

    long (* load)(struct _tddl_module_* m, const char* name);
	long (* free)(struct _tddl_module_* m);
	
	char name[256];

	TSM_RESULT (STDCALL* Tddli_Open)();
	
	TSM_RESULT (STDCALL* Tddli_Close)();
	
    TSM_RESULT (STDCALL* Tddli_Cancel)();

	TSM_RESULT
		(STDCALL* Tddli_GetCapability)(
		UINT32 CapArea,
		UINT32 SubCap,
		BYTE* pCapBuf,
		UINT32* pCapBufLen
		);
	
	TSM_RESULT
		(STDCALL* Tddli_SetCapability)(
		UINT32 CapArea,
		UINT32 SubCap,
		BYTE* pSetCapBuf,
		UINT32 SetCapBufLen
		);
	
	TSM_RESULT
		(STDCALL* Tddli_GetStatus)(
		UINT32 ReqStatusType,
		UINT32* pStatus
		);
	
	TSM_RESULT
		(STDCALL* Tddli_TransmitData)(
		BYTE* pTransmitBuf,
		UINT32 TransmitBufLen,
		BYTE* pRececeiveBuf,
		UINT32* pRececeiveBufLen
	);
}TDDL_MODULE;

#pragma pack(pop)

extern TDDL_MODULE gTddlModule;

#endif