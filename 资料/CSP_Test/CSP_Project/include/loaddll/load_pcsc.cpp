#include "stdafx.h"
#include "load_pcsc.h"

#undef GETPROCADDRESS
#define GETPROCADDRESS(f)                           \
{                                                   \
    void ** p = (void **)&(m->##f);                 \
    *p = GetProcAddress((HMODULE)m->hModule, #f);   \
    if(NULL == *p)                                  \
    {                                               \
        m->free(m);                                 \
        return TCSERR(TSM_E_FAIL);                  \
    }                                               \
}                                                   \

long free_pcsc(JW_PCSC* m)
{
    if((void *)0 == m)
    {
        return -1;
    }
    if((void *)0 != m->hModule)
    {
        FreeLibrary((HMODULE)m->hModule);
    }

    // 通用接口
    m->CreateAppObj = NULL;
    m->DeleteAppObj = NULL;

    return 0;
}

long load_pcsc(JW_PCSC* m, const char* name)
{
    int len = 0;
    if((NULL == m) || (0 == name))
    {
        return -1;
    }
    len = strlen(name);
    if((0 == len) || (255 < len))
    {
        return -2;
    }

    m->load = load_pcsc;
    m->free = free_pcsc;

    memset(m->name, 0, sizeof(m->name));
    memcpy(m->name, name, len);

    m->hModule = LoadLibraryA(name);
    if((void *)0 == m->hModule)
    {
        return -3;
    }

    // 通用接口
    GETPROCADDRESS(CreateAppObj);
    GETPROCADDRESS(DeleteAppObj);

    return 0;
}

#undef GETPROCADDRESS

JW_PCSC gJwPcsc = {
    (void *)0, load_pcsc, free_pcsc,
};