
#include <WINDOWS.H>
#include <wincrypt.h>
#include <STDIO.H>

#include <tchar.h>
#include "cspdk.h"
#include "load_inter.h"

#define CSP_FLAG_NO_KEY 0x123
#define CSP_ALG_SMS4	0x124