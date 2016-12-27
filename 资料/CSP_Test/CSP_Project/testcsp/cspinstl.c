#undef UNICODE					// ## Not Yet
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <windows.h>
#include <wincrypt.h>

#define CSP_PROV	"CSP Install Provider"

CHAR szprovider[] = "SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\CSP Install Provider";

//CHAR szdef[] = "SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\A Install Test Provider";

//CHAR szcsp[] = "SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\CSP Install Provider";

CHAR sztype[] = "SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider Types\\Type 900";

CHAR szImagePath[] = "csp.dll";

DWORD     	    dwIgn;
HKEY      	    hKey;
DWORD           err;
DWORD           dwValue;
HANDLE          hFileSig;
DWORD     	    NumBytesRead;
DWORD           lpdwFileSizeHigh;
LPVOID          lpvAddress;    
DWORD           NumBytes;

int __cdecl main(int cArg, char *rgszArg[])
{
    //
    // Just to open scp.dll signature file.  This file was created by
    // sign.exe.
    //
    if ((hFileSig = CreateFile("csp.sig",
                               GENERIC_READ, 0, NULL,
			       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
			       0)) != INVALID_HANDLE_VALUE)
    {
        if ((NumBytes = GetFileSize((HANDLE) hFileSig, &lpdwFileSizeHigh)) ==
                                    0xffffffff)
        {
            printf("Install failed: Getting size of file cspsign: %x\n",
                    GetLastError());
            CloseHandle(hFileSig);
            return(FALSE);
        }

        if ((lpvAddress = VirtualAlloc(NULL, NumBytes, MEM_RESERVE |
		                                       MEM_COMMIT,
                                       PAGE_READWRITE)) == NULL)
        {
            CloseHandle(hFileSig);
            printf("Install failed: Alloc to read uisign: %x\n",
                    GetLastError());
            return(FALSE);
        }

        if (!ReadFile((HANDLE) hFileSig, lpvAddress, NumBytes,
		      &NumBytesRead, 0))
        {

            CloseHandle(hFileSig);
            printf("Install failed: Reading uisign: %x\n",
                    GetLastError());
            VirtualFree(lpvAddress, 0, MEM_RELEASE);
            return(FALSE);
        }

        CloseHandle(hFileSig);

        if (NumBytesRead != NumBytes)
        {
            printf("Install failed: Bytes read doesn't match file size\n");
            return(FALSE);
        }

	//
	// Create or open in local machine for provider:
	//
        if ((err = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
                                  (const char *) szprovider,
                                  0L, "", REG_OPTION_NON_VOLATILE,
                                  KEY_ALL_ACCESS, NULL, &hKey,
                                  &dwIgn)) != ERROR_SUCCESS)
        {
            printf("Install failed: RegCreateKeyEx\n");
        }

	//
	// Set Image path to: scp.dll
	//
        if ((err = RegSetValueEx(hKey, "Image Path", 0L, REG_SZ, szImagePath,
	                         strlen(szImagePath)+1)) != ERROR_SUCCESS)
        {
            printf("Install failed: Setting Image Path value\n");
            return(FALSE);
        }

	//
	// Set Type to: Type 900
	//
        dwValue = 1;
        if ((err = RegSetValueEx(hKey, "Type", 0L, REG_DWORD,
                                 (LPTSTR) &dwValue,
                                 sizeof(DWORD))) != ERROR_SUCCESS)
        {
            printf("Install failed: Setting Type value: %x\n", err);
            return(FALSE);
        }

	//
	// Place signature
	//
        if ((err = RegSetValueEx(hKey, "Signature", 0L, REG_BINARY, 
                                 (LPTSTR) lpvAddress,
                                 NumBytes)) != ERROR_SUCCESS)
        {
            printf("Install failed: Setting Signature value for cspsign: %x\n", err);
            return(FALSE);
        }

        RegCloseKey(hKey);
        VirtualFree(lpvAddress, 0, MEM_RELEASE);

	//
	// Create or open in local machine for provider type:
	// Type 900
	//
        if ((err = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
                                  (const char *) sztype,
                                  0L, "", REG_OPTION_NON_VOLATILE,
                                  KEY_ALL_ACCESS, NULL, &hKey,
                                  &dwIgn)) != ERROR_SUCCESS)
        {
            printf("Install failed: Registry entry existed: %x\n", err);
        }

        if ((err = RegSetValueEx(hKey, "Name", 0L, REG_SZ, CSP_PROV,
                                 strlen(CSP_PROV)+1)) != ERROR_SUCCESS)
        {
            printf("Install failed: Setting Default type: %x\n", err);
            return(FALSE);
        }

	printf("Installed: %s\n", szImagePath);

    }

    return(FALSE);

}
