
//#include "cspdk.h"
#include "../include/loaddll/load_tsp.h"
#include "resource.h"

#define MAX_AUTHDATA_SIZE 32

// global variable
TSM_HKEY hSMK;					// smk handle
BOOL	bOwnerAuth = FALSE;		// declare whether owner exists
UINT32	g_uTcmSecretSize = 32;	// tcm auth data size
UINT32	g_uSMKSecretSize = 32;	// smk auth data size
BYTE	g_TcmAuth[32] = {0};	// TCM auth data
BYTE	g_SMKAuth[32] = {0};	// SMK auth data

int		g_iStrItemSize = 0;							// data size of edit control
char	g_szItemData[MAX_AUTHDATA_SIZE+10] = {0};	// receives data from edit control

BOOL	g_SetSMKAuth = FALSE;	// declare whether set smk auth 

extern HINSTANCE g_instance;	// instance handle
//////////////////////////////////////////////////////////////////////////
// windows callback fuction
//////////////////////////////////////////////////////////////////////////
BOOL CALLBACK DeleteItemProc(HWND hwndDlg, 
                             UINT message, 
                             WPARAM wParam, 
                             LPARAM lParam) 
{
    switch (message) 
    {
	case WM_INITDIALOG:
		if (g_SetSMKAuth)
		{
			SetDlgItemText(hwndDlg,IDC_STATIC_PIN,"请输入SMK授权数据:");
		}
		else
		{
			SetDlgItemText(hwndDlg,IDC_STATIC_PIN,"请输入TCM授权数据:");
		}
		return TRUE;
		break;
	case WM_COMMAND: 
		switch (LOWORD(wParam)) 
		{
		case IDOK: 
			memset(g_szItemData,0,MAX_AUTHDATA_SIZE);
			GetDlgItemText(hwndDlg, IDC_PIN, g_szItemData, MAX_AUTHDATA_SIZE);
			g_iStrItemSize = strlen(g_szItemData);
			if (g_iStrItemSize>0)
			{
				// get smk auth data
				if (g_SetSMKAuth)
				{
					memset(g_SMKAuth,0,32);
					memcpy(g_SMKAuth,g_szItemData,g_iStrItemSize);
					g_uSMKSecretSize = g_iStrItemSize;
				}
				else	// get tcm auth data
				{
					memset(g_TcmAuth,0,32);
					memcpy(g_TcmAuth,g_szItemData,g_iStrItemSize);
					g_uTcmSecretSize = g_iStrItemSize;
				}

				//MessageBox(NULL,g_szItemData,"GetStringData",MB_OK);
				EndDialog(hwndDlg, wParam);
				return TRUE; 
			}
			break;
		case IDCANCEL: 
			//EndDialog(hwndDlg, wParam); 
			//return TRUE; 
			break;
		} 
    } 
    return FALSE; 
} 

// input auth data 
void PopDlg_InputAuth(BOOL bSetSMK)
{
	g_SetSMKAuth = bSetSMK;
	DialogBox(g_instance, MAKEINTRESOURCE(IDD_PIN), NULL, (DLGPROC)DeleteItemProc);
}


//////////////////////////////////////////////////////////////////////////
// tsm module fuction
//////////////////////////////////////////////////////////////////////////
TSM_RESULT initsp(TSM_HCONTEXT *hContext)
{
	TSM_RESULT m_result;
	
	//printf("\t===initsp:\n");
	m_result = gTspModule.Tspi_Context_Create(hContext);
 	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}
	
	m_result = gTspModule.Tspi_Context_Connect(*hContext, NULL);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}
	return TSM_SUCCESS;
func_end:
	return m_result;
}


TSM_RESULT initcm(TSM_HCONTEXT hContext)
{
	TSM_RESULT		m_result;
	TSM_HTCM		hTCM;
	TSM_FLAG		objectType	= 0;
    TSM_FLAG		initFlags	= 0;
	UINT32 TestResultLength;
	BYTE *prgbTestResult = NULL;
	TSM_VALIDATION  ValidationData = {0};
	TSM_HPOLICY hSmkPolicy;
	TSM_FLAG secretMode;
	TSM_HKEY hEndorsementPubKey;
	BYTE			rgbEkResetData[TCM_SCH_256_HASH_LEN] = {0};
	TSM_HPOLICY hTcmPolicy;
	TSM_HKEY hKeyEK;

	//printf("\t===initcm:\n");
	m_result = gTspModule.Tspi_Context_GetTCMObject(hContext, &hTCM);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	objectType = TSM_OBJECT_TYPE_KEY;
	initFlags = TSM_KEY_VOLATILE			// EK启动时必须加载
				| TSM_KEY_NO_AUTHORIZATION	// EK使用时无需授权验证
				| TSM_SM2KEY_TYPE_SIGNING   // EK 只能用于签名
				| TSM_KEY_SIZE_256			// 目前只支持256bit
				| TSM_KEY_NOT_MIGRATABLE	// EK 不可迁移
				| TSM_KEY_TSP_SMK			// 有疑问? 创建EK使用什么模板?
				;

	m_result = gTspModule.Tspi_TCM_SelfTestFull(hTCM);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	m_result = gTspModule.Tspi_TCM_GetTestResult(hTCM, &TestResultLength,&prgbTestResult);	
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	//PhysicalPresece--0x40
	m_result = gTspModule.Tspi_TCM_SetStatus(hTCM,TSM_TCMSTATUS_PHYSPRES_HWENABLE,TSM_TCMSTATUS_PHYSPRES_HWENABLE);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}
	
	//PhysicalPresece--0x20
	m_result = gTspModule.Tspi_TCM_SetStatus(hTCM,TSM_TCMSTATUS_PHYSPRES_CMDENABLE,TSM_TCMSTATUS_PHYSPRES_CMDENABLE);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}
	
	//PhysicalPresece--0x08
	m_result = gTspModule.Tspi_TCM_SetStatus(hTCM,TSM_TCMSTATUS_PHYSPRESENCE,TCM_PHYSICAL_PRESENCE_PRESENT);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}
	
	//PhysicalSetDeactived
	m_result = gTspModule.Tspi_TCM_SetStatus(hTCM,TSM_TCMSTATUS_DEACTIVATED,FALSE);
 	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	//SetOwnerInstall
	m_result = gTspModule. Tspi_TCM_SetStatus (hTCM,TSM_TCMSTATUS_SETOWNERINSTALL,TRUE);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	m_result = gTspModule.Tspi_Context_CreateObject(hContext, objectType, initFlags, &hKeyEK);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end ;
	}
	
	ValidationData.ulExternalDataLength = TCM_SCH_256_HASH_LEN;
	ValidationData.rgbExternalData = (BYTE*)malloc(TCM_SCH_256_HASH_LEN);
	{
		int i;
		for(i = 0; i < TCM_SCH_256_HASH_LEN; i++)
		{
			ValidationData.rgbExternalData[i] = i;
			rgbEkResetData[i] = i;
		}
	}

	m_result = gTspModule.Tspi_TCM_CreateEndorsementKey(hTCM, hKeyEK, &ValidationData); 
	if((m_result & 0x000000FF) == TSM_E_KEY_ALREADY_REGISTERED)
	{
		//
	}
	else if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	m_result = gTspModule.Tspi_GetPolicyObject(hTCM, TSM_POLICY_USAGE, &hTcmPolicy);
 	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	PopDlg_InputAuth(FALSE);
	secretMode = TSM_SECRET_MODE_PLAIN;
	m_result = gTspModule.Tspi_Policy_SetSecret(hTcmPolicy, secretMode, g_uTcmSecretSize, g_TcmAuth);
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}
	
	m_result = gTspModule.Tspi_TCM_GetPubEndorsementKey(hTCM, (TSM_BOOL)bOwnerAuth, &ValidationData, &hEndorsementPubKey);
 	if((m_result & 0x000000FF) == TSM_E_KEY_ALREADY_REGISTERED)
	{
		bOwnerAuth =TRUE;
		m_result = gTspModule.Tspi_TCM_GetPubEndorsementKey(hTCM, (TSM_BOOL)bOwnerAuth, &ValidationData, &hEndorsementPubKey); 
		if(TSM_SUCCESS != m_result)
		{
			goto func_end;
		}
	}
	else if ((m_result & 0x000000FF) == 0x00000001)
	{
		bOwnerAuth =TRUE;
		m_result = gTspModule.Tspi_TCM_GetPubEndorsementKey(hTCM, FALSE, &ValidationData, &hEndorsementPubKey); 
		if(TSM_SUCCESS != m_result)
		{
			goto func_end;
		}
	}
	else if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	// create the smk key
	objectType = TSM_OBJECT_TYPE_KEY;
	initFlags =	TSM_KEY_AUTHORIZATION	// SMK使用时无需授权验证
				| TSM_SMS4KEY_TYPE_STORAGE  // SMK 只能用于存储
				| TSM_KEY_SIZE_128			// 目前只支持128bit
				| TSM_KEY_NOT_MIGRATABLE	// SMK 不可迁移
				| TSM_KEY_TSP_SMK
				;
	m_result = gTspModule.Tspi_Context_CreateObject(hContext, objectType, initFlags, &hSMK); 
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}
	
	m_result = gTspModule.Tspi_GetPolicyObject(hSMK, TSS_POLICY_USAGE, &hSmkPolicy);	
	if(TSM_SUCCESS != m_result)	
	{
		goto func_end;
	}

	PopDlg_InputAuth(TRUE);
	secretMode = TSM_SECRET_MODE_PLAIN;
	m_result = gTspModule.Tspi_Policy_SetSecret(hSmkPolicy, secretMode, g_uSMKSecretSize, g_SMKAuth); 
	if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}
	
	// 	m_result = gTspModule.Tspi_TCM_ClearOwner(hTCM,TRUE);
	// 	if (m_result != TSM_SUCCESS)
	// 	{
	// 		m_result = gTspModule.Tspi_TCM_ClearOwner(hTCM,FALSE);
	// 	}
	
	m_result = gTspModule.Tspi_TCM_TakeOwnership(hTCM, hSMK, hEndorsementPubKey); 
	if((m_result & 0x000000FF) == TSM_E_TCM_UNSUPPORTED_FEATURE)
	{
		//
	}
	else if(TSM_SUCCESS != m_result)
	{
		goto func_end;
	}

	return TSM_SUCCESS;
func_end:
	return m_result;
}

void
LoadBlob(DWORD *offset, DWORD size, BYTE *Blob, BYTE *Section)
{
	if (size == 0)
		return;
	
	if (Blob)
		memcpy(&Blob[*offset], Section, size);
	(*offset) += size;
}

void
UnloadBlob(DWORD *offset, DWORD size, BYTE *Blob, BYTE *Section)
{
	if (size == 0)
		return;
	
	if (Section)
		memcpy(Section, &Blob[*offset], size);
	(*offset) +=  size;
}



