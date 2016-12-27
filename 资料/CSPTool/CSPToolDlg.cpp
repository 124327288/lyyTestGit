// CSPToolDlg.cpp : implementation file
//

#include "stdafx.h"
#include "CSPTool.h"
#include "CSPToolDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CCSPToolDlg dialog

CCSPToolDlg::CCSPToolDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CCSPToolDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CCSPToolDlg)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CCSPToolDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CCSPToolDlg)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CCSPToolDlg, CDialog)
	//{{AFX_MSG_MAP(CCSPToolDlg)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, OnButton1)
	ON_NOTIFY(NM_CLICK, IDC_CSP_LIST, OnClickCspList)
	ON_BN_CLICKED(IDC_BUTTON_CERT, OnButtonCert)
	ON_BN_CLICKED(IDC_BUTTON_VIREFY, OnButtonVirefy)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CCSPToolDlg message handlers

BOOL CCSPToolDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon


	CListCtrl *ListCsp =  (CListCtrl*)GetDlgItem(IDC_CSP_LIST);
	ListCsp->InsertColumn(1, "    CSP名", LVCFMT_LEFT, 300, 55);
	
	EnumCSP(*ListCsp);

	ListCsp =  (CListCtrl*)GetDlgItem(IDC_CONT_LIST);
	ListCsp->InsertColumn(1, "  容器名", LVCFMT_LEFT, 250); //KEYSPEC

	ListCsp->InsertColumn(2, "KeySpec", LVCFMT_LEFT, 80); //KEYSPEC
	ListCsp->InsertColumn(3, "Param", LVCFMT_LEFT, 50); //KEYSPEC

	//LVCOLUMN x;
	

//	ListCsp->SetColumn(2, );
//	ListCsp->InsertColumn(1, "  容器名", LVCFMT_LEFT, 100);

	// TODO: Add extra initialization here
	
	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CCSPToolDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CCSPToolDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}




void CCSPToolDlg::OnButton1() 
{
	((CListCtrl*)GetDlgItem(IDC_CONT_LIST))->DeleteAllItems();
	EnumCSP(*(CListCtrl*)GetDlgItem(IDC_CSP_LIST));
	
}

void CCSPToolDlg::EnumCSP(CListCtrl &List)
{
	DWORD num = 1;
	// 这里 hDevProv 为传出参数
	HCRYPTPROV hDevprov = NULL;//(HCRYPTPROV)pDeviceList[0].hDevice;
	
    DWORD       cbName = 0;
    DWORD       dwType = 0;
    DWORD       dwIndex = 0;
    CHAR        szProvider[MAX_PATH] = { 0 }; 
	ULONG     uResult = NTE_NOT_FOUND;

	
	List.DeleteAllItems();

	

	BOOL bRet = FALSE;
	while(1)
	{
		char szSignContainer[128] = { 0 };
		
		cbName = sizeof(szProvider);
		
		bRet = CryptEnumProviders(
			dwIndex++,
			NULL,
			0,
			&dwType,
			szProvider,
			&cbName
			);
		
		if ( !bRet )
		{
			break;//都没有匹配到
		}

		if ( !strnicmp(szProvider, "Microsoft", 4) )
		{
			List.InsertItem(List.GetItemCount(), szProvider, 0);
		}
		else
		{
			List.InsertItem(0, szProvider, 0);
		}				
	} 

}


int CSP_ExportCert(const char* szContainer, const char* szProvider, 
				   unsigned long dwKeyUsage, unsigned long uKeyParam,
				   unsigned char* cert, int certbufflen)
{
	HCRYPTPROV hProv = 0;
	HCRYPTKEY hUserKey; 
	
	DWORD dwFlag = 0; // | CRYPT_SILENT;
	

	
	if(!CryptAcquireContext(&hProv, szContainer, szProvider, PROV_RSA_FULL, dwFlag))
	{
		return -1;
	}
	
	if(!CryptGetUserKey(hProv, dwKeyUsage, &hUserKey))
	{
		CryptReleaseContext(hProv,0);
		return -2;
	}
	
	if(!CryptGetKeyParam(hUserKey, uKeyParam, cert, (LPDWORD)&certbufflen, 0))
	{
		CryptDestroyKey(hUserKey);
		CryptReleaseContext(hProv,0);
		return -3;
	}
	
	CryptDestroyKey(hUserKey);
	CryptReleaseContext(hProv,0);
	
	return certbufflen;
}

void CCSPToolDlg::EnumContainer( const char* szProvider, CListCtrl &List)
{
	HCRYPTPROV hDevprov = NULL;
	ULONG  dwGetProvParamFlag = CRYPT_FIRST;
	BOOL   bResult = FALSE;

	static char _szProvider[MAX_PATH] = { 0 };

	List.DeleteAllItems();

	strcpy(_szProvider, szProvider);

	char * p = (char*)3289429;
	
	DWORD error  = 0;
				

	if ( !CryptAcquireContext(&hDevprov, NULL, szProvider, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) ) 
	{		
		DWORD error = GetLastError();
		if ( NTE_BAD_SIGNATURE == error )
		{
			// The provider(CSP) DLL signature could not be verified. Either the DLL or the digital signature has been tampered with.

			MessageBoxA("\n以下是微软官方文档提示信息：\n\n  The provider(CSP) DLL signature could not be verified. Either the\t \n  DLL or the digital signature has been tampered with\t\t \n\n",
				"CSP服务提供程序（DLL）签名无效！ 请咨询您的CSP服务提供商");

		}
		return ;
	}
	do
	{
		BYTE pbData[1024] = { 0 };
		DWORD dwDataLen = sizeof(pbData);
		
		HCRYPTPROV hSubDev = NULL;
		
		if ( !CryptGetProvParam(hDevprov, PP_ENUMCONTAINERS, pbData, &dwDataLen, dwGetProvParamFlag) )
		{
			error = GetLastError();
			break;
		}
		
		
		dwGetProvParamFlag = 0;
		
		int count = List.GetItemCount();
		List.InsertItem(count, (char*)pbData, 0);
		List.SetItemData(count, (ULONG_PTR)_szProvider);



		char szXX[512] = { 0 };
		ULONG uKEYSPEC = 0;
		dwDataLen = sizeof(uKEYSPEC);
		
		
		

		if ( CryptGetProvParam(hDevprov, PP_KEYSPEC, (BYTE*)&uKEYSPEC, &dwDataLen, dwGetProvParamFlag) )
		{
			sprintf(szXX, "%s%s", (uKEYSPEC&1)?"加密":"",  (uKEYSPEC&2)?"签名":"" );
			List.SetItemText(count, 1, szXX);
		}

		sprintf(szXX, "%u", 26);
		List.SetItemText(count, 2, szXX);

		dwDataLen = sizeof(szXX);






	}while( 1 );
	
	CryptReleaseContext(hDevprov, 0);
	
}

void CCSPToolDlg::OnClickCspList(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here

	NM_LISTVIEW* pNMListCtrl = (NM_LISTVIEW*)pNMHDR;

	CString str;
	CListCtrl *ListCsp =  (CListCtrl*)GetDlgItem(IDC_CSP_LIST);

	str = ListCsp->GetItemText(pNMListCtrl->iItem, 0);

	EnumContainer(str, *(CListCtrl*)GetDlgItem(IDC_CONT_LIST));



	
	*pResult = 0;
}



void CCSPToolDlg::OnButtonCert() 
{
	// TODO: Add your control notification handler code here

	// AT_SIGNATURE

	CListCtrl* List = (CListCtrl*)GetDlgItem(IDC_CONT_LIST);

	POSITION Sel = List->GetFirstSelectedItemPosition();
	int nSel = -1;
	if ( Sel )
	{
		nSel = List->GetNextSelectedItem(Sel);
	}
	if ( nSel < 0 )
	{
		if ( List->GetItemCount() < 1 )
		{
			MessageBoxA("未选中容器");
			return;
		}
		nSel = 0;
	}

	
	CString CSP = (char*)List->GetItemData(nSel);
	CString cont = List->GetItemText(nSel, 0);

	BYTE Cert[4096] ={ 0 };

	int KeyPara = AT_SIGNATURE;

	CString strKey;
	GetDlgItemText(IDC_EDIT1, strKey);

	if ( atoi(strKey) > 0 )
	{
		KeyPara = atoi(strKey);
	}

	
	
	SetDlgItemText(IDC_EDIT1, "");

	int Size = CSP_ExportCert(cont, CSP, KeyPara, 26, Cert, sizeof(Cert) );

	if ( Size > 0 )
	{
		char Path[MAX_PATH] = { 0 };
		GetTempPathA(sizeof(Path), Path);

		int nLen = strlen(Path);
		if ( nLen > 0 && Path[nLen-1] != '\\')
		{
			strcpy(Path + nLen, "\\");
			nLen++;
		}
		strcpy(Path+nLen, "XXX.tmp.cer");

		DeleteFile(Path);

		FILE* f = fopen(Path, "wb");

		if ( !f )
		{
			MessageBoxA(Path, "fopen  Failed");
			return;
		}
		fwrite(Cert, Size, 1, f);
		fclose(f);

		ShellExecute(m_hWnd, "open", Path, NULL, NULL, SW_SHOW);


		Sleep(6000);
		DeleteFile(Path);

	}
	else
	{
       MessageBoxA("导出失败");
	}
	
}

void CCSPToolDlg::OnButtonVirefy() 
{
		HCRYPTPROV hDevprov = NULL;

		CListCtrl* List = (CListCtrl*)GetDlgItem(IDC_CONT_LIST);
		
		POSITION Sel = List->GetFirstSelectedItemPosition();
		int nSel = -1;
		if ( Sel )
		{
			nSel = List->GetNextSelectedItem(Sel);
		}
		if ( nSel < 0 )
		{
			if ( List->GetItemCount() < 1 )
			{
				MessageBoxA("未选中容器");
				return;
			}
			nSel = 0;
		}
		
		
	CString CSP = (char*)List->GetItemData(nSel);
	CString cont = List->GetItemText(nSel, 0);

	CString Pin;
	GetDlgItemText(IDC_EDIT_PIN, Pin);

	if ( Pin.GetLength() < 1 )
	{
		MessageBoxA("输入PIN码");
		return;
	}

	if(!CryptAcquireContext(&hDevprov, cont, CSP, PROV_RSA_FULL, 0))
	{
		DWORD dwError = GetLastError();
		MessageBoxA("OPEN UKEY 失败");
		return  ;
	}
	//效验密码
	if ( !CryptSetProvParam(hDevprov, PP_SIGNATURE_PIN, (BYTE*)(const char*)Pin, 0) )
	{
		MessageBoxA("密码错误");
		return;
	}
	MessageBoxA("密码正确");
	
}
