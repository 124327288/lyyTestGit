
// TestCSPDlg.cpp : implementation file
//

#include "stdafx.h"
#include "TestCSP.h"
#include "TestCSPDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CTestCSPDlg dialog



CTestCSPDlg::CTestCSPDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CTestCSPDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_hProv = NULL;
}

void CTestCSPDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CTestCSPDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_DESTROY()
	ON_CBN_SELCHANGE(IDC_COMBO_CSPLIST, &CTestCSPDlg::OnCbnSelchangeComboCsplist)
	ON_BN_CLICKED(IDC_BTN_NEWKEYSET, &CTestCSPDlg::OnBnClickedBtnNewkeyset)
END_MESSAGE_MAP()


// CTestCSPDlg message handlers

BOOL CTestCSPDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_PARAM);
	pList->SetExtendedStyle(pList->GetExtendedStyle()|LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);
	pList->InsertColumn(0, _T("参数ID"), 0, 150);
	pList->InsertColumn(1, _T("参数说明"), 0, 100);
	pList->InsertColumn(2, _T("参数值"), 0, 500);
	EnumCSP();

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CTestCSPDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CTestCSPDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

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
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CTestCSPDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CTestCSPDlg::OnDestroy()
{
	CDialogEx::OnDestroy();

	if (m_hProv != NULL)
	{
		CryptReleaseContext(m_hProv, 0);
		m_hProv = NULL;
	}
}

void CTestCSPDlg::OnCbnSelchangeComboCsplist()
{
	CString strCSPName;
	CComboBox* pCSPList = (CComboBox*)GetDlgItem(IDC_COMBO_CSPLIST);
	DWORD dwIndex = pCSPList->GetCurSel();
	DWORD dwType = pCSPList->GetItemData(dwIndex);

	GetDlgItemText(IDC_COMBO_CSPLIST, strCSPName);
	ListCSPParam(strCSPName, dwType);
}



void CTestCSPDlg::EnumCSP()
{
	DWORD dwIndex = 0;
	DWORD dwType = 0;
	DWORD dwNameLen = 0;
	CComboBox* pCSPList = (CComboBox*)GetDlgItem(IDC_COMBO_CSPLIST);
	pCSPList->ResetContent();

	while (CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &dwNameLen))
	{	
		DWORD dwItem = 0;
		TCHAR * pName = new TCHAR[dwNameLen + 1 ];
		if (CryptEnumProviders(dwIndex++, NULL, 0, &dwType, pName, &dwNameLen))
		{
			dwItem = pCSPList->AddString(pName);
			pCSPList->SetItemData(dwItem, dwType);

		}
		delete []pName;
	}
	pCSPList->SetCurSel(0);
	OnCbnSelchangeComboCsplist();
}

void CTestCSPDlg::ListCSPParam(CString strCSPName, DWORD dwType)
{
	HCRYPTPROV hProv = NULL;
	BYTE btParamData[2048] = {0};
	DWORD dwParamLen = 2048;
	DWORD dwIndex = 0;
	CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_PARAM);
	pList->DeleteAllItems();
	
	USES_CONVERSION;
	
	if (!CryptAcquireContext(&hProv, NULL, strCSPName, dwType, 0))
	{
		DWORD dwErr = GetLastError();
		MessageBox(_T("函数CryptAcquireContext失败!"));
		return;
	}
	
	//获取CSP类型
	dwParamLen = 2048;
	memset(btParamData, 0, 2048);
	pList->InsertItem(dwIndex, _T("PP_PROVTYPE"), 0);
	pList->SetItemText(dwIndex, 1, _T("CSP类型"));
	if (CryptGetProvParam(hProv, PP_PROVTYPE, btParamData, &dwParamLen, 0))
	{
		DWORD dwCSPType;
		CString strCSPType;
		memcpy(&dwCSPType, btParamData, 4);
		switch (dwCSPType)
		{
		case PROV_RSA_FULL:
			strCSPType = _T("PROV_RSA_FULL");
			break;
		case PROV_RSA_AES:
			strCSPType = _T("PROV_RSA_AES");
			break;
		case PROV_RSA_SIG:
			strCSPType = _T("PROV_RSA_SIG");
			break;
		case PROV_RSA_SCHANNEL:
			strCSPType = _T("PROV_RSA_SCHANNEL");
			break;
		case PROV_DSS:
			strCSPType = _T("PROV_DSS");
			break;
		case PROV_DSS_DH:
			strCSPType = _T("PROV_DSS_DH");
			break;
		case PROV_DH_SCHANNEL:
			strCSPType = _T("PROV_DH_SCHANNEL");
			break;
		case PROV_FORTEZZA:
			strCSPType = _T("PROV_FORTEZZA");
			break;
		case PROV_MS_EXCHANGE:
			strCSPType = _T("PROV_MS_EXCHANGE");
			break;
		case PROV_SSL:
			strCSPType = _T("PROV_SSL");
			break;
		default:
			strCSPType = _T("Unknown");
			break;
		}
		pList->SetItemText(dwIndex, 2, strCSPType);
	}
	else
	{
		pList->SetItemText(dwIndex, 2, _T("Failed!"));
	}
	dwIndex++;
	
	//获取CSP实现的类型
	dwParamLen = 2048;
	memset(btParamData, 0, 2048);
	pList->InsertItem(dwIndex, _T("PP_IMPTYPE"), 0);
	pList->SetItemText(dwIndex, 1, _T("实现类型"));
	if (CryptGetProvParam(hProv, PP_IMPTYPE, btParamData, &dwParamLen, 0))
	{
		DWORD dwImplType;
		CString strImplType;
		memcpy(&dwImplType, btParamData, 4);
		if (dwImplType & CRYPT_IMPL_HARDWARE)
			strImplType += _T("Hardware/");
		if (dwImplType & CRYPT_IMPL_SOFTWARE)
			strImplType += _T("Software/");
		if (dwImplType & CRYPT_IMPL_MIXED)
			strImplType += _T("Mixed/");
		if (dwImplType & CRYPT_IMPL_REMOVABLE)
			strImplType += _T("Removable/");
		if (dwImplType & CRYPT_IMPL_UNKNOWN)
			strImplType += _T("Unknown");

		pList->SetItemText(dwIndex, 2, strImplType);
	}
	else
	{
		pList->SetItemText(dwIndex, 2, _T("Failed!"));
	}
	dwIndex++;

	//获取CSP容器名称
	dwParamLen = 2048;
	memset(btParamData, 0, 2048);
	pList->InsertItem(dwIndex, _T("PP_CONTAINER"), 0);
	pList->SetItemText(dwIndex, 1, _T("密钥容器名称"));
	if (CryptGetProvParam(hProv, PP_CONTAINER, btParamData, &dwParamLen, 0))
	{
		TCHAR *tcValue = NULL;
#ifdef UNICODE
		tcValue = A2W((char*)btParamData);
#else
		tcValue = (char*)btParamData;
#endif
		pList->SetItemText(dwIndex, 2, tcValue);
	}
	else
	{
		pList->SetItemText(dwIndex, 2, _T("Failed!"));
	}
	dwIndex++;

	//获取CSP唯一的容器名	
	dwParamLen = 2048;
	memset(btParamData, 0, 2048);
	pList->InsertItem(dwIndex, _T("PP_UNIQUE_CONTAINER"), 0);
	pList->SetItemText(dwIndex, 1, _T("唯一的容器名"));
	if (CryptGetProvParam(hProv, PP_UNIQUE_CONTAINER, btParamData, &dwParamLen, 0))
	{
		TCHAR *tcValue = NULL;
#ifdef UNICODE
		tcValue = A2W((char*)btParamData);
#else
		tcValue = (char*)btParamData;
#endif
		pList->SetItemText(dwIndex, 2, tcValue);
	}
	else
	{
		pList->SetItemText(dwIndex, 2, _T("Failed!"));
	}
	dwIndex++;
	
	
	dwParamLen = 2048;
	memset(btParamData, 0, 2048);
	pList->InsertItem(dwIndex, _T("PP_KEYSET_SEC_DESCR"), 0);
	pList->SetItemText(dwIndex, 1, _T("唯一的容器名"));
	if (CryptGetProvParam(hProv, PP_KEYSET_SEC_DESCR, btParamData, &dwParamLen, 0))
	{
		TCHAR *tcValue = NULL;
#ifdef UNICODE
		tcValue = A2W((char*)btParamData);
#else
		tcValue = (char*)btParamData;
#endif
		pList->SetItemText(dwIndex, 2, tcValue);
	}
	else
	{
		pList->SetItemText(dwIndex, 2, _T("Failed!"));
	}
	dwIndex++;
	
	//获取CSP所支持的算法信息
	dwParamLen = 2048;
	memset(btParamData, 0, 2048);
	pList->InsertItem(dwIndex, _T("PP_ENUMALGS"), 0);
	pList->SetItemText(dwIndex, 1, _T("支持的算法信息"));
	if (CryptGetProvParam(hProv, PP_ENUMALGS, btParamData, &dwParamLen, CRYPT_FIRST))
	{
		CString strAlgs;
		PROV_ENUMALGS* alg = (PROV_ENUMALGS*)btParamData;
		TCHAR *tcValue = NULL;
#ifdef UNICODE
		tcValue = A2W(alg->szName);
#else
		tcValue = alg->szName;
#endif
		strAlgs += tcValue;
		
		dwParamLen = 2048;
		memset(btParamData, 0, 2048);
		while (CryptGetProvParam(hProv, PP_ENUMALGS, btParamData, &dwParamLen, CRYPT_NEXT))
		{
			alg = (PROV_ENUMALGS*)btParamData;
#ifdef UNICODE
			tcValue = A2W(alg->szName);
#else
			tcValue = alg->szName;
#endif
			strAlgs += _T("/");
			strAlgs += tcValue;
		}
		pList->SetItemText(dwIndex, 2, strAlgs);
	}
	else
	{
		pList->SetItemText(dwIndex, 2, _T("Failed!"));
	}
	dwIndex++;


	//获取CSP所有的容器名称
	dwParamLen = 2048;
	memset(btParamData, 0, 2048);
	pList->InsertItem(dwIndex, _T("PP_ENUMCONTAINERS"), 0);
	pList->SetItemText(dwIndex, 1, _T("所有容器名"));
	if (CryptGetProvParam(hProv, PP_ENUMCONTAINERS, btParamData, &dwParamLen, CRYPT_FIRST))
	{
		CString strContianers;
		TCHAR *tcValue = NULL;
#ifdef UNICODE
		tcValue = A2W((char*)btParamData);
#else
		tcValue = btParamData;
#endif
		strContianers += tcValue;
		
		dwParamLen = 2048;
		memset(btParamData, 0, 2048);
		while (CryptGetProvParam(hProv, PP_ENUMCONTAINERS, btParamData, &dwParamLen, CRYPT_NEXT))
		{
#ifdef UNICODE
			tcValue = A2W((char*)btParamData);
#else
			tcValue = btParamData;
#endif
			strContianers += _T("/");
			strContianers += tcValue;
		}
		pList->SetItemText(dwIndex, 2, strContianers);
	}
	else
	{
		pList->SetItemText(dwIndex, 2, _T("Failed!"));
	}
	dwIndex++;

	//获取CSP密钥描述
	dwParamLen = 2048;
	memset(btParamData, 0, 2048);
	pList->InsertItem(dwIndex, _T("PP_KEYSET_SEC_DESCR"), 0);
	pList->SetItemText(dwIndex, 1, _T("密钥描述"));
	if (CryptGetProvParam(hProv, PP_KEYSET_SEC_DESCR, btParamData, &dwParamLen, 0))
	{
		TCHAR *tcValue = NULL;
		SECURITY_DESCRIPTOR *pDesc = (SECURITY_DESCRIPTOR *)btParamData;
#ifdef UNICODE
		tcValue = A2W((char*)btParamData);
#else
		tcValue = (char*)btParamData;
#endif
		pList->SetItemText(dwIndex, 2, tcValue);
	}
	else
	{
		pList->SetItemText(dwIndex, 2, _T("Failed!"));
	}
	dwIndex++;	 
}

void CTestCSPDlg::OnBnClickedBtnNewkeyset()
{
	CString strCSPName;
	CComboBox* pCSPList = (CComboBox*)GetDlgItem(IDC_COMBO_CSPLIST);
	DWORD dwIndex = pCSPList->GetCurSel();
	DWORD dwType = pCSPList->GetItemData(dwIndex);
	HCRYPTPROV hProv = NULL;
	GetDlgItemText(IDC_COMBO_CSPLIST, strCSPName);

	//if (!CryptAcquireContext(&hProv, NULL, strCSPName, dwType, 0))
	{
		GUID containerId = GUID_NULL;
		WCHAR wccontainerId[48] = {0};
		CoCreateGuid(&containerId);
		int nSize = ::StringFromGUID2(containerId, wccontainerId, 48);
		if (!CryptAcquireContext(&hProv, wccontainerId, strCSPName, dwType, CRYPT_NEWKEYSET))
		{
			return;
		}
	}
	if (hProv)
	{
		CryptReleaseContext(hProv, 0);
	}
}
