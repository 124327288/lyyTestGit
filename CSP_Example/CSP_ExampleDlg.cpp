
// CSP_ExampleDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "CSP_Example.h"
#include "CSP_ExampleDlg.h"
#include "afxdialogex.h"
#include<atlconv.h>


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	// ʵ��
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


// CCSP_ExampleDlg �Ի���




CCSP_ExampleDlg::CCSP_ExampleDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CCSP_ExampleDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CCSP_ExampleDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_CSPENUM, pCSPENUMList);
	DDX_Control(pDX, IDC_COMBO_CSPPARA, pComboBoxPARA);
	DDX_Control(pDX, IDC_LIST_CSPPARA, pListBoxpara);
	DDX_Control(pDX, IDC_COMBO1, pComboBoxCSP);
}

BEGIN_MESSAGE_MAP(CCSP_ExampleDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//ON_BN_CLICKED(IDC_BUTTON_CSPENUM, &CCSP_ExampleDlg::OnBnClickedButtonCspenum)
	//ON_LBN_SELCHANGE(IDC_LIST_CSPENUM, &CCSP_ExampleDlg::OnLbnSelchangeComboCsplist)
	ON_CBN_SELCHANGE(IDC_COMBO_ENUMCSP, &CCSP_ExampleDlg::OnCbnSelchangeComboCSPlist)
	ON_BN_CLICKED(IDC_BUTTON_CSPPARA, &CCSP_ExampleDlg::OnBnClickedButtonCsppara)
END_MESSAGE_MAP()


// CCSP_ExampleDlg ��Ϣ�������

BOOL CCSP_ExampleDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��
	pComboBoxPARA.AddString(_T("PP_PROVTYPE"));
	pComboBoxPARA.AddString(_T("PP_IMPTYPE"));
	pComboBoxPARA.AddString(_T("PP_CONTAINER"));
	pComboBoxPARA.AddString(_T("PP_UNIQUE_CONTAINER"));
	pComboBoxPARA.AddString(_T("PP_ENUMALGS"));
	pComboBoxPARA.AddString(_T("PP_ENUMCONTAINERS"));
	pComboBoxPARA.AddString(_T("PP_KEYSET_SEC_DESCR"));
	pComboBoxPARA.SetCurSel(0);
	pComboBoxCSP.AddString(_T("ö�ټ�����е�CSP"));
	pComboBoxCSP.AddString(_T("ö�ټ�����е�CSP������"));
	pComboBoxCSP.AddString(_T("Ĭ�ϵ�CSP"));
	pComboBoxCSP.SetCurSel(0);
	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CCSP_ExampleDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CCSP_ExampleDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CCSP_ExampleDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CCSP_ExampleDlg::EnumCSP()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	DWORD dwIndex = 0;
	DWORD dwType = 0;
	DWORD dwNameLen = 0;
	//CListBox* pCSPENUMList = (CListBox*)GetDlgItem(IDC_LIST_CSPENUM);	
	pCSPENUMList.ResetContent();
	while (CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &dwNameLen))
	{	
		DWORD dwItem = 0;
		TCHAR * pName = new TCHAR[dwNameLen + 1 ];
		if (CryptEnumProviders(dwIndex++, NULL, 0, &dwType, pName, &dwNameLen))
		{
			pCSPENUMList.AddString(pName);
			if (dwIndex == 2)
			{
				strcspName = pName;
			}

		}
		delete []pName;
	}
	RefreshCSPEnumHorizontalScrollBar();

}
void CCSP_ExampleDlg::EnumCSPType()
{
	pCSPENUMList.ResetContent();
	DWORD       dwIndex;
	DWORD       dwType;
	DWORD       cbName;
	LPTSTR      pszName;
	// Loop through enumerating provider types.
	dwIndex = 0;
	while(CryptEnumProviderTypes(
		dwIndex,
		NULL,
		0,
		&dwType,
		NULL,
		&cbName
		))
	{

		//-----------------------------------------------------------
		//  cbName returns the length of the name of the next
		//  provider type. Allocate memory in a buffer to retrieve
		//  that name.
		if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName)))
		{
			//printf("ERROR - LocalAlloc failed.\n");
			MessageBox(_T("ERROR - LocalAlloc failed."));
			exit(1);
		}
		//-----------------------------------------------------------
		//  Get the provider type name.

		if (CryptEnumProviderTypes(
			dwIndex++,
			NULL,
			NULL,
			&dwType,   
			pszName,
			&cbName))     
		{
			//printf ("     %4.0d\t%s\n",dwType, pszName);
			CString strType ;
			strType.Format(_T("%4.0d"),dwType);
			CString str ;
			str += strType;
			str += _T("  ");
			str += pszName;
			pCSPENUMList.AddString(str);

		}
		else
		{
			MessageBox(_T("ERROR - CryptEnumProviderTypes"));
			exit(1);
		}
		LocalFree(pszName);
	} // End of while loop.
}

void CCSP_ExampleDlg::GetDefaultCSP()
{
	CryptSetProvider(strcspName,PROV_RSA_FULL);
	pCSPENUMList.ResetContent();
	LPTSTR pszName;
	DWORD cbName;
	// Get the name of the default CSP specified for the PROV_RSA_SIG 
	// type for the machine.
	cbName = 0;
	if (!CryptGetDefaultProvider(PROV_RSA_FULL, NULL, CRYPT_USER_DEFAULT
		,
		NULL, &cbName)) 
	{/*printf("Error %x during CryptGetDefaultProvider!\n", GetLastError);*/
		MessageBox(_T("ERROR - CryptGetDefaultProvider"));
		return;
	}
	if (NULL == (pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) 
	{
		//printf("Error during memory allocation\n");
		MessageBox(_T("Error during memory allocation"));

		return;
	}
	if (!CryptGetDefaultProvider(PROV_RSA_FULL, NULL, CRYPT_USER_DEFAULT
		,
		pszName, &cbName)) 
	{/*printf("Error %x during CryptGetDefaultProvider!\n", GetLastError);*/
		MessageBox(_T("ERROR - CryptGetDefaultProvider"));
		return;
	}

	pCSPENUMList.AddString(pszName);
	LocalFree(pszName);
}
void CCSP_ExampleDlg::RefreshCSPEnumHorizontalScrollBar()
{
	CDC *pDC = pCSPENUMList.GetDC();
	if ( NULL == pDC )
	{
		return;
	}

	int nCount = pCSPENUMList.GetCount();
	if ( nCount < 1 )
	{
		pCSPENUMList.SetHorizontalExtent( 0 );
		return;
	}
	int nMaxExtent = 0;
	CString szText;
	for ( int i = 0; i < nCount; ++i )
	{
		pCSPENUMList.GetText( i, szText );
		CSize &cs = pDC->GetTextExtent( szText );
		if ( cs.cx > nMaxExtent )
		{
			nMaxExtent = cs.cx;
		}
	}
	pCSPENUMList.SetHorizontalExtent( nMaxExtent );
}
void CCSP_ExampleDlg::RefreshCSPparaHorizontalScrollBar()
{
	CDC *pDC = pListBoxpara.GetDC();
	if ( NULL == pDC )
	{
		return;
	}

	int nCount = pListBoxpara.GetCount();
	if ( nCount < 1 )
	{
		pListBoxpara.SetHorizontalExtent( 0 );
		return;
	}
	int nMaxExtent = 0;
	CString szText;
	for ( int i = 0; i < nCount; ++i )
	{
		pListBoxpara.GetText( i, szText );
		CSize &cs = pDC->GetTextExtent( szText );
		if ( cs.cx > nMaxExtent )
		{
			nMaxExtent = cs.cx;
		}
	}
	pListBoxpara.SetHorizontalExtent( nMaxExtent );
}
//  void CCSP_ExampleDlg::OnLbnSelchangeComboCsplist()
//  {
// 	 pCSPENUMList.GetCurSel();
// 	 DWORD dwIndex = pCSPENUMList.GetCurSel();
// 	 DWORD dwType = pCSPENUMList.GetItemData(dwIndex);
// 	 CString str;
// 	 pCSPENUMList.GetText(dwIndex,str);
// 	// pCSPENUMList.AddString()
//  }




void CCSP_ExampleDlg::OnBnClickedButtonCsppara()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	if (pComboBoxCSP.GetCurSel() == 0)
	{
		int nCount = pCSPENUMList.GetCount();
		DWORD dwIndex = pCSPENUMList.GetCurSel();
		DWORD dwType = pCSPENUMList.GetItemData(dwIndex);
		pListBoxpara.ResetContent();
		if (dwIndex > -1 && dwIndex < nCount)
		{
			CString strCSPName;
			pCSPENUMList.GetText(dwIndex,strCSPName);
			ListCSPParam(strCSPName, dwType);
		}
		else
		{
			ListCSPParam(NULL, dwType);
		}
		RefreshCSPparaHorizontalScrollBar();
	}
	else
	{
		ListCSPParam(NULL, 0);
	}

}
void CCSP_ExampleDlg::ListCSPParam(CString strCSPName, DWORD dwType)
{
	//char *s="Golden Global View";
	//clrscr();
	//memset(s,'G',6);
	HCRYPTPROV hProv = NULL;
	BYTE btParamData[2048] = {0};
	DWORD dwParamLen = 2048;
	DWORD dwIndex = 0;
	//CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_PARAM);
	//pList->DeleteAllItems();
	if (!CryptAcquireContext(&hProv, L"lyycathie1102", strCSPName, PROV_RSA_FULL, 0))
	{
		DWORD dwErr = GetLastError();
		MessageBox(_T("����CryptAcquireContextʧ��!"));
		return;
	}
	CString strPara;
	GetDlgItemText(IDC_COMBO_CSPPARA, strPara);
	//��ȡCSP����
	if(strPara == _T("PP_PROVTYPE"))
	{
		dwParamLen = 2048;
		memset(btParamData, 0, 2048);
		//pList->InsertItem(dwIndex, _T("PP_PROVTYPE"), 0);
		//pList->SetItemText(dwIndex, 1, _T("CSP����"));
		pListBoxpara.AddString(_T("CSP����"));
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
			pListBoxpara.AddString(strCSPType);
		}
		else
		{
			pListBoxpara.AddString(_T("Failed"));
		}
	}
	//dwIndex++;

	//��ȡCSPʵ�ֵ�����
	if(strPara == _T("PP_IMPTYPE"))
	{
		dwParamLen = 2048;
		memset(btParamData, 0, 2048);
		//   	pList->InsertItem(dwIndex, _T("PP_IMPTYPE"), 0);
		//   	pList->SetItemText(dwIndex, 1, _T("ʵ������"));
		pListBoxpara.AddString(_T("ʵ������"));
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

			pListBoxpara.AddString(strImplType);
		}
		else
		{
			pListBoxpara.AddString(_T("Failed"));
		}
	}
	//dwIndex++;

	//��ȡCSP��������
	if(strPara == _T("PP_CONTAINER"))
	{
		dwParamLen = 2048;
		memset(btParamData, 0, 2048);
		//   	pList->InsertItem(dwIndex, _T("PP_CONTAINER"), 0);
		//   	pList->SetItemText(dwIndex, 1, _T("��Կ��������"));
		pListBoxpara.AddString(_T("��Կ��������"));		
			if (CryptGetProvParam(hProv, PP_CONTAINER, btParamData, &dwParamLen, 0))
			{
				TCHAR *tcValue = NULL;
#ifdef UNICODE
				USES_CONVERSION;
				tcValue = A2W((char*)btParamData);
#else
				tcValue = (char*)btParamData;
#endif
				//pList->SetItemText(dwIndex, 2, tcValue);
				pListBoxpara.AddString(tcValue);
			}
			else
			{
				//pList->SetItemText(dwIndex, 2, _T("Failed!"));
				pListBoxpara.AddString( _T("Failed!"));
			}
			
	}
	//dwIndex++;

	//��ȡCSPΨһ��������
	if(strPara == _T("PP_UNIQUE_CONTAINER"))
	{
		dwParamLen = 2048;
		memset(btParamData, 0, 2048);
		//   	pList->InsertItem(dwIndex, _T("PP_UNIQUE_CONTAINER"), 0);
		//   	pList->SetItemText(dwIndex, 1, _T("Ψһ��������"));
		pListBoxpara.AddString(_T("Ψһ��������"));
		if (CryptGetProvParam(hProv, PP_UNIQUE_CONTAINER, btParamData, &dwParamLen, 0))
		{
			TCHAR *tcValue = NULL;
#ifdef UNICODE
			USES_CONVERSION;
			tcValue = A2W((char*)btParamData);
#else
			tcValue = (char*)btParamData;
#endif
			//pList->SetItemText(dwIndex, 2, tcValue);
			pListBoxpara.AddString(tcValue);
		}
		else
		{
			//pList->SetItemText(dwIndex, 2, _T("Failed!"));
			pListBoxpara.AddString(_T("Failed!"));
		}
	}
	//dwIndex++;


	//   	dwParamLen = 2048;
	//   	memset(btParamData, 0, 2048);
	//   	pList->InsertItem(dwIndex, _T("PP_KEYSET_SEC_DESCR"), 0);
	//   	pList->SetItemText(dwIndex, 1, _T("Ψһ��������"));
	//   	if (CryptGetProvParam(hProv, PP_KEYSET_SEC_DESCR, btParamData, &dwParamLen, 0))
	//   	{
	//   		TCHAR *tcValue = NULL;
	//   #ifdef UNICODE
	//   		tcValue = A2W((char*)btParamData);
	//   #else
	//   		tcValue = (char*)btParamData;
	//   #endif
	//   		pList->SetItemText(dwIndex, 2, tcValue);
	//   	}
	//   	else
	//   	{
	//   		pList->SetItemText(dwIndex, 2, _T("Failed!"));
	//   	}
	//   	dwIndex++;

	//��ȡCSP��֧�ֵ��㷨��Ϣ
	if(strPara == _T("PP_ENUMALGS"))
	{
		dwParamLen = 2048;
		memset(btParamData, 0, 2048);
		//   	pList->InsertItem(dwIndex, _T("PP_ENUMALGS"), 0);
		//   	pList->SetItemText(dwIndex, 1, _T("֧�ֵ��㷨��Ϣ"));
		pListBoxpara.AddString(_T("֧�ֵ��㷨��Ϣ"));
		if (CryptGetProvParam(hProv, PP_ENUMALGS, btParamData, &dwParamLen, CRYPT_FIRST))
		{
			CString strAlgs;
			PROV_ENUMALGS* alg = (PROV_ENUMALGS*)btParamData;
			TCHAR *tcValue = NULL;
#ifdef UNICODE
			USES_CONVERSION;
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
				USES_CONVERSION;
				tcValue = A2W(alg->szName);
#else
				tcValue = alg->szName;
#endif
				strAlgs += _T("/");
				strAlgs += tcValue;
			}
			//pList->SetItemText(dwIndex, 2, strAlgs);
			pListBoxpara.AddString(strAlgs);
		}
		else
		{
			//pList->SetItemText(dwIndex, 2, _T("Failed!"));
			pListBoxpara.AddString(_T("Failed!"));
		}
	}
	//dwIndex++;


	//��ȡCSP���е���������
	if(strPara == _T("PP_ENUMCONTAINERS"))
	{
		dwParamLen = 2048;
		memset(btParamData, 0, 2048);
		//pList->InsertItem(dwIndex, _T("PP_ENUMCONTAINERS"), 0);
		//pList->SetItemText(dwIndex, 1, _T("����������"));
		pListBoxpara.AddString(_T("����������"));
		if (CryptGetProvParam(hProv, PP_ENUMCONTAINERS, btParamData, &dwParamLen, CRYPT_FIRST))
		{
			CString strContianers;
			TCHAR *tcValue = NULL;
#ifdef UNICODE
			USES_CONVERSION;
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
			//pList->SetItemText(dwIndex, 2, strContianers);
			pListBoxpara.AddString(strContianers);
		}
		else
		{
			//pList->SetItemText(dwIndex, 2, _T("Failed!"));
			pListBoxpara.AddString(_T("Failed!"));
		}
	}
	//dwIndex++;

	//��ȡCSP��Կ����
	if(strPara == _T("PP_KEYSET_SEC_DESCR"))
	{
		dwParamLen = 2048;
		memset(btParamData, 0, 2048);
		//pList->InsertItem(dwIndex, _T("PP_KEYSET_SEC_DESCR"), 0);
		//pList->SetItemText(dwIndex, 1, _T("��Կ����"));
		pListBoxpara.AddString(_T("��Կ����"));
		if (CryptGetProvParam(hProv, PP_KEYSET_SEC_DESCR, btParamData, &dwParamLen, 0))
		{
			TCHAR *tcValue = NULL;
			SECURITY_DESCRIPTOR *pDesc = (SECURITY_DESCRIPTOR *)btParamData;
#ifdef UNICODE
			USES_CONVERSION;
			tcValue = A2W((char*)btParamData);
#else
			tcValue = (char*)btParamData;
#endif
			//pList->SetItemText(dwIndex, 2, tcValue);
			pListBoxpara.AddString(tcValue);
		}
		else
		{
			//pList->SetItemText(dwIndex, 2, _T("Failed!"));
			pListBoxpara.AddString(_T("Failed!"));
		}
	}
	//dwIndex++;	


}

void CCSP_ExampleDlg::OnCbnSelchangeComboCSPlist()
{
	DWORD Index  = pComboBoxCSP.GetCurSel();
	if(Index == 0) //ö�ټ����������CSP
	{
		EnumCSP();
	}
	if(Index == 1) //ö�ټ����������CSP����
	{
		EnumCSPType();
	}
	if(Index == 2) //Ĭ�ϵ�CSP
	{
		GetDefaultCSP();
	}

}
