// GenKeyPairPromptDlg.cpp : implementation file
//

#include "stdafx.h"
#include "tyCSP.h"
#include "GenKeyPairPromptDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CGenKeyPairPromptDlg dialog


CGenKeyPairPromptDlg::CGenKeyPairPromptDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CGenKeyPairPromptDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CGenKeyPairPromptDlg)
	m_szPrompt = _T("");
	//}}AFX_DATA_INIT
}


void CGenKeyPairPromptDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CGenKeyPairPromptDlg)
	DDX_Control(pDX, IDC_AVI, m_Avi);
	DDX_Text(pDX, IDC_PROMPT, m_szPrompt);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CGenKeyPairPromptDlg, CDialog)
	//{{AFX_MSG_MAP(CGenKeyPairPromptDlg)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CGenKeyPairPromptDlg message handlers
BOOL CGenKeyPairPromptDlg::OnInitDialog() 
{
	CDialog::OnInitDialog();
	
	// TODO: Add extra initialization here
	m_szPrompt.LoadString(IDS_CS_GENKEYPAIR_PROMPT + g_nRscOffset);
	m_Avi.Open(IDR_AVI_GENKEYPAIR);
	m_Avi.Play(0, -1, -1);

	UpdateData(FALSE);
	
	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}

BOOL CGenKeyPairPromptDlg::ShowPrompt()
{
	if(!this->Create(IDD_GENKEYPAIR_PROMPT))
		return FALSE;

	ShowWindow(SW_SHOW);

	return TRUE;
}

BOOL CGenKeyPairPromptDlg::HidePrompt()
{
	return DestroyWindow();
}
