//-------------------------------------------------------------------
//	本文件为 TY Cryptographic Service Provider 的组成部分
//
//	版权所有 天喻信息产业有限公司 (c) 1996 - 2005 保留一切权利
//-------------------------------------------------------------------
// VerifyPIN.cpp : implementation file
//

#include "stdafx.h"
#include "afxpriv.h"
#include "tyCSP.h"
#include "VerifyPIN.h"
#include "CSPObject.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// VerifyPIN dialog


VerifyPIN::VerifyPIN(CTYCSP* pCSPObject, CWnd* pParent /*=NULL*/)
	: CDialog(VerifyPIN::IDD, pParent)
{
	ASSERT(pCSPObject);
	m_pCSPObject = pCSPObject;
	//{{AFX_DATA_INIT(VerifyPIN)
		// NOTE: the ClassWizard will add member initialization here
	m_bPass = FALSE;
	m_bPINBlocked = FALSE;
	//}}AFX_DATA_INIT
}


void VerifyPIN::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(VerifyPIN)
	DDX_Control(pDX, IDOK, m_btnOk);
	DDX_Control(pDX, IDC_PASSWORD, m_editPassword);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(VerifyPIN, CDialog)
	//{{AFX_MSG_MAP(VerifyPIN)
	ON_EN_CHANGE(IDC_PASSWORD, OnChangePassword)
	ON_WM_CREATE()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// VerifyPIN message handlers
BOOL VerifyPIN::OnInitDialog() 
{
	CDialog::OnInitDialog();
	
	// TODO: Add extra initialization here

	//显示文本

	//对话框标题
	CString szCaption;
	szCaption.LoadString(IDS_CS_DIALOG_CAPTION + g_nRscOffset);
	SetWindowText(szCaption);

	//静态文本1
	szCaption.LoadString(IDS_CS_DLGSTC_1 + g_nRscOffset);
	GetDlgItem(IDC_STATIC1)->SetWindowText(szCaption);

//	//静态文本2
//	szCaption.LoadString(IDS_CS_DLGSTC_2 + g_nRscOffset);
//	GetDlgItem(IDC_STATIC2)->SetWindowText(szCaption);

	//OK按钮文本
	szCaption.LoadString(IDS_CS_DLGBTN_OK + g_nRscOffset);
	GetDlgItem(IDOK)->SetWindowText(szCaption);

	//CANCEL按钮文本
	szCaption.LoadString(IDS_CS_DLGBTN_CANCEL + g_nRscOffset);
	GetDlgItem(IDCANCEL)->SetWindowText(szCaption);

	m_btnOk.EnableWindow(FALSE);
	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}

int VerifyPIN::OnCreate(LPCREATESTRUCT lpCreateStruct) 
{
	if (CDialog::OnCreate(lpCreateStruct) == -1)
		return -1;
	
	// TODO: Add your specialized creation code here
     SetWindowPos(
		 &wndTopMost, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE
		 );
	 
	return 0;
}

void VerifyPIN::OnOK() 
{
	// TODO: Add extra validation here
	CString szPassworld;
	m_editPassword.GetWindowText(szPassworld);
	int nRetryCount;
	BOOL bRetVal = Verify(
		(BYTE* )szPassworld.LockBuffer(), szPassworld.GetLength(), nRetryCount
		);
	szPassworld.UnlockBuffer();

	CString szMsgBoxCaption;
	szMsgBoxCaption.LoadString(IDS_CS_DIALOG_CAPTION + g_nRscOffset);
	CString szMsg;
	if(!bRetVal){
		if(nRetryCount < 0){
			szMsg.LoadString(IDS_CS_VERIFYPIN_INNERERROR + g_nRscOffset);
		}
		else{
			if(nRetryCount == 0){
				m_bPINBlocked = TRUE;
				m_btnOk.EnableWindow(FALSE);
				szMsg.LoadString(IDS_CS_VERIFYPIN_PINLOCKED + g_nRscOffset);
			}
			else{
				CString szTmp;
				szTmp.LoadString(IDS_CS_VERIFYPIN_INCORRECTPIN + g_nRscOffset);
				szMsg.Format(szTmp, nRetryCount);
			}
		}
		MessageBox(szMsg, szMsgBoxCaption, MB_OK | MB_ICONSTOP);
	}
	else{
		m_bPass = TRUE;
		CDialog::OnOK();
	}
	
}

void VerifyPIN::OnCancel() 
{
	// TODO: Add extra cleanup here
	
	CDialog::OnCancel();
}

void VerifyPIN::OnChangePassword() 
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	
	// TODO: Add your control notification handler code here
	if(!m_bPINBlocked){
		CString szPassword;
		m_editPassword.GetWindowText(szPassword);
		m_btnOk.EnableWindow(szPassword.GetLength() > 0);
	}
}

BOOL VerifyPIN::Verify(BYTE* pPassword, DWORD dwLen, int& nRetryCount)
{
	ASSERT(pPassword != NULL || dwLen != 0);

	//进行外部认证 
	if(m_bPINBlocked){
		nRetryCount = 0;
		return FALSE;
	}

	BOOL bRetVal = m_pCSPObject->VerifyPin(pPassword, dwLen, nRetryCount);
	if(!bRetVal && nRetryCount == 0)
		m_bPINBlocked = TRUE;

	return bRetVal;
}

BOOL VerifyPassword(CTYCSP* pCSPObject)
{
	VerifyPIN dlg(pCSPObject);
	dlg.DoModal();

	return dlg.IsPassed();
}




