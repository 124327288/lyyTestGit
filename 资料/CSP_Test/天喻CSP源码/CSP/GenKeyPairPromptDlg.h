#if !defined(AFX_GENKEYPAIRPROMPTDLG_H__E045ECDE_F8AA_4EC9_B60B_AACBE37EAD14__INCLUDED_)
#define AFX_GENKEYPAIRPROMPTDLG_H__E045ECDE_F8AA_4EC9_B60B_AACBE37EAD14__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// GenKeyPairPromptDlg.h : header file
//

#include "resource.h"

/////////////////////////////////////////////////////////////////////////////
// CGenKeyPairPromptDlg dialog

class CGenKeyPairPromptDlg : public CDialog
{
// Construction
public:
	CGenKeyPairPromptDlg(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CGenKeyPairPromptDlg)
	enum { IDD = IDD_GENKEYPAIR_PROMPT };
	CAnimateCtrl	m_Avi;
	CString	m_szPrompt;
	//}}AFX_DATA

	BOOL ShowPrompt();
	BOOL HidePrompt();
// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CGenKeyPairPromptDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CGenKeyPairPromptDlg)
	virtual BOOL OnInitDialog();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};
//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_GENKEYPAIRPROMPTDLG_H__E045ECDE_F8AA_4EC9_B60B_AACBE37EAD14__INCLUDED_)
