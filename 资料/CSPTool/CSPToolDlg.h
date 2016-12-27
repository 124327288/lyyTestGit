// CSPToolDlg.h : header file
//

#if !defined(AFX_CSPTOOLDLG_H__9FB7F85A_3901_43C4_9DDA_44013002EB12__INCLUDED_)
#define AFX_CSPTOOLDLG_H__9FB7F85A_3901_43C4_9DDA_44013002EB12__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <WinCrypt.h>

/////////////////////////////////////////////////////////////////////////////
// CCSPToolDlg dialog

class CCSPToolDlg : public CDialog
{
// Construction
public:
	CCSPToolDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	//{{AFX_DATA(CCSPToolDlg)
	enum { IDD = IDD_CSPTOOL_DIALOG };
		// NOTE: the ClassWizard will add data members here
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CCSPToolDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	void EnumContainer( const char* szProvider, CListCtrl& List);
	void EnumCSP(CListCtrl& list);
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CCSPToolDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnButton1();
	afx_msg void OnClickCspList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnButtonCert();
	afx_msg void OnButtonVirefy();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_CSPTOOLDLG_H__9FB7F85A_3901_43C4_9DDA_44013002EB12__INCLUDED_)
