//-------------------------------------------------------------------
//	本文件为 TY Cryptographic Service Provider 的组成部分
//
//
//	版权所有 天喻信息产业有限公司 (c) 1996 - 2005 保留一切权利
//-------------------------------------------------------------------
#if !defined(AFX_VERIFYPIN_H__5D7C97A5_0048_11D6_A6CC_DE8B1A23F73E__INCLUDED_)
#define AFX_VERIFYPIN_H__5D7C97A5_0048_11D6_A6CC_DE8B1A23F73E__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

// VerifyPIN.h : header file
//
#include "resource.h"

class CTYCSP;

/////////////////////////////////////////////////////////////////////////////
// VerifyPIN dialog

class VerifyPIN : public CDialog
{
// Construction
public:
	VerifyPIN(CTYCSP* pCSPObject, CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(VerifyPIN)
	enum { IDD = IDD_INPUT_PIN };
	CButton	m_btnOk;
	CEdit	m_editPassword;
	//}}AFX_DATA
	
	BOOL IsPassed() const { return m_bPass; }

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(VerifyPIN)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	CTYCSP*	m_pCSPObject;
	BOOL m_bPass;
	BOOL m_bPINBlocked;
	
	BOOL Verify(BYTE* pPassword, DWORD dwLen, int& nRetryCount);

	// Generated message map functions
	//{{AFX_MSG(VerifyPIN)
	virtual void OnOK();
	virtual void OnCancel();
	afx_msg void OnChangePassword();
	virtual BOOL OnInitDialog();
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()
};

BOOL VerifyPassword(CTYCSP* pCSPObject);

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_VERIFYPIN_H__5D7C97A5_0048_11D6_A6CC_DE8B1A23F73E__INCLUDED_)
