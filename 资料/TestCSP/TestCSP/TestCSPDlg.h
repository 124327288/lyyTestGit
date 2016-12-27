
// TestCSPDlg.h : header file
//

#pragma once


// CTestCSPDlg dialog
class CTestCSPDlg : public CDialogEx
{
// Construction
public:
	CTestCSPDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_TESTCSP_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
private:
	HCRYPTPROV	m_hProv;
private:
	void	EnumCSP();
	void	ListCSPParam(CString strCSPName, DWORD dwType);
public:
	afx_msg void OnDestroy();
	afx_msg void OnCbnSelchangeComboCsplist();
	afx_msg void OnBnClickedBtnNewkeyset();
};
