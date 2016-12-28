
// CSP_ExampleDlg.h : 头文件
//

#pragma once
#include "afxwin.h"


// CCSP_ExampleDlg 对话框
class CCSP_ExampleDlg : public CDialogEx
{
// 构造
public:
	CCSP_ExampleDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_CSP_EXAMPLE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonCspenum();
	//afx_msg void OnLbnSelchangeComboCsplist();
private:
	void RefreshCSPEnumHorizontalScrollBar();
	void RefreshCSPparaHorizontalScrollBar();
	void ListCSPParam(CString strCSPName, DWORD dwType);
	void EnumCSP();
	void EnumCSPType();
	void GetDefaultCSP();

private:
	afx_msg void OnBnClickedButtonCsppara();
	afx_msg void OnCbnSelchangeComboCSPlist();
	
private:
	CListBox pCSPENUMList;
	CComboBox pComboBoxPARA;
	CListBox pListBoxpara;
	CString strcspName;
public:
	CComboBox pComboBoxCSP;
};
