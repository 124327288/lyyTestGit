
// CSP_ExampleDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"


// CCSP_ExampleDlg �Ի���
class CCSP_ExampleDlg : public CDialogEx
{
// ����
public:
	CCSP_ExampleDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_CSP_EXAMPLE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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
