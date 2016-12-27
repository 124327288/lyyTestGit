#if !defined(AFX_OPENCARDDLG_H__9AED5E95_2399_4BF7_964F_AFC225E66559__INCLUDED_)
#define AFX_OPENCARDDLG_H__9AED5E95_2399_4BF7_964F_AFC225E66559__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// OpenCardDlg.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// COpenCardDlg dialog

class COpenCardDlg : public CDialog
{
// Construction
public:
	COpenCardDlg(LPOPENCARDNAME pOpenCardStruct, BOOL bFilterReader, CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(COpenCardDlg)
	enum { IDD = IDD_OPENCARD };
	//}}AFX_DATA

	CListCtrl		m_listReader;
	CString			m_szCardName;
	CString			m_szCardStatus;
	LPOPENCARDNAME	m_pOpenCardStruct;
	CImageList		m_imgList;
	int				m_imgNoCard, 
					m_imgHaveCard, 
					m_imgUnavailCard, 
					m_imgReaderUnknown;
	
// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(COpenCardDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual void PostNcDestroy();
	//}}AFX_VIRTUAL

// Implementation
protected:
	//�Ƿ���˶�����(��Ҫ���PCSC)
	BOOL m_bFilterReader;
	//��ǰϵͳ�д��ڵ����ܿ���Ŀ
	int m_nCardNum;
	//������һ�����ܿ�ʱ������Ӧ�Ķ���������
	int	m_nOnlyOneCardListItem;
	//���ڼ������������ܿ��Ĳ��
	UINT m_nTimer;

	//ˢ�¶������б�
	void RefreshReaders();
	int CreateReaderList();
	//�ڶ������б��в���һ����Ŀ
	int InsertReader(LPCTSTR lpszName, int nImgIndex, LPVOID pvData);

	// Generated message map functions
	//{{AFX_MSG(COpenCardDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnDeleteitemReaderList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnItemchangedReaderList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnRefresh();
	afx_msg void OnDestroy();
	virtual void OnOK();
	virtual void OnCancel();
	afx_msg void OnTimer(UINT nIDEvent);
	//}}AFX_MSG
	afx_msg BOOL OnDeviceChange( UINT nEventType, DWORD dwData );
	DECLARE_MESSAGE_MAP()
};

LONG GetOpenCard(LPOPENCARDNAME pOpenCardStruct, BOOL bFilterReader);

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.


#endif // !defined(AFX_OPENCARDDLG_H__9AED5E95_2399_4BF7_964F_AFC225E66559__INCLUDED_)
