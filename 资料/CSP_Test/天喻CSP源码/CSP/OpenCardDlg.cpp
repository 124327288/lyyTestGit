// OpenCardDlg.cpp : implementation file
//

#include "stdafx.h"
#include "tyCSP.h"
#include "OpenCardDlg.h"
#include "HelperFunc.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//-------------------------------------------------------------------
//	功能：
//		获取包含指定卡的读卡器的名字
//
//	返回：
//		SCARD_S_SUCCESS:成功; 其它:失败
//
//  参数：
//		LPOPENCARDNAME pOpenCardStruct
//		BOOL bFilterReader
//
//  说明：
//-------------------------------------------------------------------
LONG GetOpenCard(LPOPENCARDNAME pOpenCardStruct, BOOL bFilterReader)
{
	COpenCardDlg dlg(pOpenCardStruct, bFilterReader);
	if(dlg.DoModal() == IDOK)
		return SCARD_S_SUCCESS;
	else
		return SCARD_E_CANCELLED;
}

/////////////////////////////////////////////////////////////////////////////
// COpenCardDlg dialog

//读卡器状态
#define RS_NOCARD					1	//没有智能卡	
#define RS_HAVECARD					2	//包含了智能卡
#define RS_HAVECARD_UNAVAIL			3	//包含了智能卡但不可用
struct ListItemData{
	ReaderType nReaderType;				//读卡器类型
	int nReaderIndex;					//读卡器索引
	int nReaderState;					//读卡器状态
	TOKENINFO tokenInfo;				//包含的智能卡信息
};

COpenCardDlg::COpenCardDlg(LPOPENCARDNAME pOpenCardStruct, BOOL bFilterReader, CWnd* pParent)
	: CDialog(COpenCardDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(COpenCardDlg)
	//}}AFX_DATA_INIT
	m_szCardName = _T("");
	m_szCardStatus = _T("");
	m_pOpenCardStruct = pOpenCardStruct;
	m_nCardNum = 0;
	m_nOnlyOneCardListItem = -1;
	m_bFilterReader = bFilterReader;
	m_nTimer = NULL;
}

//-------------------------------------------------------------------
//	功能：
//		刷新读卡器列表
//
//	返回：
//		无
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
void COpenCardDlg::RefreshReaders()
{
	//关闭已打开的定时器
	if(m_nTimer != NULL){
		KillTimer(m_nTimer);
		m_nTimer = NULL;
	}
	
	//清空显示
	m_listReader.DeleteAllItems();
	m_nCardNum = 0;
	m_nOnlyOneCardListItem = -1;
	m_szCardName = _T("");
	m_szCardStatus = _T("");
	UpdateData(FALSE);

	//刷新各类读卡器列表
	int nReaderNum = CreateReaderList();

	//确定当前被选中的读卡器
	if(m_listReader.GetItemCount() > 0){
		int nSelItem = 0;
		if(m_nCardNum == 1)
			nSelItem = m_nOnlyOneCardListItem;
		UINT itemState = LVIS_SELECTED | LVIS_FOCUSED;
		m_listReader.SetItemState(nSelItem, itemState, itemState);
	}

	//如果存在读卡器则打开定时器
	if(nReaderNum > 0){
		m_nTimer = SetTimer(10, 500, NULL);
	}
}

//-------------------------------------------------------------------
//	功能：
//		创建各类读卡器列表
//
//	返回：
//		读卡器数目
//
//  参数：
//		无
//
//  说明：
//-------------------------------------------------------------------
int COpenCardDlg::CreateReaderList()
{
	//获取当前读卡器的数目
	g_theTYCSPManager.CreateCSPs();
	int nReaderNumber = g_theTYCSPManager.GetCSPCount();

	//插入到读卡器列表中
	for(int i = 0; i < nReaderNumber; i++){
		CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPAt(i);

		//获取读卡器名称
		CHAR szReaderName[MAX_PATH];
		lstrcpy(szReaderName, pCSPObject->GetReaderName());

		//读卡器结点数据
		int nItem;
		ListItemData* data = new ListItemData;
		memset(data, 0, sizeof(ListItemData));
		data->nReaderType = pCSPObject->GetReaderType();
		data->nReaderIndex = i;

		//判断是否存在智能卡
		if(pCSPObject->CheckCardIsExist()){
			data->nReaderState = RS_HAVECARD;

			//判断能否连接智能卡
			if(pCSPObject->Connect()){
				pCSPObject->GetTokenInfo(&(data->tokenInfo));
				nItem = InsertReader(szReaderName, m_imgHaveCard, data);
				m_nCardNum++;

				if(m_nCardNum == 1) 
					m_nOnlyOneCardListItem = nItem;
			}
			else{
				data->nReaderState = RS_HAVECARD_UNAVAIL;
				nItem = InsertReader(szReaderName, m_imgUnavailCard, data);
			}
		}
		else{
			data->nReaderState = RS_NOCARD;
			nItem = InsertReader(szReaderName, m_imgNoCard, data);
		}
	}
	
	return nReaderNumber;
}


//-------------------------------------------------------------------
//	功能：
//		在读卡器列表中插入一个项目
//
//	返回：
//		在列表中的索引
//
//  参数：
//		LPCTSTR lpszName		读卡器名称
//		int nImgIndex			图标索引
//		LPVOID pvData			自定义数据
//
//  说明：
//-------------------------------------------------------------------
int COpenCardDlg::InsertReader(LPCTSTR lpszName, int nImgIndex, LPVOID pvData)
{
	int nItem = m_listReader.InsertItem(
		m_listReader.GetItemCount(), lpszName, nImgIndex
		);
	if(nItem >= 0)
		m_listReader.SetItemData(nItem, (DWORD)pvData);

	return nItem;
}

void COpenCardDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(COpenCardDlg)
	DDX_Control(pDX, IDC_READER_LIST, m_listReader);
	DDX_Text(pDX, IDC_CARD_NAME, m_szCardName);
	DDX_Text(pDX, IDC_CARD_STATUS, m_szCardStatus);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(COpenCardDlg, CDialog)
	//{{AFX_MSG_MAP(COpenCardDlg)
	ON_NOTIFY(LVN_DELETEITEM, IDC_READER_LIST, OnDeleteitemReaderList)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_READER_LIST, OnItemchangedReaderList)
	ON_BN_CLICKED(IDC_REFRESH, OnRefresh)
	ON_WM_DESTROY()
	ON_WM_TIMER()
	//}}AFX_MSG_MAP
	ON_WM_DEVICECHANGE()
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// COpenCardDlg message handlers

BOOL COpenCardDlg::OnInitDialog() 
{
	CDialog::OnInitDialog();
	
	//对话框标题
	CString szCaption;
	szCaption.LoadString(IDS_CS_OCDLG_DLG_CAPTION + g_nRscOffset);
	SetWindowText(szCaption);
	//静态文本1
	szCaption.LoadString(IDS_CS_OCDLG_STC1 + g_nRscOffset);
	GetDlgItem(IDC_STATIC1)->SetWindowText(szCaption);
	//静态文本2
	szCaption.LoadString(IDS_CS_OCDLG_STC2 + g_nRscOffset);
	GetDlgItem(IDC_STATIC2)->SetWindowText(szCaption);
	//静态文本3
	szCaption.LoadString(IDS_CS_OCDLG_STC3 + g_nRscOffset);
	GetDlgItem(IDC_STATIC3)->SetWindowText(szCaption);
	//Refresh按钮
	szCaption.LoadString(IDS_CS_OCDLG_REFRESH + g_nRscOffset);
	GetDlgItem(IDC_REFRESH)->SetWindowText(szCaption);
	//Ok按钮
	szCaption.LoadString(IDS_CS_OCDLG_OK + g_nRscOffset);
	GetDlgItem(IDOK)->SetWindowText(szCaption);
	//Cancel按钮
	szCaption.LoadString(IDS_CS_OCDLG_CANCEL + g_nRscOffset);
	GetDlgItem(IDCANCEL)->SetWindowText(szCaption);
	
	m_imgList.Create(32, 32, ILC_COLOR8, 0, 1);
	m_imgNoCard = m_imgList.Add(AfxGetApp()->LoadIcon(IDI_CARD_NO));
	m_imgHaveCard = m_imgList.Add(AfxGetApp()->LoadIcon(IDI_CARD_HAVE));
	m_imgUnavailCard = m_imgList.Add(AfxGetApp()->LoadIcon(IDI_CARD_UNAVAIL));
	m_imgReaderUnknown = m_imgList.Add(AfxGetApp()->LoadIcon(IDI_READER_UNKNOWN));
	m_listReader.SetImageList(&m_imgList, LVSIL_NORMAL);

	RefreshReaders();

	if(m_nCardNum == 1)
		OnOK();
 
	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}


void COpenCardDlg::PostNcDestroy() 
{
	CDialog::PostNcDestroy();
}

void COpenCardDlg::OnDeleteitemReaderList(NMHDR* pNMHDR, LRESULT* pResult) 
{
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;

	LPVOID pvData = (LPVOID)m_listReader.GetItemData(pNMListView->iItem);
	if(pvData != NULL)
		delete pvData;
	
	*pResult = 0;
}

void COpenCardDlg::OnItemchangedReaderList(NMHDR* pNMHDR, LRESULT* pResult) 
{
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;

	GetDlgItem(IDOK)->EnableWindow(FALSE);
	
	ListItemData* pItemData = (ListItemData* )pNMListView->lParam;
	if(pItemData){
		if(pItemData->nReaderState == RS_HAVECARD){
			GetDlgItem(IDOK)->EnableWindow(TRUE);
			TOKENINFO* pInfo = &(pItemData->tokenInfo);

			m_szCardName = _T("Manufacturer: ");
			m_szCardName += pInfo->manufacturerID;
			m_szCardName += _T("\r\n");

			m_szCardName += _T("Label: ");
			m_szCardName += pInfo->label;
			m_szCardName += _T("\r\n");

			m_szCardName += _T("Model: ");
			m_szCardName += pInfo->model;
			m_szCardName += _T("\r\n");

			m_szCardName += _T("SerialNumber: ");
			char szSn[256] = {0};
			memcpy(szSn, pInfo->serialNumber, sizeof(pInfo->serialNumber));
			m_szCardName += szSn;
			m_szCardName += _T("\r\n");

			m_szCardStatus.LoadString(IDS_CS_OCDLG_CARD_HAVE + g_nRscOffset);
		}
		else if(pItemData->nReaderState == RS_HAVECARD_UNAVAIL){
			m_szCardStatus.LoadString(IDS_CS_OCDLG_CARD_UNAVAIL + g_nRscOffset);
		}
		else if(pItemData->nReaderState == RS_NOCARD){
			m_szCardStatus.LoadString(IDS_CS_OCDLG_CARD_NO + g_nRscOffset);
		}
	}

	UpdateData(FALSE);
	
	*pResult = 0;
}

void COpenCardDlg::OnRefresh() 
{
	RefreshReaders();
}

BOOL COpenCardDlg::OnDeviceChange(UINT nEventType, DWORD dwData)
{
	RefreshReaders();

	return TRUE;
}

void COpenCardDlg::OnDestroy() 
{
	if(m_nTimer != NULL){
		KillTimer(m_nTimer);
		m_nTimer = NULL;
	}

	CDialog::OnDestroy();
}

void COpenCardDlg::OnOK() 
{
	if(m_listReader.GetSelectedCount() == 0)
		return;

	POSITION pos = m_listReader.GetFirstSelectedItemPosition();
	if(pos == NULL)
		return;
	int nSelItem = m_listReader.GetNextSelectedItem(pos);
	m_listReader.GetItemText(
		nSelItem, 0, m_pOpenCardStruct->lpstrRdr, m_pOpenCardStruct->nMaxRdr
		);
	
	CDialog::OnOK();
}

void COpenCardDlg::OnCancel() 
{
	CDialog::OnCancel();
}

void COpenCardDlg::OnTimer(UINT nIDEvent) 
{
	for(int i = 0; i < m_listReader.GetItemCount(); i++){
		CHAR szReaderName[MAX_PATH];
		LVITEM item;
		item.iItem = i;
		item.iSubItem = 0;
		item.pszText = szReaderName;
		item.cchTextMax = sizeof(szReaderName);
		item.mask = LVIF_TEXT | LVIF_PARAM;
		m_listReader.GetItem(&item);
		ListItemData* pItemData = (ListItemData* )item.lParam;
		if(pItemData == NULL)
			continue;

		CTYCSP* pCSPObject = g_theTYCSPManager.GetCSPByReaderName(szReaderName);
		if(pCSPObject == NULL)
			continue;

		BOOL bUpdate = FALSE;

		if(pCSPObject->CheckCardIsExist()){
			//插入了智能卡
			if(pItemData->nReaderState == RS_NOCARD){
				//判断能否连接智能卡
				if(pCSPObject->Connect()){
					pItemData->nReaderState = RS_HAVECARD;
					item.iImage = m_imgHaveCard;

					pCSPObject->GetTokenInfo(&(pItemData->tokenInfo));
				}
				else{
					pItemData->nReaderState = RS_HAVECARD_UNAVAIL;
					item.iImage = m_imgUnavailCard;
				}

				bUpdate = TRUE;
			}
		}
		else{
			//抽出了智能卡
			if(pItemData->nReaderState != RS_NOCARD){
				pItemData->nReaderState = RS_NOCARD;
				item.iImage = m_imgNoCard;

				bUpdate = TRUE;
			}
		}

		//更新结点显示
		if(bUpdate){
			item.mask = LVIF_IMAGE;
			m_listReader.SetItem(&item);
			UINT itemState = LVIS_SELECTED | LVIS_FOCUSED;
			m_listReader.SetItemState(i, itemState, itemState);
		}
	}

	CDialog::OnTimer(nIDEvent);
}
