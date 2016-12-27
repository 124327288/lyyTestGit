// CSPBase.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "Resource.h"

ByteOrderMode g_ByteOrderMode = BOM_BIG_ENDIAN;
BOOL g_bUseReaderIndex = FALSE;

HINSTANCE g_hModule = NULL;

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
	if(ul_reason_for_call == DLL_PROCESS_ATTACH){
		g_hModule = (HINSTANCE)hModule;

		if(!g_theTYCSPManager.Initialize())
			return FALSE;

		g_rng.init();
	}
	else if(ul_reason_for_call == DLL_PROCESS_DETACH){
		g_hModule = NULL;

		g_theTYCSPManager.Finalize();
	}

	return TRUE;
}


///////////////////////////////////////////////////////////////////////////////
//
//	OpenCard Dialog

#include "CommCtrl.h"
#pragma comment(lib, "COMCTL32.LIB")

//选择的读卡器索引
int g_nSelectIndex = -1;
CHAR g_nSelectName[MAX_PATH] = {0};

///////////////////////////////////////////////////////////////////////////////
//
//	对话框内部变量

int m_imgNoCard, m_imgHaveCard, m_imgUnavailCard, m_imgUnknownReader;
HIMAGELIST m_hImgList = NULL;
int m_nCardNum = 0;
int	m_nOnlyOneCardListItem = -1;
UINT m_nTimer = NULL;

///////////////////////////////////////////////////////////////////////////////
//
//	读卡器列表条目自定义数据

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

//刷新读卡器列表
void _RefreshReaders(HWND hDlg);
int _CreateReaderList(HWND hDlg);
int _InsertReader(HWND hDlg, LPCTSTR lpszName, int nImgIndex, LPVOID pvData);
void _SelectReader(HWND hDlg);
VOID CALLBACK _MonitorReaderProc(HWND hwnd, UINT uMsg, UINT idEvent, DWORD dwTime);

BOOL CALLBACK OpenCardDlgProc(HWND hDlg, UINT Message, WPARAM wParam, LPARAM lParam)
{
	switch(Message){
	case WM_INITDIALOG:
		{
			//创建并设置读卡器列表的图像列表
			m_hImgList = ImageList_Create(32, 32, ILC_COLOR8, 0, 1);
			m_imgNoCard = ImageList_AddIcon(m_hImgList, 
				LoadIcon(g_hModule, MAKEINTRESOURCE(IDI_CARD_NO)));
			m_imgHaveCard = ImageList_AddIcon(m_hImgList, 
				LoadIcon(g_hModule, MAKEINTRESOURCE(IDI_CARD_HAVE)));
			m_imgUnavailCard = ImageList_AddIcon(m_hImgList, 
				LoadIcon(g_hModule, MAKEINTRESOURCE(IDI_CARD_UNAVAIL)));
			m_imgUnknownReader = ImageList_AddIcon(m_hImgList, 
				LoadIcon(g_hModule, MAKEINTRESOURCE(IDI_READER_UNKNOWN)));
			HWND hCtrl = GetDlgItem(hDlg, IDC_READER_LIST);
			ListView_SetImageList(hCtrl, m_hImgList, LVSIL_NORMAL);
			
			//刷新读卡器列表
			_RefreshReaders(hDlg);
			if(m_nCardNum == 1){
				_SelectReader(hDlg);
			}
		}
		break;
	case WM_DESTROY:
		{
			if(m_hImgList == NULL){
				ImageList_Destroy(m_hImgList);
				m_hImgList = NULL;
			}

			if(m_nTimer != NULL){
				KillTimer(hDlg, m_nTimer);
				m_nTimer = NULL;
			}
		}
		break;
	case WM_NOTIFY:
		{
			switch(((LPNMHDR)lParam)->code) {
				case LVN_DELETEITEM:
					{
						NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)lParam;
						LPVOID pvData = (LPVOID)pNMListView->lParam;
						if(pvData != NULL)
							delete pvData;
					}
					break;
				case LVN_ITEMCHANGED:
					{
						EnableWindow(GetDlgItem(hDlg, IDOK), FALSE);

						CHAR szTokenInfo[MAX_PATH] = {0};
						CHAR szTokenStatus[MAX_PATH] = {0};

						NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)lParam;
						ListItemData* pItemData = (ListItemData* )pNMListView->lParam;
						if(pItemData){
							if(pItemData->nReaderState == RS_HAVECARD){
								EnableWindow(GetDlgItem(hDlg, IDOK), TRUE);
								TOKENINFO* pInfo = &(pItemData->tokenInfo);

								lstrcpy(szTokenInfo, "制造商：");
								lstrcat(szTokenInfo, pInfo->manufacturerID);
								lstrcat(szTokenInfo, "\r\n");

								lstrcat(szTokenInfo, "标签：");
								lstrcat(szTokenInfo, pInfo->label);
								lstrcat(szTokenInfo, "\r\n");

								lstrcat(szTokenInfo, "模式：");
								lstrcat(szTokenInfo, pInfo->model);
								lstrcat(szTokenInfo, "\r\n");

								lstrcat(szTokenInfo, "序列号：");
								lstrcat(szTokenInfo, pInfo->serialNumber);
								lstrcat(szTokenInfo, "\r\n");

								lstrcpy(szTokenStatus, _T("智能卡可以使用"));
							}
							else if(pItemData->nReaderState == RS_HAVECARD_UNAVAIL){
								lstrcpy(szTokenStatus, _T("智能卡无法被使用"));
							}
							else if(pItemData->nReaderState == RS_NOCARD){
								lstrcpy(szTokenStatus, _T("没有智能卡"));
							}
						}

						SetDlgItemText(hDlg, IDC_CARD_NAME, szTokenInfo);
						SetDlgItemText(hDlg, IDC_CARD_STATUS, szTokenStatus);
					}
					break;
			}
		}
		break;
	case WM_COMMAND:
		{
			WORD wCmd = LOWORD(wParam);
			if(wCmd == IDOK)
			{
				_SelectReader(hDlg);
			}
			else if(wCmd == IDCANCEL)
			{
				EndDialog(hDlg, IDCANCEL);
			}
			else if(wCmd == IDC_REFRESH)
			{
				_RefreshReaders(hDlg);
			}
		}
	case WM_DEVICECHANGE:
		{
			_RefreshReaders(hDlg);
		}
		break;
	default:
		return FALSE;
	}

	return TRUE;
}

void _RefreshReaders(HWND hDlg)
{
	//关闭已打开的定时器
	if(m_nTimer != NULL){
		KillTimer(hDlg, m_nTimer);
		m_nTimer = NULL;
	}

	//清空显示
	HWND hListCtrl = GetDlgItem(hDlg, IDC_READER_LIST);
	ListView_DeleteAllItems(hListCtrl);
	m_nCardNum = 0;
	m_nOnlyOneCardListItem = -1;

	SetDlgItemText(hDlg, IDC_CARD_NAME, _T(""));
	SetDlgItemText(hDlg, IDC_CARD_STATUS, _T(""));

	//刷新各类读卡器列表
	int nReaderNum = _CreateReaderList(hDlg);

	//确定当前被选中的读卡器
	if(ListView_GetItemCount(hListCtrl)){
		int nSelItem = 0;
		if(m_nCardNum == 1)
			nSelItem = m_nOnlyOneCardListItem;
		UINT itemState = LVIS_SELECTED | LVIS_FOCUSED;
		ListView_SetItemState(hListCtrl, nSelItem, itemState, itemState);
	}

	//如果存在读卡器则打开定时器
	if(nReaderNum > 0){
		m_nTimer = SetTimer(hDlg, 10, 500, _MonitorReaderProc);
	}
}

int _CreateReaderList(HWND hDlg)
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
		if(g_bUseReaderIndex)
			data->nReaderIndex = pCSPObject->GetReaderIndex();
		else
			data->nReaderIndex = i;

		//判断是否存在智能卡
		if(pCSPObject->CheckCardIsExist()){
			data->nReaderState = RS_HAVECARD;

			//判断能否连接智能卡
			if(pCSPObject->Connect(TRUE)){
				pCSPObject->GetTokenInfo(&(data->tokenInfo));
				nItem = _InsertReader(hDlg, szReaderName, m_imgHaveCard, data);
				m_nCardNum++;

				if(m_nCardNum == 1) 
					m_nOnlyOneCardListItem = nItem;
			}
			else{
				data->nReaderState = RS_HAVECARD_UNAVAIL;
				nItem = _InsertReader(hDlg, szReaderName, m_imgUnavailCard, data);
			}
		}
		else{
			data->nReaderState = RS_NOCARD;
			nItem = _InsertReader(hDlg, szReaderName, m_imgNoCard, data);
		}
	}
	
	return nReaderNumber;
}

int _InsertReader(HWND hDlg, LPCTSTR lpszName, int nImgIndex, LPVOID pvData)
{
	HWND hListCtrl = GetDlgItem(hDlg, IDC_READER_LIST);

	LVITEM item;
	item.iItem = ListView_GetItemCount(hListCtrl);
	item.iSubItem = 0;
	item.mask = LVIF_IMAGE | LVIF_PARAM | LVIF_TEXT;
	item.iImage = nImgIndex;
	item.lParam = (LPARAM)pvData;
	item.pszText = (LPSTR)lpszName;

	return ListView_InsertItem(hListCtrl, &item);
}

void _SelectReader(HWND hDlg)
{
	HWND hListCtrl = GetDlgItem(hDlg, IDC_READER_LIST);
	if(ListView_GetSelectedCount(hListCtrl) == 0)
		return;

	LVITEM item;
	item.iItem = ListView_GetNextItem(hListCtrl, -1, LVNI_SELECTED);
	item.iSubItem = 0;
	item.mask = LVIF_PARAM | LVIF_TEXT;
	item.pszText = g_nSelectName;
	item.cchTextMax = sizeof(g_nSelectName);
	ListView_GetItem(hListCtrl, &item);

	ListItemData* pItemData = (ListItemData* )(item.lParam);
	if(pItemData != NULL){
		g_nSelectIndex = pItemData->nReaderIndex;
		EndDialog(hDlg, IDOK);
	}
}

VOID CALLBACK _MonitorReaderProc(HWND hwnd, UINT uMsg, UINT idEvent, DWORD dwTime)
{
	HWND hListCtrl = GetDlgItem(hwnd, IDC_READER_LIST);
	int nReaderCount = ListView_GetItemCount(hListCtrl);
	for(int i = 0; i < nReaderCount; i++){
		CHAR szReaderName[MAX_PATH];
		LVITEM item;
		item.iItem = i;
		item.iSubItem = 0;
		item.pszText = szReaderName;
		item.cchTextMax = sizeof(szReaderName);
		item.mask = LVIF_TEXT | LVIF_PARAM;
		ListView_GetItem(hListCtrl, &item);
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
				if(pCSPObject->Connect(TRUE)){
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

		if(bUpdate){
			item.mask = LVIF_IMAGE;
			ListView_SetItem(hListCtrl, &item);
			UINT itemState = LVIS_SELECTED | LVIS_FOCUSED;
			ListView_SetItemState(hListCtrl, i, itemState, itemState);
		}
	}
}

//获取选择的读卡器名称或索引
int SelectSmartCardReader(CHAR* szReaderName)
{
	int nResult = DialogBox(
		g_hModule, MAKEINTRESOURCE(IDD_OPENCARD), NULL, OpenCardDlgProc
		);
	if(IDOK == nResult){
		if(szReaderName) 
			lstrcpy(szReaderName, g_nSelectName);

		return g_nSelectIndex;
	}
	else
		return -1;
}

