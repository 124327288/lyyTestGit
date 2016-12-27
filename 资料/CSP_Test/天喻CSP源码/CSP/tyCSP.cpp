// tyCSP.cpp : Defines the initialization routines for the DLL.
//

#include "stdafx.h"
#include "tyCSP.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//
//	Note!
//
//		If this DLL is dynamically linked against the MFC
//		DLLs, any functions exported from this DLL which
//		call into MFC must have the AFX_MANAGE_STATE macro
//		added at the very beginning of the function.
//
//		For example:
//
//		extern "C" BOOL PASCAL EXPORT ExportedFunction()
//		{
//			AFX_MANAGE_STATE(AfxGetStaticModuleState());
//			// normal function body here
//		}
//
//		It is very important that this macro appear in each
//		function, prior to any calls into MFC.  This means that
//		it must appear as the first statement within the 
//		function, even before any object variable declarations
//		as their constructors may generate calls into the MFC
//		DLL.
//
//		Please see MFC Technical Notes 33 and 58 for additional
//		details.
//

/////////////////////////////////////////////////////////////////////////////
// CTyCSPApp

BEGIN_MESSAGE_MAP(CTyCSPApp, CWinApp)
	//{{AFX_MSG_MAP(CTyCSPApp)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CTyCSPApp construction

CTyCSPApp::CTyCSPApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CTyCSPApp object

CTyCSPApp theApp;

UINT g_nRscOffset = 0;

CMyMutex g_apiMutex;

BOOL CTyCSPApp::InitInstance() 
{
	// TODO: Add your specialized code here and/or call the base class
	TRACE_FUNCTION("CTyCSPApp::InitInstance");


	if(!g_theTYCSPManager.Initialize())
		return FALSE;

	g_rng.init();
	
	//确定显示何种语言,目前支持简体中文、繁体中文和英文
	LANGID DefaultSystemLangId = GetSystemDefaultLangID();
	if(PRIMARYLANGID(DefaultSystemLangId) == LANG_CHINESE){
		if(SUBLANGID(DefaultSystemLangId) == SUBLANG_CHINESE_SIMPLIFIED ||
			SUBLANGID(DefaultSystemLangId) == SUBLANG_CHINESE_SINGAPORE)
			g_nRscOffset = 0;	//简体中文
		else
			g_nRscOffset = 100;	//繁体中文
	}
	else
		g_nRscOffset = 200;		//英文

	return CWinApp::InitInstance();
}

int CTyCSPApp::ExitInstance() 
{
	// TODO: Add your specialized code here and/or call the base class
	TRACE_FUNCTION("CTyCSPApp::ExitInstance");

	if(!g_theTYCSPManager.Finalize())
		return FALSE;

	
	return CWinApp::ExitInstance();
}
