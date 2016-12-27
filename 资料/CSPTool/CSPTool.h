// CSPTool.h : main header file for the CSPTOOL application
//

#if !defined(AFX_CSPTOOL_H__2DEC95E0_CA5C_49DC_8C6B_0FE6AE7CA404__INCLUDED_)
#define AFX_CSPTOOL_H__2DEC95E0_CA5C_49DC_8C6B_0FE6AE7CA404__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CCSPToolApp:
// See CSPTool.cpp for the implementation of this class
//

class CCSPToolApp : public CWinApp
{
public:
	CCSPToolApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CCSPToolApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CCSPToolApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_CSPTOOL_H__2DEC95E0_CA5C_49DC_8C6B_0FE6AE7CA404__INCLUDED_)
