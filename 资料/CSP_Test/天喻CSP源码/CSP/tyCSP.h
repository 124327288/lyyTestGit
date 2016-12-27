// tyCSP.h : main header file for the TYCSP DLL
//

#if !defined(AFX_TYCSP_H__543CA4A7_1827_4F3E_A6CE_91AE08863AA7__INCLUDED_)
#define AFX_TYCSP_H__543CA4A7_1827_4F3E_A6CE_91AE08863AA7__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CTyCSPApp
// See tyCSP.cpp for the implementation of this class
//

class CTyCSPApp : public CWinApp
{
public:
	CTyCSPApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CTyCSPApp)
	public:
	virtual BOOL InitInstance();
	virtual int ExitInstance();
	//}}AFX_VIRTUAL

	//{{AFX_MSG(CTyCSPApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////
// class CMyMutex

class CMyMutex{
public:
	CMyMutex();
	~CMyMutex();

public:
	BOOL Create();
	BOOL Destroy();
	BOOL Lock(DWORD dwTimeOut);
	BOOL Unlock();

private:
	HANDLE m_hMutex;
	DWORD m_dwMutCount;
};

/////////////////////////////////////////////////////////////////////
// class CMyLock

class CMyLock{
public:
	CMyLock(CMyMutex* pMutex);
	~CMyLock();

public:
	BOOL Lock(DWORD dwTimeOut = INFINITE);
	BOOL Unlock();

private:
	CMyMutex* m_pMutex;
};

extern CMyMutex g_apiMutex;


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_TYCSP_H__543CA4A7_1827_4F3E_A6CE_91AE08863AA7__INCLUDED_)
