
// CSP_Example.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CCSP_ExampleApp:
// �йش����ʵ�֣������ CSP_Example.cpp
//

class CCSP_ExampleApp : public CWinApp
{
public:
	CCSP_ExampleApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CCSP_ExampleApp theApp;