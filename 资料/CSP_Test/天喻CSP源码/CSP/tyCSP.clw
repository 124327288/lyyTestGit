; CLW file contains information for the MFC ClassWizard

[General Info]
Version=1
LastClass=COpenCardDlg
LastTemplate=CDialog
NewFileInclude1=#include "stdafx.h"
NewFileInclude2=#include "tycsp.h"
LastPage=0

ClassCount=4
Class1=CGenKeyPairPromptDlg
Class2=COpenCardDlg
Class3=CTyCSPApp
Class4=VerifyPIN

ResourceCount=3
Resource1=IDD_INPUT_PIN
Resource2=IDD_GENKEYPAIR_PROMPT
Resource3=IDD_OPENCARD

[CLS:CGenKeyPairPromptDlg]
Type=0
BaseClass=CDialog
HeaderFile=GenKeyPairPromptDlg.h
ImplementationFile=GenKeyPairPromptDlg.cpp

[CLS:COpenCardDlg]
Type=0
BaseClass=CDialog
HeaderFile=OpenCardDlg.h
ImplementationFile=OpenCardDlg.cpp
LastObject=COpenCardDlg

[CLS:CTyCSPApp]
Type=0
BaseClass=CWinApp
HeaderFile=tyCSP.h
ImplementationFile=tyCSP.cpp

[CLS:VerifyPIN]
Type=0
BaseClass=CDialog
HeaderFile=VerifyPIN.h
ImplementationFile=VerifyPIN.cpp

[DLG:IDD_GENKEYPAIR_PROMPT]
Type=1
Class=CGenKeyPairPromptDlg
ControlCount=2
Control1=IDC_PROMPT,static,1342308864
Control2=IDC_AVI,SysAnimate32,1342242822

[DLG:IDD_OPENCARD]
Type=1
Class=COpenCardDlg
ControlCount=9
Control1=IDOK,button,1342242817
Control2=IDCANCEL,button,1342242816
Control3=IDC_STATIC1,static,1342308352
Control4=IDC_READER_LIST,SysListView32,1350631436
Control5=IDC_STATIC2,static,1342308352
Control6=IDC_CARD_NAME,edit,1350568068
Control7=IDC_STATIC3,static,1342308352
Control8=IDC_CARD_STATUS,edit,1350567940
Control9=IDC_REFRESH,button,1342242816

[DLG:IDD_INPUT_PIN]
Type=1
Class=VerifyPIN
ControlCount=6
Control1=IDC_PASSWORD,edit,1350631584
Control2=IDOK,button,1342242817
Control3=IDCANCEL,button,1342242816
Control4=IDC_STATIC1,static,1342308352
Control5=IDC_STATIC2,static,1342308352
Control6=IDC_STATIC,static,1342177283

