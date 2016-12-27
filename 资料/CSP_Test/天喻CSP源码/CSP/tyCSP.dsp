# Microsoft Developer Studio Project File - Name="tyCSP" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=tyCSP - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "tyCSP.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "tyCSP.mak" CFG="tyCSP - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "tyCSP - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "tyCSP - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""$/TY CSP/DLL", ZQAAAAAA"
# PROP Scc_LocalPath "."
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "tyCSP - Win32 Release"

# PROP BASE Use_MFC 5
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 5
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_WINDLL" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I ".\Inc\Crypto" /I ".\Inc\Common" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "_WINDLL" /FR /Yu"stdafx.h" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x804 /d "NDEBUG"
# ADD RSC /l 0x804 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 /nologo /subsystem:windows /dll /machine:I386 /libpath:".\lib"
# Begin Special Build Tool
SOURCE="$(InputPath)"
PostBuild_Cmds=move         /Y                         %WINDIR%\system32\tycsp.dll           D:     	copy                          .\Release\tycsp.dll                          %WINDIR%\system32\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "tyCSP - Win32 Debug"

# PROP BASE Use_MFC 5
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 5
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_WINDLL" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I ".\Inc\Crypto" /I ".\inc\common" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "_WINDLL" /FR /Yu"stdafx.h" /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x804 /d "_DEBUG"
# ADD RSC /l 0x804 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept /libpath:".\lib"
# Begin Special Build Tool
SOURCE="$(InputPath)"
PostBuild_Desc=copy                          .\debug\tycsp.dll                          %WINDIR%\system32\ 
PostBuild_Cmds=move         /Y                         %WINDIR%\system32\tycsp.dll           D:        	copy                          .\debug\tycsp.dll                          %WINDIR%\system32\ 
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "tyCSP - Win32 Release"
# Name "tyCSP - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\CryptSPI.cpp
# End Source File
# Begin Source File

SOURCE=.\CSPAsymmetricalKey.cpp
# End Source File
# Begin Source File

SOURCE=.\CSPDes.cpp
# End Source File
# Begin Source File

SOURCE=.\CSPEccPrk.cpp
# End Source File
# Begin Source File

SOURCE=.\CSPEccPuk.cpp
# End Source File
# Begin Source File

SOURCE=.\CSPKey.cpp
# End Source File
# Begin Source File

SOURCE=.\CSPObject.cpp
# End Source File
# Begin Source File

SOURCE=.\CSPRc2Key.cpp
# End Source File
# Begin Source File

SOURCE=.\CSPRc4Key.cpp
# End Source File
# Begin Source File

SOURCE=.\CSPRsaPrk.cpp
# End Source File
# Begin Source File

SOURCE=.\CSPRsaPuk.cpp
# End Source File
# Begin Source File

SOURCE=.\CSPSCB2.cpp
# End Source File
# Begin Source File

SOURCE=.\CSPSSF33.cpp
# End Source File
# Begin Source File

SOURCE=.\CSPSymmetricalKey.cpp
# End Source File
# Begin Source File

SOURCE=.\DERCoding.cpp
# End Source File
# Begin Source File

SOURCE=.\DERTool.cpp
# End Source File
# Begin Source File

SOURCE=.\GenKeyPairPromptDlg.cpp
# End Source File
# Begin Source File

SOURCE=.\HashObject.cpp
# End Source File
# Begin Source File

SOURCE=.\HelperFunc.cpp
# End Source File
# Begin Source File

SOURCE=.\KeyContainer.cpp
# End Source File
# Begin Source File

SOURCE=.\Mac.CPP
# End Source File
# Begin Source File

SOURCE=.\Modifier.cpp
# End Source File
# Begin Source File

SOURCE=.\OpenCardDlg.cpp
# End Source File
# Begin Source File

SOURCE=.\Reader.cpp
# End Source File
# Begin Source File

SOURCE=.\scb2.cpp
# End Source File
# Begin Source File

SOURCE=.\ssf33.cpp
# End Source File
# Begin Source File

SOURCE=.\StdAfx.cpp
# ADD CPP /Yc"stdafx.h"
# End Source File
# Begin Source File

SOURCE=.\tyCSP.cpp
# End Source File
# Begin Source File

SOURCE=.\tyCSP.def
# End Source File
# Begin Source File

SOURCE=.\tyCSP.rc
# End Source File
# Begin Source File

SOURCE=.\VerifyPIN.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\ArrayTmpl.h
# End Source File
# Begin Source File

SOURCE=.\CardTrans.h
# End Source File
# Begin Source File

SOURCE=.\CryptSPI.h
# End Source File
# Begin Source File

SOURCE=.\CSPAfx.h
# End Source File
# Begin Source File

SOURCE=.\cspkey.h
# End Source File
# Begin Source File

SOURCE=.\CSPObject.h
# End Source File
# Begin Source File

SOURCE=.\DbgOut.h
# End Source File
# Begin Source File

SOURCE=.\DERCoding.h
# End Source File
# Begin Source File

SOURCE=.\DERTool.h
# End Source File
# Begin Source File

SOURCE=.\Ecc.h
# End Source File
# Begin Source File

SOURCE=.\GenKeyPairPromptDlg.h
# End Source File
# Begin Source File

SOURCE=.\GlobalVars.h
# End Source File
# Begin Source File

SOURCE=.\HashObject.h
# End Source File
# Begin Source File

SOURCE=.\HelperFunc.h
# End Source File
# Begin Source File

SOURCE=.\KeyContainer.h
# End Source File
# Begin Source File

SOURCE=.\Mac.H
# End Source File
# Begin Source File

SOURCE=.\Modifier.h
# End Source File
# Begin Source File

SOURCE=.\OpenCardDlg.h
# End Source File
# Begin Source File

SOURCE=.\Reader.h
# End Source File
# Begin Source File

SOURCE=.\Resource.h
# End Source File
# Begin Source File

SOURCE=.\scb2.h
# End Source File
# Begin Source File

SOURCE=.\sf33.h
# End Source File
# Begin Source File

SOURCE=.\StdAfx.h
# End Source File
# Begin Source File

SOURCE=.\tyCSP.h
# End Source File
# Begin Source File

SOURCE=.\VerifyPIN.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=.\res\havecard.ico
# End Source File
# Begin Source File

SOURCE=.\res\ic.ico
# End Source File
# Begin Source File

SOURCE=.\res\nocard.ico
# End Source File
# Begin Source File

SOURCE=.\res\readerunknown.ico
# End Source File
# Begin Source File

SOURCE=.\res\tyCSP.rc2
# End Source File
# Begin Source File

SOURCE=.\res\unavailcard.ico
# End Source File
# Begin Source File

SOURCE=.\res\W95mbx04.ico
# End Source File
# End Group
# Begin Source File

SOURCE=.\res\keypair.avi
# End Source File
# End Target
# End Project
