# Microsoft Developer Studio Project File - Name="tycspi" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=tycspi - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "tycspi.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "tycspi.mak" CFG="tycspi - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "tycspi - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "tycspi - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""$/tycspi", ULBAAAAA"
# PROP Scc_LocalPath "."
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "tycspi - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CSPBASE_EXPORTS" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I ".\Inc\Crypto" /I ".\Inc\Common" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CSPBASE_EXPORTS" /FR /Yu"stdafx.h" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x804 /d "NDEBUG"
# ADD RSC /l 0x804 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /out:"./release/tycspi.dll" /libpath:".\Lib"

!ELSEIF  "$(CFG)" == "tycspi - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CSPBASE_EXPORTS" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I ".\Inc\Crypto" /I ".\Inc\Common" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CSPBASE_EXPORTS" /FR /Yu"stdafx.h" /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x804 /d "_DEBUG"
# ADD RSC /l 0x804 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /def:".\tycspi.def" /implib:"Debug/tycspid.lib" /pdbtype:sept /libpath:".\Lib"
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
SOURCE="$(InputPath)"
PostBuild_Cmds=copy  .\debug\tycspi.dll  C:
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "tycspi - Win32 Release"
# Name "tycspi - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\tycspi.cpp
# End Source File
# Begin Source File

SOURCE=.\tycspi.def

!IF  "$(CFG)" == "tycspi - Win32 Release"

!ELSEIF  "$(CFG)" == "tycspi - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\tycspi.rc
# End Source File
# End Group
# Begin Group "BaseFiles"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\BaseFile\ArrayTmpl.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CryptSPI.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CryptSPI.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPAfx.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPAsymmetricalKey.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPDes.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPEccPrk.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPEccPuk.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPKey.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\Cspkey.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPObject.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPObject.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPRc2Key.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPRc4Key.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPRsaPrk.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPRsaPuk.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPSCB2.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPSSF33.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\CSPSymmetricalKey.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\DbgOut.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\DERCoding.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\DERCoding.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\DERTool.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\DERTool.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\Ecc.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\GlobalVars.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\HashObject.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\HashObject.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\HelperFunc.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\HelperFunc.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\KeyContainer.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\KeyContainer.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\Mac.CPP
# End Source File
# Begin Source File

SOURCE=.\BaseFile\Mac.H
# End Source File
# Begin Source File

SOURCE=.\BaseFile\Modifier.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\Modifier.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\Reader.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\Reader.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\Reader2.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\scb2.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\scb2.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\sf33.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\ssf33.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\StdAfx.cpp
# ADD CPP /Yc"stdafx.h"
# End Source File
# Begin Source File

SOURCE=.\BaseFile\StdAfx.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\Support.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\Support.h
# End Source File
# Begin Source File

SOURCE=.\BaseFile\UserFile.cpp
# End Source File
# Begin Source File

SOURCE=.\BaseFile\UserFile.h
# End Source File
# End Group
# Begin Group "Include Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\RESOURCE.H
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\res\havecard.ico
# End Source File
# Begin Source File

SOURCE=.\res\nocard.ico
# End Source File
# Begin Source File

SOURCE=.\res\readerunknown.ico
# End Source File
# Begin Source File

SOURCE=.\res\unavailcard.ico
# End Source File
# End Group
# Begin Source File

SOURCE=.\BaseFile\CardTrans.h
# End Source File
# Begin Source File

SOURCE=.\ReadMe.txt
# End Source File
# Begin Source File

SOURCE=.\BaseFile\TYKeyInt.h
# End Source File
# End Target
# End Project
