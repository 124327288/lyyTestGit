echo off
cls
!����sigǩ��
"cspSign.exe" s csp.dll csp.sig
cls
echo.
echo ����ǩ�����!!!@!!!
echo.
pause

regsvr32 c:\windows\system32\csp.dll
