echo off
cls
!����sigǩ��
"cspSign.exe" s csp.dll csp.sig
cls
echo.
echo ����ǩ�����!!!!!!
echo.

regsvr32 c:\windows\system32\csp.dll
echo.
echo ע��CSP���!!!!!!
echo.
pause
