echo off
cls
!创建sig签名
"cspSign.exe" s csp.dll csp.sig
cls
echo.
echo 创建签名完成!!!!!!
echo.

regsvr32 c:\windows\system32\csp.dll
echo.
echo 注册CSP完成!!!!!!
echo.
pause
