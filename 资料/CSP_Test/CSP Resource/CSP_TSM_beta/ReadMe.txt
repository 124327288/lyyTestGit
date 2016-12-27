创建csp环境流程：
1〉选择在windowsXP SP2 中建立csp环境，需安装TSM；

2〉因csp需要签名认证，所以将"advapi32.dll"替换到"c:\windows\system32"目录下。注意这里最好是在安全模式下进行替换。其中主要的dos操作命令如下:
	·1 将"advapi32.dll"拷贝至C盘根目录下；
	·2 dos命令中 
	cd c:\windows\system32
	expand advapi32.dll advapi32.dll__
	copy c:\advapi32.dll 

3> 将 "csp.dll"、"csp.sig"、和"cspSign.exe" ， 放于"c:\windows\system32"下，运"Install CspDll.bat"，将"csp.dll"注册到注册表中。

4> 运行"Install CspDll.bat",csp环境搭建完毕，运行 "testcsp.exe" 即可。

文件清单：
csp.dll
csp.sig 
cspSign.exe 
advapi32.dll 
testcsp.exe 
Install CspDll.bat
