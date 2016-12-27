#ifndef _DBGOUT_INCLUDED_
#define _DBGOUT_INCLUDED_

#include "tchar.h"

//
//调试窗口的名字，不能改动
//
static TCHAR tszWindowName[] = _T("TRACE WINDOW");
static TCHAR tszClassName[] =  _T("TRACE WINDOW");

inline void DbgOutA(LPCSTR p, LPCTSTR lpszWindowName, LPCTSTR lpszClassName)
{
	//
	//保留原ERROR值，因为调用FindWindow可能会产生一个ERROR
	//
	DWORD dwError = GetLastError();

    HWND hWnd = ::FindWindow (lpszClassName, lpszWindowName); 
    if (hWnd)
    {  
		COPYDATASTRUCT cd;
        cd.dwData = 0;
        cd.cbData = (strlen(p)+1)*sizeof(char);
        cd.lpData = (void *)p; 
        ::SendMessage (hWnd, WM_COPYDATA, 0, (LPARAM)&cd);  
    } 

	//
	//恢复原ERROR值，屏蔽调用FindWindow时可能产生的ERROR
	//
	SetLastError(dwError);
}

inline void DbgOutW(LPCWSTR p, LPCTSTR lpszWindowName, LPCTSTR lpszClassName)
{
	//
	//保留原ERROR值，因为调用FindWindow可能会产生一个ERROR
	//
	DWORD dwError = GetLastError();

    HWND hWnd = ::FindWindow (lpszClassName, lpszWindowName); 
    if (hWnd)
    {  
		COPYDATASTRUCT cd; 
        cd.dwData = 0xFEFF;
        cd.cbData = (wcslen(p)+1)*sizeof(wchar_t);
        cd.lpData = (void *)p; 
        ::SendMessage (hWnd, WM_COPYDATA, 0, (LPARAM)&cd);  
    } 
	
	//
	//恢复原ERROR值，屏蔽调用FindWindow时可能产生的ERROR
	//
	SetLastError(dwError);
}

inline void DbgOut(LPCTSTR pFormat, ...)
{
	va_list args;
	va_start(args, pFormat);

    TCHAR buffer [1024*sizeof(TCHAR)];
	wvsprintf(buffer, pFormat, args);

//	FILE* fp = fopen("c:\\trace.txt", "at");
//	if(fp){
//		fprintf(fp, buffer);
//		fclose(fp);
//	}

	int nIndex = 0;
	TCHAR szWindowName[MAX_PATH];
	TCHAR szClassName[MAX_PATH];
	wsprintf(szWindowName, "%s %d", tszWindowName, nIndex);
	wsprintf(szClassName, "%s %d", tszClassName, nIndex);

    #ifdef UNICODE
    DbgOutW(buffer, szWindowName, szClassName);
    #else
    DbgOutA(buffer, szWindowName, szClassName);
    #endif

    va_end(args);
}

inline DWORD DbgOutLastError (LPCTSTR pFormat, ...)
{
   if (::GetLastError() == 0) 
        return 0;
   
	va_list args;
	va_start(args, pFormat);

    TCHAR buffer [1024*sizeof(TCHAR)];
	wvsprintf(buffer, pFormat, args);

    LPVOID pMessage;
    DWORD  result;
    result = ::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                             NULL,
                             GetLastError(),
                             MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED),
                             (LPTSTR)&pMessage,
                             0,
                             NULL);
  
    lstrcat (buffer, _T(" : "));
	if(result == 0)
		lstrcat(buffer, _T("Can't find the error message"));
	else
		lstrcat (buffer, (TCHAR*)pMessage);
    
    ::DbgOut(buffer);
    
    if(result)
        ::LocalFree(pMessage);
   
    va_end(args);
    return result;
}

inline DWORD DbgOutError(DWORD dwError)
{
    TCHAR buffer [1024*sizeof(TCHAR)];
	sprintf(buffer, _T("Error Code = %08X  Description = "), dwError);
	
    LPVOID pMessage;
    DWORD  result;
    result = ::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                             NULL,
                             dwError,
                             MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED),
                             (LPTSTR)&pMessage,
                             0,
                             NULL);
  
	if(result == 0)
		lstrcat(buffer, _T("Can't find the error message"));
	else
		lstrcat (buffer, (TCHAR*)pMessage);
    
    ::DbgOut(buffer);
    
    if(result)
        ::LocalFree(pMessage);

	return result;
}



#ifdef _TRACE_INFO
#define TRACE_LINE				::DbgOut
#define TRACE_LASTERROR			::DbgOutLastError
#define TRACE_ERROR				::DbgOutError
#else
#define TRACE_LINE				(void(0))
#define TRACE_LASTERROR			(void(0))
#define TRACE_ERROR				(void(0))
#endif


#ifdef _TRACE_INFO
class CTraceFunction{
private:
	TCHAR*	m_szFunctionName;
public:
	CTraceFunction(LPCTSTR lpszFunctionName)
	{
		m_szFunctionName = NULL;

		if(lpszFunctionName){
			int nLen = _tcslen(lpszFunctionName) + 1;
			m_szFunctionName = new TCHAR[nLen];
			if(m_szFunctionName)
				memcpy(m_szFunctionName, lpszFunctionName, nLen);
		}

		if(m_szFunctionName){
			TRACE_LINE("\n============================================\n");
			TRACE_LINE("Enter Function: %s\n", m_szFunctionName);
		}
	}

	~CTraceFunction()
	{
		if(m_szFunctionName){
			TRACE_LINE("\nExit Function: %s\n", m_szFunctionName);
			TRACE_LINE("============================================\n");
			delete m_szFunctionName;
		}
	}
};

#define TRACE_FUNCTION(szFuncName); \
	CTraceFunction tf(szFuncName); \
	
#define TRACE_DATA(pbData, dwDataLen);\
{\
	if(pbData != NULL){\
		for(DWORD i = 0; i < dwDataLen; i++)\
			TRACE_LINE("%02x ", pbData[i]);\
		TRACE_LINE("\n");\
	}\
}\

#define TRACE_RESULT(bRetVal); \
{ \
	if(bRetVal == TRUE) \
		TRACE_LINE("\nFunction execute success!\n"); \
	else \
		TRACE_LINE("\nFunction execute fail!\n"); \
} \

#else

#define TRACE_FUNCTION(szFuncName); 
#define TRACE_DATA(pbData, dwDataLen);
#define TRACE_RESULT(bRetVal);

#endif

#endif
