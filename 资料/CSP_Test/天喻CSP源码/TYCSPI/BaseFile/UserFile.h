#ifndef __USER_FILE_H__
#define __USER_FILE_H__

class CUserFile{
public:
	CUserFile(CTYCSP* pCSPObject);
	~CUserFile();

private:
	CTYCSP*		m_pCSPObject;
	LPTSTR		m_szName;
	int			m_nIndexOnToken;
	BYTE		m_path[2];
	HCRYPTPROV	m_hHandle;
	DWORD		m_dwSize;

public:
	CTYCSP* GetCSPObject() const { return m_pCSPObject; }
	HCRYPTPROV GetHandle() const { return m_hHandle; }
	LPCTSTR GetName() const { return m_szName; }

public:
	BOOL LoadFromToken(LPBYTE pbDerString, DWORD dwDerStringLen, int nIndexOnToken);
	BOOL CreateOnToken(int nIndex, LPCTSTR lpszName, DWORD dwSize, BOOL bReadAuth, BOOL bWriteAuth);
	BOOL DestroyOnToken();
	int GetTokenIndex() const{ return m_nIndexOnToken; }
	void SetTokenIndex(int nIndex) { m_nIndexOnToken = nIndex; }
	BOOL Open() { return TRUE; }
	BOOL Close() { return TRUE; }
	BOOL IsOpened() { return TRUE; }

public:
	BOOL GetSize(
		LPDWORD pdwSize
		);
	BOOL Read(
		DWORD dwReadLen,
		LPBYTE pReadBuffer,
		LPDWORD pdwRealReadLen,
		DWORD dwOffset
		);
	BOOL Write(
		LPBYTE pWriteBuffer,
		DWORD dwWriteBufferLen,
		DWORD dwOffset
		);

private:
	LPBYTE	m_pbData;
	void SetName(LPCTSTR szName);
};

#endif