//-------------------------------------------------------------------
//	���ļ�Ϊ TY Cryptographic Service Provider ����ɲ���
//
//
//	��Ȩ���� ������Ϣ��ҵ���޹�˾ (c) 2001 - 2004 ����һ��Ȩ��
//-------------------------------------------------------------------
#ifndef __TYCSP_READER_H__
#define __TYCSP_READER_H__

//���ܿ���Ϣ
typedef struct TOKENINFO{
	CHAR manufacturerID[32];		//�����̵�����
	CHAR label[32];					//Token������
	CHAR model[16];					//Token��ģʽ
	CHAR serialNumber[16];			//Token�����к�
	BYTE pinMaxRetry;				//����Ա���û�PIN��������Դ���
}TOKENINFO, *LPTOKENINFO;

//��д������
enum ReaderType{
	RT_UNKNOWN,
	RT_PCSC,				//PCSC
	RT_USBPORT,				//USB Port
	RT_COMPORT				//Serical Port
};

//���ܿ�����
enum CardType{
	NOCARD,
	CPU_PKI,
	CPU_PKI_SSF33,
};

//��λģʽ
enum ResetMode{COLD, WARM};

//���ܿ��������
typedef ULONG CARDHANDLE;
//�ļ��������
typedef ULONG FILEHANDLE;

//����CPU���е��ļ������Ϊ��ֵ
#define HFILECOS		(~0UL)

/////////////////////////////////////////////////////////////////////
//		Ϊ�˶�CPU���н������ļ�����ά��, �ڿ��н�����һFAT�ļ�, ���ļ�
//	�ṹ����(����MEMORY�����轨�����ļ�,��Ϊ��MEMORY�����ļ�ϵͳ����
//	��ʵ����FAT):
//
//	--------------------------------------------------
//	�汾 1byte | ���ļ��еļ�¼��������������¼��2byte
//	--------------------------------------------------
//	�ļ�id 2byte |	��־ 2byte |	�ļ���С 2byte
//	--------------------------------------------------
//	                        ����
//	--------------------------------------------------
//	                        ����
//	--------------------------------------------------
//
//	�汾��ĿǰΪ3
//	���б�־�ֽڵ��������£�
//	------------------------------------------------------
//	λ	 | B7 | B6 | B5 | B4 | B3 | B2 | B1 | B0          |
//  ��;	 Reserved		 |      AuthId
//	------------------------------------------------------
//	λ	 | B7 | B6 | B5 | B4 | B3 | B2 | B1 | B0          |
//	-------------------------------------------------------
//	��; |      	   type                 | Used/unused |
//	-------------------------------------------------------

#define FILE_USED    					0x01
#define FILE_UNUSED    					0x00

#define FILETYPE_DATA  					(BYTE(0x00<<1))
#define FILETYPE_CERT  					(BYTE(0x01<<1))
#define FILETYPE_SK  					(BYTE(0x02<<1))
#define FILETYPE_PUK  					(BYTE(0x03<<1))
#define FILETYPE_PRK	  				(BYTE(0x04<<1))
#define FILETYPE_PRKEX  				(BYTE(0x05<<1))
#define FILETYPE_PUK_ECC				(BYTE(0x06<<1))
#define FILETYPE_PRK_ECC  				(BYTE(0x07<<1))
#define FILETYPE_PRKEX_ECC				(BYTE(0x08<<1))


//���B2, B3��ȫΪ0,��������ļ�Ҫ��Ȩ��
//���B0, B1��ȫΪ0,�����д�ļ�Ҫ��Ȩ��
#define IS_READ_NEEDAUTH(flag)			((flag) & 0x0C)
#define IS_WRITE_NEEDAUTH(flag)			((flag) & 0x03)
#define SET_READ_NEEDAUTH(flag)			((flag) |= 0x0C)
#define SET_WRITE_NEEDAUTH(flag)		((flag) |= 0x03)

//FAT��ӳ��
#define MAX_FAT_LEN		1024
struct SHARE_FAT{
	BYTE cContent[MAX_FAT_LEN];						//FAT�ļ�������
	DWORD dwTotalLen;								//FAT�ļ��ĳ���
	DWORD dwDataLen;								//FAT�ļ��а������ݵĳ���
};

/////////////////////////////////////////////////////////////////////
//	class CCSPReader
//
class CCSPReader{
//��������������
public:
	CCSPReader();
	~CCSPReader();

//����
private:
	//��Դ�����ľ��(PCSC)
	SCARDCONTEXT	m_hSC;
	//�����
	CARDHANDLE		m_hCard;
	//������������
	CString			m_szName;
	//���ܿ�����
	CardType		m_cardType;
	//��д������
	ReaderType		m_readerType;
	//��д��������(TYKEY��COMPort)
	int				m_nIndex;

//����
protected:
	//������Դ������
	BOOL EstablishContext();
	//�ͷ���Դ������
	BOOL ReleaseContext();

public:
	//��ȡ��д������
	ReaderType GetType() const { return m_readerType; }
	//���ö�д��������
	void SetType(ReaderType type) { m_readerType = type; }
	//��ȡ��д��������
	CString GetName() const { return m_szName; }
	//���ö�д��������
	void SetName(LPCTSTR lpszName) { m_szName = lpszName; }
	//��ȡ��д��������
	int GetIndex() const { return m_nIndex; }
	//���ö�д��������
	void SetIndex(int nIndex);
	//��ȡ���ܿ�����
	CardType GetCardType() const { return m_cardType; }
	//��ȡ���ܿ����
	CARDHANDLE GetCardHandle() const { return m_hCard; }
	
	//��ȡ�ļ�ϵͳ�汾��Ϣ
	BOOL ReadFileSysVer();
	//����ļ�ϵͳ�汾��Ϣ, ����һ����Ϣ�ṹָ��
	void GetFileSysVer(LPCSP_FILESYS_VER pFileSysVer) ;


public:
	//�ж��Ƿ������ܿ�����������
	BOOL IsConnectCard() const { return m_hCard != NULL; }
	//�����ܿ�����
	BOOL ConnectCard(BOOL bCheckCardValid = TRUE);
	//�Ͽ������ܿ�������
	BOOL DisconnectCard();
	//������ܿ��Ƿ񻹴�������״̬
	BOOL CheckCardConnect();
	//����Ƿ�������ܿ�
	BOOL CheckCardIsExist();
	
	//��ʼ����
	BOOL BeginTransaction();
	//��������
	BOOL EndTransaction(DWORD dwDisposition = SCARD_LEAVE_CARD);
	//��λ
	BOOL Reset(BYTE* pbATR, DWORD* pdwATR);
	//��������
	BOOL SendCommand(
		BYTE* pbCommand, 
		DWORD dwCommandLen, 
		BYTE* pbRespond = NULL, 
		DWORD* pdwRespondLen = NULL, 
		WORD* pwStatus = NULL
		);

//���º������ڲ������ܿ��е��ļ�
public:
	//��ȡ���õ��ļ�
	BOOL GetWorkableFile(
		WORD flag,
		DWORD dwSize,
		BYTE path[2]
		);
	//�����ļ�
	BOOL CreateFile(
		BYTE path[2],
		DWORD dwSize,
		FILEHANDLE* phFile,
		BYTE type,
		BYTE readAuth,
		BYTE writeAuth
		);
	//ɾ���ļ�
	BOOL DeleteFile(
		BYTE path[2]
		);
	//���ļ�
	BOOL OpenFile(
		BYTE path[2],
		FILEHANDLE* phFile,
		LPDWORD pdwFileSize = NULL
		);
	//���ļ�
	BOOL ReadFile(
		FILEHANDLE hFile,
		DWORD dwReadLen,
		LPBYTE pReadBuffer,
		LPDWORD pdwRealReadLen,
		DWORD dwOffset = 0
		);
	//д�ļ�
	BOOL WriteFile(
		FILEHANDLE hFile,
		LPBYTE pWriteBuffer,
		DWORD dwWriteBufferLen,
		DWORD dwOffset = 0
		);
	//�ر��ļ�
	BOOL CloseFile(
		FILEHANDLE hFile
		);

//���º������ڵ�¼����
public:
	BOOL Login(
		LPBYTE pPIN,						//PIN��
		DWORD dwPINLen,						//PIN��ĳ���
		DWORD& nRetryCount					//ʣ������ԵĴ���
		);
	BOOL Logout();
	BOOL ChangePIN(
		LPBYTE pNewPIN,						//��PIN
		DWORD dwNewPINLen					//��PIN�ĳ���
		);
public:
	//��ȡTokenInfo
	BOOL GetTokenInfo(
		LPTOKENINFO pTokenInfo
		);
	
	//��ȡӲ�����к�
	BOOL HWReadCardSN(char *szSN, int nMaxLen);

	BOOL cpuRefreshFatFile();
	
//���º���Ϊ��COS����ķ�װ
private:
	//����DF��ʶö��
	enum DF_ID{MF, TYCSP};
	//ѡ��DF�ļ�
	BOOL cpuSelectDF(DF_ID dfId);
	//ѡ��EF�ļ�(���ļ���ʶ����ѡ��)
	BOOL cpuSelectEF(
		BYTE cPath[2],						//�ļ���ʶ 
		BYTE* pbRetData = NULL,				//��Ӧ����
		DWORD* pdwRetDataLen = NULL			//��Ӧ���ݵĳ���
		);
	//����EF�ļ�
	BOOL cpuCreateEF(
		BYTE path[2],						//�ļ���ʶ
		DWORD dwSize,						//�ļ��ߴ�
		BYTE type,							//�ļ�����
		BYTE readAuth,						//��Ȩ��
		BYTE writeAuth,						//дȨ��
		BYTE* pbUseAuth	= NULL				//ʹ��Ȩ��
		);
	//��ȡ��ǰ�ļ��еĶ����Ƽ�¼
	BOOL cpuReadCurrentBinaryFile(
		BYTE* pbData,						//����������
		DWORD dwDataLen,					//���ݵĳ���
		DWORD dwOffset = 0					//�ڵ�ǰ�ļ���ƫ����
		);
	//��ǰ�ļ���д�����Ƽ�¼
	BOOL cpuUpdateCurrentBinaryFile(
		BYTE* pbData,						//д�������
		DWORD dwDataLen,					//���ݵĳ���
		DWORD dwOffset = 0,					//�ڵ�ǰ�ļ���ƫ����
		BOOL bPlain = FALSE				//�Ƿ�ǿ������д
		);
	//��ǰ�ļ������ļ�MACд������
	BOOL cpuUpdateBinaryWithMac(
		BYTE* pbData,						//д�������
		DWORD dwDataLen,					//���ݵĳ���
		DWORD dwOffset = 0					//�ڵ�ǰ�ļ���ƫ����
		);
	//����д����Կ
	BOOL cpuWriteKey(
		LPBYTE pKeyData,					//��Կ����
		DWORD dwKeyDataLen,					//��Կ���ݵĳ���
		BOOL bInstall						//��װ�����޸�
		);

//���º����ͳ�Ա���ڲ���CPU���е�FAT�ļ�
private:
	//CPU����FAT�ļ����ڴ�ӳ��
	SHARE_FAT	m_fileFAT;

	//CSP�ļ�ϵͳ�汾��Ϣ
	CSP_FILESYS_VER m_FileSys;

	//��ʼ��FAT�ļ����ڴ�ӳ��
	BOOL cpuInitFatFile();
	//�ӿ��ж���FAT�ļ�
	BOOL cpuReadFatFile();
	//����һ��FAT����
	BOOL cpuAddFatFileItem(
		BYTE path[2],
		WORD flag,
		DWORD dwSize
		);
	//����ָ���ļ�FAT�����еĵ�ʹ�ñ�־λ
	BOOL cpuSetFileUseableFlag(
		BYTE path[2],
		BOOL bDeleted
		);
	//��ȡ�����ļ�
	BOOL cpuGetWorkableFile(
		WORD flag,
		DWORD dwSize,
		BYTE path[2]
		);

};

#endif