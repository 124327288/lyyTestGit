#ifndef __TYCSP_READER_H__
#define __TYCSP_READER_H__

//����������
enum ReaderType{
	RT_USBPORT = 0,					//USB Port
	RT_COMPORT,						//Serical Port
	RT_PCSC,						//PCSC
	RT_UNKNOWN,						//δ֪����
};

//���ܿ�����
enum CardType{
	NOCARD,
	CPU_PKI,
	CPU_PKI_SSF33,
};

//��λģʽ
enum ResetMode{COLD, WARM};

//�������ܿ��������
typedef unsigned long CARDHANDLE;
//�����ļ��������
typedef unsigned long FILEHANDLE;
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
	//���ܿ����
	CARDHANDLE		m_hCard;
	//���ܿ�����
	CardType		m_cardType;
	//������������
	LPTSTR			m_szName;
	//����������
	ReaderType		m_readerType;
	//������������
	int				m_nIndex;

	//Token��Ϣ
	LPTOKENINFO		m_pTokenInfo;

	//CSP�ļ�ϵͳ�汾��Ϣ
	CSP_FILESYS_VER m_FileSys;
//����
protected:
	//������Դ������
	BOOL EstablishContext(
		DWORD dwScope = SCARD_SCOPE_USER 
		);
	//�ͷ���Դ������
	BOOL ReleaseContext();

	//��ջ����Token��Ϣ
	void ClearTokenInfoBuffer();

public:
	//��ȡ����������
	ReaderType GetType() const { return m_readerType; }
	//���ö�����������
	void SetType(ReaderType type) { m_readerType = type; }
	//��ȡ������������
	LPCTSTR GetName() const { return m_szName; }
	//���ö�����������
	void SetName(LPCTSTR lpszName);
	//��ȡ������������
	int GetIndex() const { return m_nIndex; }
	//��ȡ����������������
	int GetRealIndex();
	//���ö�����������
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
	BOOL ConnectCard(
		BOOL bCheckCardValid = TRUE
		);
	//�Ͽ������ܿ�������
	BOOL DisconnectCard();

	//������ܿ��Ƿ񻹴�������״̬
	BOOL CheckCardConnect();

	//����Ƿ�������ܿ�
	BOOL CheckCardIsExist();

public:
	//��ʼ����
	BOOL BeginTransaction();
	//��������
	BOOL EndTransaction(
		DWORD dwDisposition = SCARD_LEAVE_CARD
		);
	//��λ
	BOOL Reset(
		BYTE* pbATR,
		DWORD* pdwATR,
		ResetMode mode = WARM
		);
	//��ȡATR
	BOOL GetATR(
		BYTE* pbATR,
		DWORD* pdwATR
		);
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
		int nUserType,						//��¼�û�����
		LPBYTE pPIN,						//PIN��
		DWORD dwPINLen,						//PIN��ĳ���
		DWORD& nRetryCount					//ʣ������ԵĴ���
		);
	//�û��˳�
	BOOL Logout();
	//����PIN��
	BOOL ChangePIN(
		int nUserType,						//�û�����
		LPBYTE pOldPIN,						//��PIN
		DWORD dwOldPINLen,					//��PIN�ĳ���
		LPBYTE pNewPIN,						//��PIN
		DWORD dwNewPINLen					//��PIN�ĳ���
		);
	//PIN����
	BOOL UnlockPIN(
		LPBYTE pUserDefaultPIN,				//�������û���ȱʡPIN
		DWORD dwUserDefaultPINLen			//�������û���ȱʡPIN�ĳ���
		);

	//��дTokenInfo
	BOOL GetTokenInfo(
		LPTOKENINFO pTokenInfo,
		BOOL bReload = FALSE
		);
	BOOL SetTokenInfo(
		LPTOKENINFO pTokenInfo
		);
	//��ȡӲ�����к�
	BOOL HWReadCardSN(char *szSN, int nMaxLen);

	//��ʽ����Ƭ
	BOOL FormatCard(
		LPFORMATINFO pInfo
		);

	//����EEPROM
	BOOL EraseE2();
	//��ѯ����
	BOOL GetE2Size(
		DWORD& dwTotalSize,					//�ܿռ�(��ϵͳռ��)
		DWORD& dwTotalSize2,				//�ܿռ�(����ϵͳռ��)
		DWORD& dwUnusedSize					//���ÿռ�
		);
	
	//��ѯCOS�汾
	BOOL GetCosVer(
		DWORD& dwVersion					//COS�汾
		);

	//��ѯ�Ƿ�������SSF33�㷨
	BOOL IsSSF33Support();

	BOOL cpuRefreshFatFile();

	//��ȡPIN���������
	BOOL GetPinRetryInfo(
		int nUserType,						//�û�����
		int& nMaxRetry,						//������Դ���
		int& nLeftRetry						//ʣ�����Դ���
		);

	
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

	//��ʽ�����ܿ�
	BOOL cpuFormatCard(
		LPFORMATINFO pInfo
		);

	//����EEPROM
	BOOL cpuEraseE2();

	//��ѯ����
	BOOL cpuGetE2Size(
		int nType,							//����
		DWORD& dwSize,						//�ռ��С
		BOOL* pErrBecauseNoMF = NULL		//�����Ƿ���Ϊû��MF			
		);
	
	//��ѯCOS�汾
	BOOL cpuGetCosVer(
		DWORD& dwVersion					//COS�汾
		);

	//��ѯ�Ƿ�������SSF33�㷨
	BOOL cpuIsSSF33Support();
	
	//��ȡ���������
	BOOL cpuGetKeyErrCount(
		int nKeyId,							//��Կ��ʶ
		int nKeyType,						//��Կ����
		BYTE& cErrCount						//����������ֽ�
		);

//���º����ͳ�Ա���ڲ���CPU���е�FAT�ļ�
private:
	//CPU����FAT�ļ����ڴ�ӳ��
	SHARE_FAT	m_fileFAT;

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