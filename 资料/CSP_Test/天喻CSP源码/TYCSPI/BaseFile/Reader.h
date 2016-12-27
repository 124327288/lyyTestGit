#ifndef __TYCSP_READER_H__
#define __TYCSP_READER_H__

//读卡器类型
enum ReaderType{
	RT_USBPORT = 0,					//USB Port
	RT_COMPORT,						//Serical Port
	RT_PCSC,						//PCSC
	RT_UNKNOWN,						//未知类型
};

//智能卡类型
enum CardType{
	NOCARD,
	CPU_PKI,
	CPU_PKI_SSF33,
};

//复位模式
enum ResetMode{COLD, WARM};

//定义智能卡句柄类型
typedef unsigned long CARDHANDLE;
//定义文件句柄类型
typedef unsigned long FILEHANDLE;
//所有CPU卡中的文件句柄都为该值
#define HFILECOS		(~0UL)

/////////////////////////////////////////////////////////////////////
//		为了对CPU卡中建立的文件进行维护, 在卡中建立了一FAT文件, 该文件
//	结构如下(对于MEMORY卡不需建立该文件,因为在MEMORY卡的文件系统中已
//	经实现了FAT):
//
//	--------------------------------------------------
//	版本 1byte | 该文件中的记录数（不包括本记录）2byte
//	--------------------------------------------------
//	文件id 2byte |	标志 2byte |	文件大小 2byte
//	--------------------------------------------------
//	                        ……
//	--------------------------------------------------
//	                        ……
//	--------------------------------------------------
//
//	版本号目前为3
//	其中标志字节的描述如下：
//	------------------------------------------------------
//	位	 | B7 | B6 | B5 | B4 | B3 | B2 | B1 | B0          |
//  用途	 Reserved		 |      AuthId
//	------------------------------------------------------
//	位	 | B7 | B6 | B5 | B4 | B3 | B2 | B1 | B0          |
//	-------------------------------------------------------
//	用途 |      	   type                 | Used/unused |
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

//如果B2, B3不全为0,则表明读文件要有权限
//如果B0, B1不全为0,则表明写文件要有权限
#define IS_READ_NEEDAUTH(flag)			((flag) & 0x0C)
#define IS_WRITE_NEEDAUTH(flag)			((flag) & 0x03)
#define SET_READ_NEEDAUTH(flag)			((flag) |= 0x0C)
#define SET_WRITE_NEEDAUTH(flag)		((flag) |= 0x03)

#define MAX_FAT_LEN		1024
struct SHARE_FAT{
	BYTE cContent[MAX_FAT_LEN];						//FAT文件的内容
	DWORD dwTotalLen;								//FAT文件的长度
	DWORD dwDataLen;								//FAT文件中包含数据的长度
};

/////////////////////////////////////////////////////////////////////
//	class CCSPReader
//
class CCSPReader{
//构造与析构函数
public:
	CCSPReader();
	~CCSPReader();

//属性
private:
	//资源上下文句柄(PCSC)
	SCARDCONTEXT	m_hSC;
	//智能卡句柄
	CARDHANDLE		m_hCard;
	//智能卡类型
	CardType		m_cardType;
	//读卡器的名称
	LPTSTR			m_szName;
	//读卡器类型
	ReaderType		m_readerType;
	//读卡器的索引
	int				m_nIndex;

	//Token信息
	LPTOKENINFO		m_pTokenInfo;

	//CSP文件系统版本信息
	CSP_FILESYS_VER m_FileSys;
//方法
protected:
	//建立资源上下文
	BOOL EstablishContext(
		DWORD dwScope = SCARD_SCOPE_USER 
		);
	//释放资源上下文
	BOOL ReleaseContext();

	//清空缓存的Token信息
	void ClearTokenInfoBuffer();

public:
	//获取读卡器类型
	ReaderType GetType() const { return m_readerType; }
	//读置读卡器的类型
	void SetType(ReaderType type) { m_readerType = type; }
	//获取读卡器的名字
	LPCTSTR GetName() const { return m_szName; }
	//设置读卡器的名字
	void SetName(LPCTSTR lpszName);
	//获取读卡器的索引
	int GetIndex() const { return m_nIndex; }
	//获取读卡器的真正索引
	int GetRealIndex();
	//设置读卡器的索引
	void SetIndex(int nIndex);
	//获取智能卡类型
	CardType GetCardType() const { return m_cardType; }
	//获取智能卡句柄
	CARDHANDLE GetCardHandle() const { return m_hCard; }

	//读取文件系统版本信息
	BOOL ReadFileSysVer();
	//获得文件系统版本信息, 传入一个信息结构指针
	void GetFileSysVer(LPCSP_FILESYS_VER pFileSysVer) ;

public:
	//判断是否与智能卡建立了连接
	BOOL IsConnectCard() const { return m_hCard != NULL; }
	//与智能卡连接
	BOOL ConnectCard(
		BOOL bCheckCardValid = TRUE
		);
	//断开与智能卡的连接
	BOOL DisconnectCard();

	//检测智能卡是否还处于连接状态
	BOOL CheckCardConnect();

	//检测是否存在智能卡
	BOOL CheckCardIsExist();

public:
	//开始事务
	BOOL BeginTransaction();
	//结束事务
	BOOL EndTransaction(
		DWORD dwDisposition = SCARD_LEAVE_CARD
		);
	//复位
	BOOL Reset(
		BYTE* pbATR,
		DWORD* pdwATR,
		ResetMode mode = WARM
		);
	//获取ATR
	BOOL GetATR(
		BYTE* pbATR,
		DWORD* pdwATR
		);
	//发送命令
	BOOL SendCommand(
		BYTE* pbCommand, 
		DWORD dwCommandLen, 
		BYTE* pbRespond = NULL, 
		DWORD* pdwRespondLen = NULL, 
		WORD* pwStatus = NULL
		);

//以下函数用于操作智能卡中的文件
public:
	//获取可用的文件
	BOOL GetWorkableFile(
		WORD flag,
		DWORD dwSize,
		BYTE path[2]
		);
	//创建文件
	BOOL CreateFile(
		BYTE path[2],
		DWORD dwSize,
		FILEHANDLE* phFile,
		BYTE type,
		BYTE readAuth,
		BYTE writeAuth
		);
	//删除文件
	BOOL DeleteFile(
		BYTE path[2]
		);
	//打开文件
	BOOL OpenFile(
		BYTE path[2],
		FILEHANDLE* phFile,
		LPDWORD pdwFileSize = NULL
		);
	//读文件
	BOOL ReadFile(
		FILEHANDLE hFile,
		DWORD dwReadLen,
		LPBYTE pReadBuffer,
		LPDWORD pdwRealReadLen,
		DWORD dwOffset = 0
		);
	//写文件
	BOOL WriteFile(
		FILEHANDLE hFile,
		LPBYTE pWriteBuffer,
		DWORD dwWriteBufferLen,
		DWORD dwOffset = 0
		);
	//关闭文件
	BOOL CloseFile(
		FILEHANDLE hFile
		);

//以下函数用于登录操作
public:
	BOOL Login(
		int nUserType,						//登录用户类型
		LPBYTE pPIN,						//PIN码
		DWORD dwPINLen,						//PIN码的长度
		DWORD& nRetryCount					//剩余可重试的次数
		);
	//用户退出
	BOOL Logout();
	//更改PIN码
	BOOL ChangePIN(
		int nUserType,						//用户类型
		LPBYTE pOldPIN,						//旧PIN
		DWORD dwOldPINLen,					//旧PIN的长度
		LPBYTE pNewPIN,						//新PIN
		DWORD dwNewPINLen					//新PIN的长度
		);
	//PIN解锁
	BOOL UnlockPIN(
		LPBYTE pUserDefaultPIN,				//解锁后用户的缺省PIN
		DWORD dwUserDefaultPINLen			//解锁后用户的缺省PIN的长度
		);

	//读写TokenInfo
	BOOL GetTokenInfo(
		LPTOKENINFO pTokenInfo,
		BOOL bReload = FALSE
		);
	BOOL SetTokenInfo(
		LPTOKENINFO pTokenInfo
		);
	//读取硬件序列号
	BOOL HWReadCardSN(char *szSN, int nMaxLen);

	//格式化卡片
	BOOL FormatCard(
		LPFORMATINFO pInfo
		);

	//擦除EEPROM
	BOOL EraseE2();
	//查询容量
	BOOL GetE2Size(
		DWORD& dwTotalSize,					//总空间(含系统占用)
		DWORD& dwTotalSize2,				//总空间(不含系统占用)
		DWORD& dwUnusedSize					//可用空间
		);
	
	//查询COS版本
	BOOL GetCosVer(
		DWORD& dwVersion					//COS版本
		);

	//查询是否已下载SSF33算法
	BOOL IsSSF33Support();

	BOOL cpuRefreshFatFile();

	//获取PIN错误计数器
	BOOL GetPinRetryInfo(
		int nUserType,						//用户类型
		int& nMaxRetry,						//最大重试次数
		int& nLeftRetry						//剩余重试次数
		);

	
//以下函数为对COS命令的封装
private:
	//定义DF标识枚举
	enum DF_ID{MF, TYCSP};
	//选择DF文件
	BOOL cpuSelectDF(DF_ID dfId);
	//选择EF文件(按文件标识进行选择)
	BOOL cpuSelectEF(
		BYTE cPath[2],						//文件标识 
		BYTE* pbRetData = NULL,				//响应数据
		DWORD* pdwRetDataLen = NULL			//响应数据的长度
		);
	//创建EF文件
	BOOL cpuCreateEF(
		BYTE path[2],						//文件标识
		DWORD dwSize,						//文件尺寸
		BYTE type,							//文件类型
		BYTE readAuth,						//读权限
		BYTE writeAuth,						//写权限
		BYTE* pbUseAuth	= NULL				//使用权限
		);
	//读取当前文件中的二进制记录
	BOOL cpuReadCurrentBinaryFile(
		BYTE* pbData,						//读出的数据
		DWORD dwDataLen,					//数据的长度
		DWORD dwOffset = 0					//在当前文件中偏移量
		);
	//向当前文件中写二进制记录
	BOOL cpuUpdateCurrentBinaryFile(
		BYTE* pbData,						//写入的数据
		DWORD dwDataLen,					//数据的长度
		DWORD dwOffset = 0,					//在当前文件中偏移量
		BOOL bPlain = FALSE				//是否强制明文写
		);
	//向当前文件中明文加MAC写二进制
	BOOL cpuUpdateBinaryWithMac(
		BYTE* pbData,						//写入的数据
		DWORD dwDataLen,					//数据的长度
		DWORD dwOffset = 0					//在当前文件中偏移量
		);
	//向卡中写入密钥
	BOOL cpuWriteKey(
		LPBYTE pKeyData,					//密钥数据
		DWORD dwKeyDataLen,					//密钥数据的长度
		BOOL bInstall						//安装还是修改
		);

	//格式化智能卡
	BOOL cpuFormatCard(
		LPFORMATINFO pInfo
		);

	//擦除EEPROM
	BOOL cpuEraseE2();

	//查询容量
	BOOL cpuGetE2Size(
		int nType,							//类型
		DWORD& dwSize,						//空间大小
		BOOL* pErrBecauseNoMF = NULL		//出错是否因为没有MF			
		);
	
	//查询COS版本
	BOOL cpuGetCosVer(
		DWORD& dwVersion					//COS版本
		);

	//查询是否已下载SSF33算法
	BOOL cpuIsSSF33Support();
	
	//获取错误计数器
	BOOL cpuGetKeyErrCount(
		int nKeyId,							//密钥标识
		int nKeyType,						//密钥类型
		BYTE& cErrCount						//错误计数器字节
		);

//以下函数和成员用于操作CPU卡中的FAT文件
private:
	//CPU卡中FAT文件的内存映像
	SHARE_FAT	m_fileFAT;

	//初始化FAT文件的内存映像
	BOOL cpuInitFatFile();
	//从卡中读出FAT文件
	BOOL cpuReadFatFile();
	//加入一个FAT表项
	BOOL cpuAddFatFileItem(
		BYTE path[2],
		WORD flag,
		DWORD dwSize
		);
	//更新指定文件FAT表项中的的使用标志位
	BOOL cpuSetFileUseableFlag(
		BYTE path[2],
		BOOL bDeleted
		);
	//获取可用文件
	BOOL cpuGetWorkableFile(
		WORD flag,
		DWORD dwSize,
		BYTE path[2]
		);
};

#endif