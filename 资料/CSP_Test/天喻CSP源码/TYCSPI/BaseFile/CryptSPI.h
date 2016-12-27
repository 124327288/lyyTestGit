#ifndef __TYCSP_CRYPTSPI_H__
#define __TYCSP_CRYPTSPI_H__

//-------------------------------------------------------------------
//	���ܣ�
//		����Token
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		OUT HCRYPTPROV hProv	�������Ӻ���������
//		DWORD dwIndex			TOKEN��������(�������������б�����)
//
//  ˵����
//		���TOKEN�Ѹ�ʽ������CSP�ļ�ϵͳ���򷵻�VERIFYCONTEXT�����������
//	���򷵻�TOKEN�����Ӿ����
//		�ɵ���CPIsFormatted�����Ƿ��Ѹ�ʽ������CSP���ļ�ϵͳ��
//-------------------------------------------------------------------
BOOL WINAPI CPConnect(
	OUT HCRYPTPROV *phProv,
	IN DWORD dwIndex
	);
//-------------------------------------------------------------------
//	���ܣ�
//		���ӿ�Ƭ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		CHAR* szReaderName		������������
//
//  ˵����
//	
//-------------------------------------------------------------------
BOOL WINAPI CPConnect1(
	CHAR* szReaderName
	);

//-------------------------------------------------------------------
//	���ܣ�
//		����Token
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		OUT HCRYPTPROV hProv	�������Ӻ���������
//		CHAR* szReaderName		TOKEN������
//
//  ˵����
//		���TOKEN�Ѹ�ʽ������CSP�ļ�ϵͳ���򷵻�VERIFYCONTEXT�����������
//	���򷵻�TOKEN�����Ӿ����
//		�ɵ���CPIsFormatted�����Ƿ��Ѹ�ʽ������CSP���ļ�ϵͳ��
//-------------------------------------------------------------------
BOOL WINAPI CPConnect2(
	OUT HCRYPTPROV *phProv,
	IN CHAR* szReaderName
	);
//-------------------------------------------------------------------
//	���ܣ�
//		��λ��Ƭ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		BYTE* pbATR			ATR����
//		DWORD* pdwATR		ATR�ĳ���
//		ResetMode mode		��λģʽ
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPResetCard(
	CHAR* szReaderName,
	BYTE* pbATR,
	DWORD* pdwATR,
	ResetMode mode /*=WARM*/
);

//-------------------------------------------------------------------
//	���ܣ�
//		�ж��Ƿ��Ѹ�ʽ������CSP���ļ�ϵͳ
//
//	���أ�
//		TRUE���Ѹ�ʽ��	FALSE��δ��ʽ��
//
//  ������
//		HCRYPTPROV hProv	�������
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPIsFormatted(
	IN HCRYPTPROV hProv
	);

//-------------------------------------------------------------------
//
//	Service Provider Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	���ܣ�
//		�򿪡��½���ɾ��ָ��TOKEN�е�һ������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV* phProv		���ڴ򿪻��½����ص��������
//		CHAR* pszContainer		��������
//		DWORD dwFlags			֧������ֵ�������MSDN����
//			0
//			CRYPT_VERIFYCONTEXT
//			CRYPT_NEWKEYSET
//			CRYPT_DELETEKEYSET
//		DWORD dwIndex			TOKEN��������(�������������б�����)
//
//  ˵����
//		ȱʡΪ�б�����
//-------------------------------------------------------------------
BOOL WINAPI CPAcquireContext(
	HCRYPTPROV *phProv,
	CHAR *pszContainer,
	DWORD dwFlags,
	DWORD dwIndex
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�򿪡��½���ɾ��ָ��TOKEN�е�һ������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV* phProv		���ڴ򿪻��½����ص��������
//		CHAR* pszContainer		��������
//		DWORD dwFlags			֧������ֵ�������MSDN����
//			0
//			CRYPT_VERIFYCONTEXT
//			CRYPT_NEWKEYSET
//			CRYPT_DELETEKEYSET
//		CHAR* szReaderName		TOKEN������
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPAcquireContext2(
	HCRYPTPROV *phProv,
	CHAR *pszContainer,
	DWORD dwFlags,
	CHAR* szReaderName
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�رմ򿪵�����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv	�������
//		DWORD dwFlags		����Ϊ0
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPReleaseContext(
	HCRYPTPROV hProv,
	DWORD dwFlags
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ��������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv	�������
//		DWORD dwParam		�������ͣ�֧������ȡֵ,�����MSDN����
//			PP_CONTAINER
//			PP_ENUMALGS
//			PP_ENUMALGS_EX
//			PP_ENUMCONTAINERS
//			PP_NAME
//			PP_VERSION
//			PP_IMPTYPE
//			PP_PROVTYPE
//		BYTE* pbData		���ص�����
//		DWORD* pdwDataLen	�������ݵĳ���
//		DWORD dwFlags		��ʶ��֧������ȡֵ,�����MSDN����
//			CRYPT_FIRST
//			CRYPT_NEXT
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetProvParam(
	HCRYPTPROV hProv,  
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD *pdwDataLen, 
	DWORD dwFlags      
	);

//-------------------------------------------------------------------
//	���ܣ�
//		������������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv	�������
//		DWORD dwParam		�������ͣ�֧������ȡֵ,�����MSDN����
//		BYTE* pbData		���õ�����
//		DWORD dwFlags		��ʶ��֧������ȡֵ,�����MSDN����
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPSetProvParam(
	HCRYPTPROV hProv,  
	DWORD dwParam,     
	BYTE *pbData,      
	DWORD dwFlags      
	);
 
//-------------------------------------------------------------------
//
//	Key Generation and Exchange Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	���ܣ�
//		������Կ(�Գ���Կ��ǶԳ���Կ)
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		ALG_ID AlgId			��Կ��ʶ��֧������ȡֵ,�����MSDN����
//			CALG_RC2
//			CALG_RC4
//			CALG_3DES
//			CALG_3DES_112
//			CALG_SSF33
//			CALG_RSA_SIGN,AT_SIGNATURE
//			CALG_RSA_KEYX,AT_KEYEXCHANGE
//		DWORD dwFlags			��Կ�������ã�֧������ȡֵ,�����MSDN����
//			CRYPT_EXPORTABLE
//			CRYPT_CREATE_SALT
//			CRYPT_NO_SALT
//			CRYPT_USER_PROTECTED
//		HCRYPTKEY* phKey		��������Կ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGenKey(
	HCRYPTPROV hProv, 
	ALG_ID Algid,     
	DWORD dwFlags,    
	HCRYPTKEY *phKey  
	);

//-------------------------------------------------------------------
//	���ܣ�
//		������Կ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			�����Ƶ���Կ���
//		DWORD* pdwReserved		��ΪNULL
//		DWORD dwFlags			��Ϊ0
//		HCRYPTKEY* phKey		���Ƶ���Կ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPDuplicateKey(
	HCRYPTPROV hProv,    
	HCRYPTKEY hKey,      
	DWORD *pdwReserved,  
	DWORD dwFlags,       
	HCRYPTKEY* phKey     
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�������Գ���Կ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		ALG_ID Algid			�㷨��ʶ
//		HCRYPTHASH hBaseData	��������	
//		DWORD dwFlags			��Կ�������ã�֧������ȡֵ,�����MSDN����
//			CRYPT_EXPORTABLE
//			CRYPT_CREATE_SALT
//			CRYPT_NO_SALT
//			CRYPT_USER_PROTECTED
//		HCRYPTKEY* phKey		����������Կ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPDeriveKey(
	HCRYPTPROV hProv,      
	ALG_ID Algid,          
	HCRYPTHASH hBaseData,  
	DWORD dwFlags,         
	HCRYPTKEY *phKey       
	);

//-------------------------------------------------------------------
//	���ܣ�
//		���ٶԳ���Կ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY pKey			��Կ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPDestroyKey(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey     
	);

//-------------------------------------------------------------------
//	���ܣ�
//		������Կ��
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		DWORD dwKeySpec			��Կ������
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPDestroyKeyPair(
	IN HCRYPTPROV hProv,  
	IN DWORD dwKeySpec      
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ��Կ����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			��Կ���
//		DWORD dwParam			�������ͣ�֧������ȡֵ,�����MSDN����
//			KP_ALGID 
//			KP_BLOCKLEN 
//			KP_SALT 
//			KP_PERMISSIONS 
//			KP_IV 
//			KP_PADDING 
//			KP_MODE 
//			KP_MODE_BITS
//			KP_EFFECTIVE_KEYLEN 
//			KP_CERTIFICATE
//		BYTE* pbData			���ص�����
//		DWORD* pdwDataLen		�������ݵĳ���
//		DWORD dwFlags			����Ϊ0			
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetKeyParam(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey,    
	IN DWORD dwParam,     
	OUT BYTE *pbData,      
	IN OUT DWORD *pdwDataLen, 
	IN DWORD dwFlags      
	);

//-------------------------------------------------------------------
//	���ܣ�
//		������Կ����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			��Կ���
//		DWORD dwParam			�������ͣ�֧������ȡֵ,�����MSDN����
//			KP_ALGID 
//			KP_BLOCKLEN 
//			KP_SALT 
//			KP_PERMISSIONS 
//			KP_IV 
//			KP_PADDING 
//			KP_MODE 
//			KP_MODE_BITS
//			KP_EFFECTIVE_KEYLEN 
//			KP_CERTIFICATE
//		BYTE* pbData			���õ�����
//		DWORD dwFlags			����Ϊ0			
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPSetKeyParam(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey,    
	IN DWORD dwParam,     
	IN BYTE *pbData,      
	IN DWORD dwFlags      
	);

//-------------------------------------------------------------------
//	���ܣ�
//		������Կ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			��������Կ���
//		HCRYPTKEY hExpKey		������Կ�õļ�����Կ
//		DWORD dwBlobType		��ԿBLOB������		
//		DWORD dwFlags			����Ϊ0
//		BYTE* pbData			����������
//		DWORD* pdwDataLen		�������ݵĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPExportKey(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey,    
	IN HCRYPTKEY hExpKey, 
	IN DWORD dwBlobType,  
	IN DWORD dwFlags,     
	OUT BYTE *pbData,      
	IN OUT DWORD *pdwDataLen  
	);

//-------------------------------------------------------------------
//	���ܣ�
//		������Կ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		CONST BYTE *pbData		���������
//		DWORD dwDataLen			�������ݵĳ���
//		HCRYPTKEY hImpKey		����ʱ�����õ���Կ���		
//		DWORD dwFlags			��ʶ��֧������ȡֵ,�����MSDN����
//			CRYPT_EXPORTABLE 
//		HCRYPTKEY *phKey		�����������Կ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPImportKey(
	IN HCRYPTPROV hProv,   
	IN CONST BYTE *pbData, 
	IN DWORD dwDataLen,    
	IN HCRYPTKEY hImpKey,  
	IN DWORD dwFlags,      
	OUT HCRYPTKEY *phKey    
	);

//-------------------------------------------------------------------
//	���ܣ�
//		������Կ��DER����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKeyPair		��Կ�Ծ��
//		LPBYTE pbDERCode		�����ı���
//		LPDWORD pdwDERCodeLen	�����ı��볤��		
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPExportPublicKeyDERCode(
	IN HCRYPTPROV hProv,
	IN HCRYPTKEY hKeyPair,
	OUT LPBYTE pbDERCode,
	IN OUT LPDWORD pdwDERCodeLen
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ѯ��Կ��
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		DWORD dwKeySpec			��Կ������
//		HCRYPTKEY hKeyPair		��Կ�Ծ��
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserKey(
	IN HCRYPTPROV hProv,     
	IN DWORD dwKeySpec,      
	OUT HCRYPTKEY *phUserKey  
	);

//-------------------------------------------------------------------
//	���ܣ�
//		���������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		DWORD dwLen				����������ĳ���
//		BYTE pbBuffer			�����������
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGenRandom(
	IN HCRYPTPROV hProv,  
	IN DWORD dwLen,       
	OUT BYTE *pbBuffer     
	);
 
//-------------------------------------------------------------------
//
//	Data Encryption Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	���ܣ�
//		����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			������Կ�ľ��
//		HCRYPTHASH hHash		����ͬʱ����HASH
//		BOOL Final				���һ��
//		DWORD dwFlags			����Ϊ0
//		BYTE* pbData			[IN]����/[OUT]����
//		DWORD* pdwDataLen		[IN]���ĳ���/[OUT]���ĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPDecrypt(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey,    
	IN HCRYPTHASH hHash,  
	IN BOOL Final,        
	IN DWORD dwFlags,     
	IN OUT BYTE *pbData,      
	IN OUT DWORD *pdwDataLen  
	);
 
//-------------------------------------------------------------------
//	���ܣ�
//		����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			������Կ�ľ��
//		HCRYPTHASH hHash		����ͬʱ����HASH
//		BOOL Final				���һ��
//		DWORD dwFlags			����Ϊ0
//		BYTE* pbData			[IN]����/[OUT]����
//		DWORD* pdwDataLen		[IN]���ĳ���/[OUT]���ĳ���
//		DWORD dwBufLen			pbData�Ŀռ��С
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPEncrypt(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey,    
	IN HCRYPTHASH hHash,  
	IN BOOL Final,        
	IN DWORD dwFlags,     
	IN OUT BYTE *pbData,      
	IN OUT DWORD *pdwDataLen, 
	IN DWORD dwBufLen     
	);

//-------------------------------------------------------------------
//	���ܣ�
//		RSAԭʼ����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			��Կ�Ծ��
//		LPBYTE pbInData			��������
//		DWORD dwInDataLen		�������ݵĳ���
//		LPBYTE pbOutData		�������
//		LPDWORD pdwOutDataLen	������ݵĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPRSARawDecrypt(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey,    
	IN LPBYTE pbInData,
	IN DWORD dwInDataLen,
	OUT LPBYTE pbOutData,
	IN OUT LPDWORD pdwOutDataLen
	);

//-------------------------------------------------------------------
//	���ܣ�
//		RSAԭʼ����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTKEY hKey			��Կ�Ծ��
//		LPBYTE pbInData			��������
//		DWORD dwInDataLen		�������ݵĳ���
//		LPBYTE pbOutData		�������
//		LPDWORD pdwOutDataLen	������ݵĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPRSARawEncrypt(
	IN HCRYPTPROV hProv,  
	IN HCRYPTKEY hKey,    
	IN LPBYTE pbInData,
	IN DWORD dwInDataLen,
	OUT LPBYTE pbOutData,
	IN OUT LPDWORD pdwOutDataLen
	);

//-------------------------------------------------------------------
//
//	Hashing and Digital Signature Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	���ܣ�
//		����HASH
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		ALG_ID AlgId			�㷨��ʶ����ȡ����ֵ
//			CALG_MD5
//			CALG_SHA
//			CALG_SSL3_SHAMD5
//		HCRYPTKEY hKey			MAC���õ�����Կ���
//		DWORD dwFlags			����Ϊ0
//		HCRYPTHASH* phHash		������HASH���	
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPCreateHash(
	IN HCRYPTPROV hProv,  
	IN ALG_ID Algid,      
	IN HCRYPTKEY hKey,    
	IN DWORD dwFlags,     
	OUT HCRYPTHASH *phHash 
	);

//-------------------------------------------------------------------
//	���ܣ�
//		����HASH
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		�����Ƶ�HASH���
//		DWORD* pdwReserved		��ΪNULL
//		DWORD dwFlags			��Ϊ0
//		HCRYPTHASH* phHash		���Ƶ�HASH���	
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPDuplicateHash(
	IN HCRYPTPROV hProv,    
	IN HCRYPTHASH hHash,    
	IN DWORD *pdwReserved,  
	IN DWORD dwFlags,       
	OUT HCRYPTHASH* phHash    
	);

//-------------------------------------------------------------------
//	���ܣ�
//		����HASH
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		HASH���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPDestroyHash(
	IN HCRYPTPROV hProv, 
	IN HCRYPTHASH hHash  
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡHASH����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		HASH���
//		DWORD dwParam			�������ͣ�֧������ȡֵ,�����MSDN����
//			HP_ALGID 
//			HP_HASHSIZE 
//			HP_HASHVAL
//		BYTE* pbData			���ص�����
//		DWORD* pdwDataLen		�������ݵĳ���
//		DWORD dwFlags			����Ϊ0			
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetHashParam(
	IN HCRYPTPROV hProv,  
	IN HCRYPTHASH hHash,  
	IN DWORD dwParam,     
	OUT BYTE *pbData,      
	IN OUT DWORD *pdwDataLen, 
	IN DWORD dwFlags      
	);

//-------------------------------------------------------------------
//	���ܣ�
//		����HASH����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		HASH���
//		DWORD dwParam			�������ͣ�֧������ȡֵ,�����MSDN����
//			HP_HASHVAL 
//		BYTE* pbData			���õ�����
//		DWORD dwFlags			����Ϊ0			
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPSetHashParam(
	IN HCRYPTPROV hProv,  
	IN HCRYPTHASH hHash,  
	IN DWORD dwParam,     
	IN BYTE *pbData,      
	IN DWORD dwFlags      
	);

//-------------------------------------------------------------------
//	���ܣ�
//		HASH����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		HASH���
//		CONST BYTE* pbData		����
//		DWORD dwDataLen			���ݳ���
//		DWORD dwFlags			����Ϊ0
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPHashData(
	IN HCRYPTPROV hProv,    
	IN HCRYPTHASH hHash,    
	IN CONST BYTE *pbData,  
	IN DWORD dwDataLen,     
	IN DWORD dwFlags        
	);

//-------------------------------------------------------------------
//	���ܣ�
//		HASH��Կ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		HASH���
//		HCRYPTKEY hKey			��Կ���
//		DWORD dwFlags			����Ϊ0
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPHashSessionKey(
	IN HCRYPTPROV hProv,  
	IN HCRYPTHASH hHash,  
	IN HCRYPTKEY hKey,    
	IN DWORD dwFlags      
	);

//-------------------------------------------------------------------
//	���ܣ�
//		ǩ��HASH
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		HASH���
//		DWORD dwKeySpec			ǩ����Կ������
//		LPCWSTR sDescription	ǩ������
//		DWORD dwFlags			����Ϊ0
//		BYTE* pbSignature		ǩ��ֵ
//		DWORD* pdwSigLen		ǩ��ֵ�ĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPSignHash(
	IN HCRYPTPROV hProv,      
	IN HCRYPTHASH hHash,      
	IN DWORD dwKeySpec,       
	IN LPCWSTR sDescription,  
	IN DWORD dwFlags,         
	OUT BYTE *pbSignature,     
	IN OUT DWORD *pdwSigLen       
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��֤ǩ��
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		HCRYPTHASH hHash		HASH���
//		CONST BYTE* pbSignature	ǩ��ֵ
//		DWORD dwSigLen			ǩ��ֵ�ĳ���
//		HCRYPTKEY hPubKey		��֤��Կ�ľ��
//		LPCWSTR sDescription	ǩ������
//		DWORD dwFlags			����Ϊ0
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPVerifySignature(
	IN HCRYPTPROV hProv,      
	IN HCRYPTHASH hHash,      
	IN CONST BYTE *pbSignature,  
	IN DWORD dwSigLen,        
	IN HCRYPTKEY hPubKey,     
	IN LPCWSTR sDescription,  
	IN DWORD dwFlags          
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�ɸ�ԭǩ��
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		DWORD dwKeySpec			ǩ����Կ������
//		LPBYTE pbData			��ǩ������
//		DWORD dwDataLen			��ǩ�����ݵĳ���
//		DWORD dwFlags			����Ϊ0
//		LPBYTE pbSignature		ǩ��ֵ
//		LPDWORD pdwSigLen		ǩ��ֵ�ĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPSignRecover(
	IN HCRYPTPROV hProv,
	IN DWORD dwKeySpec, 
	IN LPBYTE pbData,
	IN DWORD dwDataLen,
	IN DWORD dwFlags,
	OUT LPBYTE pbSignature,     
	IN OUT LPDWORD pdwSigLen       
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��֤��ԭ
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		CONST LPBYTE pbSignatureǩ��ֵ
//		DWORD dwSigLen			ǩ��ֵ�ĳ���
//		HCRYPTKEY hPubKey		��֤��Կ�ľ��
//		DWORD dwFlags			����Ϊ0
//		LPBYTE pbData			��ԭ����
//		LPDWORD pdwDataLen		��ԭ���ݵĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPVerifyRecover(
	IN HCRYPTPROV hProv,
	IN CONST LPBYTE pbSignature,  
	IN DWORD dwSigLen,        
	IN HCRYPTKEY hPubKey,
	IN DWORD dwFlags,
	OUT LPBYTE pbData,
	IN OUT LPDWORD pdwDataLen
	);

//-------------------------------------------------------------------
//
//	PIN Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	���ܣ�
//		У��PIN
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		int nUserType			�û�����
//		LPBYTE pPIN				PIN
//		DWORD dwPINLen			PIN�ĳ���
//		DWORD& nRetryCount		����󣬿����Դ���������ȷ���������塣
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPLogin(
	IN HCRYPTPROV hProv,
	IN int nUserType,
	IN LPBYTE pPIN,
	IN DWORD dwPINLen,
	OUT DWORD& nRetryCount
	);

//-------------------------------------------------------------------
//	���ܣ�
//		ע��
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPLogout(
	IN HCRYPTPROV hProv
	);

//-------------------------------------------------------------------
//	���ܣ�
//		���ĵ�ǰ��¼�û���PIN
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		LPBYTE pOldPIN			��PIN
//		DWORD dwOldPINLen		��PIN�ĳ���
//		LPBYTE pNewPIN			��PIN
//		DWORD dwNewPINLen		��PIN�ĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPChangePIN(
	IN HCRYPTPROV hProv,
	IN LPBYTE pOldPIN,
	IN DWORD dwOldPINLen,
	IN LPBYTE pNewPIN,
	IN DWORD dwNewPINLen
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�����û�PIN
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv				�������
//		LPBYTE pUserDefaultPIN			�������ȱʡ�û�PIN
//		DWORD dwUserDefaultPINLen		�������ȱʡ�û�PIN����
//
//  ˵����
//		�����ѵ�¼Ϊ����Ա
//-------------------------------------------------------------------
BOOL WINAPI CPUnlockPIN(
	IN HCRYPTPROV hProv,
	IN LPBYTE pUserDefaultPIN,
	IN DWORD dwUserDefaultPINLen
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ��ǰ��¼�û�������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		int& nUserType			�û�����
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserType(
	IN HCRYPTPROV hProv,
	OUT int& nUserType
	);

//-------------------------------------------------------------------
//
//	UserFile Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	���ܣ�
//		�򿪡��½���ɾ��ָ��TOKEN�е�һ���û��ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV* phProv		�ļ����
//		CHAR* szFileName		�ļ�����
//		DWORD dwFileSize		�ļ���С(ֻ���½��ļ�������)
//		DWORD dwFlags			��־
//		DWORD dwIndex			TOKEN����
//
//  ˵����
//		dwFlags��LOWORDΪ����ģʽ,HIWORDΪ�����ļ�ʱ��Ȩ���趨
//-------------------------------------------------------------------
BOOL WINAPI CPAcquireUserFile(
	OUT HCRYPTPROV *phProv,
	IN CHAR* szFileName,
	IN DWORD dwFileSize,
	IN DWORD dwFlags,
	IN DWORD dwIndex
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�򿪡��½���ɾ��ָ��TOKEN�е�һ���û��ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV* phProv		�ļ����
//		CHAR* szFileName		�ļ�����
//		DWORD dwFileSize		�ļ���С(ֻ���½��ļ�������)
//		DWORD dwFlags			��־
//		CHAR* szReaderName		TOKEN����
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPAcquireUserFile2(
	OUT HCRYPTPROV *phProv,
	IN CHAR* szFileName,
	IN DWORD dwFileSize,
	IN DWORD dwFlags,
	IN CHAR* szReaderName
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�رմ򿪵��û��ļ����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�ļ����
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPReleaseUserFile(
	IN HCRYPTPROV hProv
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ�û��ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�ļ����
//		DWORD dwReadLen			����ȡ�ĳ���
//		LPBYTE pbReadBuffer		��ȡ������
//		LPDWORD pdwRealReadLen	ʵ�ʶ�ȡ�ĳ���
//		DWORD dwOffset			��ȡƫ����
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPReadUserFile(
	IN HCRYPTPROV hProv,
	IN DWORD dwReadLen,
	OUT LPBYTE pbReadBuffer,
	OUT LPDWORD pdwRealReadLen,
	IN DWORD dwOffset
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�����û��ļ�
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�ļ����
//		LPBYTE pbWriteBuffer	д�������
//		DWORD dwWriteLen		д�����ݵĳ���
//		DWORD dwOffset			��ȡƫ����
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPWriteUserFile(
	IN HCRYPTPROV hProv,
	IN LPBYTE pbWriteBuffer,
	IN DWORD dwWriteLen,
	IN DWORD dwOffset
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ�û��ļ��Ĵ�С
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�ļ����
//		LPDWORD pdwSize			�ļ���С
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserFileSize(
	IN HCRYPTPROV hProv,
	OUT LPDWORD pdwSize
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ�û��ļ�������
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�ļ����
//		CHAR* szFileName		�ļ�����
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserFileName(
	IN HCRYPTPROV hProv,
	OUT CHAR* szFileName
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ�����û��ļ������б�
//
//	���أ�
//		TRUE:�ɹ�		FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		TOKEN���
//		CHAR* szFileNameList	�����û��ļ����ֵ��б�,��0�ָ�,˫0����
//		LPDWORD pcchSize		[IN]��������С/[OUT]ʵ�ʴ�С				
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetUserFileNameList(
	IN HCRYPTPROV hProv,
	OUT CHAR* szFileNameList,
	IN OUT LPDWORD pcchSize
	);

//-------------------------------------------------------------------
//
//	TokenInfo Functions
//
//-------------------------------------------------------------------

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡTOKEN��Ϣ
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			�������
//		LPTOKENINFO pTokenInfo		TOKEN��Ϣ
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetTokenInfo(
	IN HCRYPTPROV hProv,
	OUT LPTOKENINFO pTokenInfo
	);

//-------------------------------------------------------------------
//	���ܣ�
//		���»�ȡTOKEN��Ϣ
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			�������
//		LPTOKENINFO pTokenInfo		TOKEN��Ϣ
//
//  ˵����
//		CPGetTokenInfo�Ỻ���Ѷ�ȡ��TOKEN��Ϣ����ȡһ�κ��Ժ��ٵ��ö�
//	���ػ����TOKEN��Ϣ��CPReGetTokenInfo��ÿ�ξ����¶�ȡ
//-------------------------------------------------------------------
BOOL WINAPI CPReGetTokenInfo(
	IN HCRYPTPROV hProv,
	OUT LPTOKENINFO pTokenInfo
	);

//-------------------------------------------------------------------
//	���ܣ�
//		����TOKEN��Ϣ
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			�������
//		LPTOKENINFO pTokenInfo		TOKEN��Ϣ
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPSetTokenInfo(
	IN HCRYPTPROV hProv,
	IN LPTOKENINFO pTokenInfo
	);


//-------------------------------------------------------------------
//	���ܣ�
//		��ѯ����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			�������
//		DWORD& dwTotalSize			�ܿռ�(��ϵͳռ��)
//		DWORD& dwTotalSize2			�ܿռ�(����ϵͳռ��)
//		DWORD& dwUnusedSize			���ÿռ�
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetE2Size(
	IN HCRYPTPROV hProv,
	OUT DWORD& dwTotalSize,
	OUT DWORD& dwTotalSize2,
	OUT DWORD& dwUnusedSize
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ѯ����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		DWORD dwIndex				����
//		DWORD& dwTotalSize			�ܿռ�(��ϵͳռ��)
//		DWORD& dwTotalSize2			�ܿռ�(����ϵͳռ��)
//		DWORD& dwUnusedSize			���ÿռ�
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetE2Size2(
	IN DWORD dwIndex,
	OUT DWORD& dwTotalSize,
	OUT DWORD& dwTotalSize2,
	OUT DWORD& dwUnusedSize
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ѯ����
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		CHAR* szReaderName			������������
//		DWORD& dwTotalSize			�ܿռ�(��ϵͳռ��)
//		DWORD& dwTotalSize2			�ܿռ�(����ϵͳռ��)
//		DWORD& dwUnusedSize			���ÿռ�
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetE2Size3(
	IN CHAR* szReaderName,
	OUT DWORD& dwTotalSize,
	OUT DWORD& dwTotalSize2,
	OUT DWORD& dwUnusedSize
	);


BOOL WINAPI CPGetCosVer(
	CHAR* szReaderName,
	DWORD& dwVersion
	);
BOOL WINAPI CPIsSSF33Support(
	CHAR* szReaderName
	);


//-------------------------------------------------------------------
//	���ܣ�
//		��ȡPIN��������Ϣ
//
//	���أ�
//		TRUE���ɹ�		FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			�������
//		int nUserType				�û�����
//		int nMaxRetry				������Դ���
//		int nLeftRetry				ʣ�����Դ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetPinRetryInfo(
	IN HCRYPTPROV hProv,
	IN int nUserType,
	OUT int& nMaxRetry,
	OUT int& nLeftRetry
	);

//-------------------------------------------------------------------
//
//	Misc Functions
//
//-------------------------------------------------------------------


#ifndef USE_TYCSPI_STATIC_LIB

//-------------------------------------------------------------------
//	���ܣ�
//		ѡ��������ܿ��Ķ�����
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		int& nReaderIndex		����������
//		CHAR* szReaderName		����������
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPSelectReader(
	OUT int& nReaderIndex,
	OUT CHAR* szReaderName
	);

#endif

//-------------------------------------------------------------------
//	���ܣ�
//		��ʽ��TOKEN
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			�������
//		LPFORMATINFO pFormatInfo	��ʽ����Ϣ
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPFormat(
	IN HCRYPTPROV hProv,
	IN LPFORMATINFO pFormatInfo
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ʽ��TOKEN
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		DWORD dwIndex				����
//		LPFORMATINFO pFormatInfo	��ʽ����Ϣ
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPFormat2(
	IN DWORD dwIndex,
	IN LPFORMATINFO pFormatInfo
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ʽ��TOKEN
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		CHAR* szReaderName			������������
//		LPFORMATINFO pFormatInfo	��ʽ����Ϣ
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPFormat3(
	IN CHAR* szReaderName,
	IN LPFORMATINFO pFormatInfo
	);

//-------------------------------------------------------------------
//	���ܣ�
//		����EEPROM
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv			�������
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPEraseEE(
	IN HCRYPTPROV hProv
	);

//-------------------------------------------------------------------
//	���ܣ�
//		����EEPROM
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		DWORD dwIndex				����
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPEraseEE2(
	IN DWORD dwIndex
	);

//-------------------------------------------------------------------
//	���ܣ�
//		����EEPROM
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		CHAR* szReaderName			������������
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPEraseEE3(
	IN CHAR* szReaderName
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡATR��Ϣ
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		BYTE* pbATR				���ص�ATR
//		DWORD* pdwATR			���ص�ATR�ĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetATR(
	IN HCRYPTPROV hProv,
	OUT BYTE* pbATR,
	OUT DWORD* pdwATR
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�򿨷�������
//
//	���أ�
//		TRUE:�ɹ�(SW1SW2 = 0x9000��0x61XX)	FALSE:ʧ��
//
//  ������
//		HCRYPTPROV hProv		�������
//		BYTE* pbCommand			������
//		DWORD dwCommandLen		������ĳ���
//		BYTE* pbRespond			��Ӧ��
//		DWORD* pdwRespondLen	��Ӧ��ĳ���
//		WORD* pwStatus			״̬�ֽ�
//
//  ˵����
//		�������Ҫ��Ӧ���״̬�ֽ�,ֻ�踳��NULL
//-------------------------------------------------------------------
BOOL WINAPI CPSendCommand(
	HCRYPTPROV hProv,
	BYTE* pbCommand, 
	DWORD dwCommandLen, 
	BYTE* pbRespond = NULL, 
	DWORD* pdwRespondLen = NULL, 
	WORD* pwStatus = NULL
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�򿨷�������
//
//	���أ�
//		TRUE:�ɹ�(SW1SW2 = 0x9000��0x61XX)	FALSE:ʧ��
//
//  ������
//		DWORD dwIndex			����
//		BYTE* pbCommand			������
//		DWORD dwCommandLen		������ĳ���
//		BYTE* pbRespond			��Ӧ��
//		DWORD* pdwRespondLen	��Ӧ��ĳ���
//		WORD* pwStatus			״̬�ֽ�
//
//  ˵����
//		�������Ҫ��Ӧ���״̬�ֽ�,ֻ�踳��NULL
//-------------------------------------------------------------------
BOOL WINAPI CPSendCommand2(
	DWORD dwIndex,
	BYTE* pbCommand, 
	DWORD dwCommandLen, 
	BYTE* pbRespond = NULL, 
	DWORD* pdwRespondLen = NULL, 
	WORD* pwStatus = NULL
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�򿨷�������
//
//	���أ�
//		TRUE:�ɹ�(SW1SW2 = 0x9000��0x61XX)	FALSE:ʧ��
//
//  ������
//		CHAR* szReaderName		������������
//		BYTE* pbCommand			������
//		DWORD dwCommandLen		������ĳ���
//		BYTE* pbRespond			��Ӧ��
//		DWORD* pdwRespondLen	��Ӧ��ĳ���
//		WORD* pwStatus			״̬�ֽ�
//
//  ˵����
//		�������Ҫ��Ӧ���״̬�ֽ�,ֻ�踳��NULL
//-------------------------------------------------------------------
BOOL WINAPI CPSendCommand3(
	CHAR* szReaderName,
	BYTE* pbCommand, 
	DWORD dwCommandLen, 
	BYTE* pbRespond = NULL, 
	DWORD* pdwRespondLen = NULL, 
	WORD* pwStatus = NULL
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�Ͽ�TOKEN������
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		HCRYPTPROV hProv	�������
//		BOOL bWrite
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPFinalize(
	IN HCRYPTPROV hProv,
	IN BOOL bWrite = TRUE
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�Ͽ�TOKEN������
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		DWORD dwIndex		����
//		BOOL bWrite
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPFinalize2(
	IN DWORD dwIndex,
	IN BOOL bWrite = TRUE
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�Ͽ�TOKEN������
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		CHAR* szReaderName	������������
//		BOOL bWrite
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPFinalize3(
	IN CHAR* szReaderName,
	IN BOOL bWrite = TRUE
	);

//-------------------------------------------------------------------
//	���ܣ�
//		���ö�д��ö�ٱ�־λ
//
//	���أ�
//		��
//
//  ������
//		DWORD dwFlag		ö�ٶ�����������
//		BOOL bFilter		�Ƿ���˷�����������(���PCSC)
//
//  ˵����
//-------------------------------------------------------------------
void WINAPI CPSetReaderEnumFlag(
	IN DWORD dwFlag, 
	IN BOOL bFilter = TRUE
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ѯCSP(Token)����Ŀ
//
//	���أ�
//		��Ŀ
//
//  ������
//
//  ˵����
//-------------------------------------------------------------------
DWORD WINAPI CPGetCSPCount();

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡCSP��Ӧ������������
//
//	���أ�
//		TRUE���ɹ�	FALSE��ʧ��
//
//  ������
//		DWORD dwIndex		����
//		CHAR* szReaderName	������������
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPGetReaderName(
	IN DWORD dwIndex,
	OUT CHAR* szReaderName
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�����ֽ�˳��ģʽ
//
//	���أ�
//		��
//
//  ������
//		ByteOrderMode nMode		�ֽ�˳��ģʽ
//
//  ˵����
//-------------------------------------------------------------------
void WINAPI 
CPSetByteOrderMode(
	IN ByteOrderMode nMode
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�ж��Ƿ��Զ�����������Ϊ��ѯ������������
//
//	���أ�
//		TRUE:��		FALSE:����
//
//  ������
//		��
//
//  ˵����
//		ȱʡΪ�ö������б�����
//-------------------------------------------------------------------
BOOL WINAPI CPIsUseReaderIndex();

//-------------------------------------------------------------------
//	���ܣ�
//		�����Ƿ��Զ�����������Ϊ��ѯ������������
//
//	���أ�
//		��
//
//  ������
//		BOOL bFlag	��־
//
//  ˵����
//		ȱʡΪ�ö������б�����
//-------------------------------------------------------------------
void WINAPI CPSetUseReaderIndex(
	BOOL bFlag
	);

//-------------------------------------------------------------------
//	���ܣ�
//		������ܿ��Ƿ����
//
//	���أ�
//		TRUE:����	FALSE:������
//
//  ������
//		HCRYPTPROV hProv	�������
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPCheckCardIsExist(
	HCRYPTPROV hProv
	);

//-------------------------------------------------------------------
//	���ܣ�
//		������ܿ��Ƿ����
//
//	���أ�
//		TRUE:����	FALSE:������
//
//  ������
//		DWORD dwIndex		����
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPCheckCardIsExist2(
	DWORD dwIndex
	);
//-------------------------------------------------------------------
//	���ܣ�
//		������ܿ��Ƿ����
//
//	���أ�
//		TRUE:����	FALSE:������
//
//  ������
//		CHAR* szReaderName	������������
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPCheckCardIsExist3(
	CHAR* szReaderName
	);

//-------------------------------------------------------------------
//	���ܣ�
//		���������Ƿ����
//
//	���أ�
//		TRUE:����	FALSE:������
//
//  ������
//		HCRYPTPROV hProv	�������
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPCheckReaderIsExist(
	HCRYPTPROV hProv
	);

//-------------------------------------------------------------------
//	���ܣ�
//		���������Ƿ����
//
//	���أ�
//		TRUE:����	FALSE:������
//
//  ������
//		DWORD dwIndex		����
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPCheckReaderIsExist2(
	DWORD dwIndex
	);

//-------------------------------------------------------------------
//	���ܣ�
//		���������Ƿ����
//
//	���أ�
//		TRUE:����	FALSE:������
//
//  ������
//		CHAR* szReaderName	������������
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI CPCheckReaderIsExist3(
	CHAR* szReaderName
	);

//-------------------------------------------------------------------
//	���ܣ�
//		Base64����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		LPBYTE pbInData			��������
//		DWORD dwInDataLen		�������ݵĳ���
//		LPBYTE pbOutData		�����Base64����
//		LPDWORD pdwOutDataLen	Base64�����ĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI
CPBase64Encode(
	IN LPBYTE pbInData, 
	IN DWORD dwInDataLen, 
	OUT LPBYTE pbOutData,
	IN OUT LPDWORD pdwOutDataLen
	);

//-------------------------------------------------------------------
//	���ܣ�
//		Base64����
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		LPBYTE pbInData			Base64����
//		DWORD dwInDataLen		Base64����ĳ���
//		LPBYTE pbOutData		���������
//		LPDWORD pdwOutDataLen	������ݵĳ���
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI
CPBase64Decode(
	IN LPBYTE pbInData, 
	IN DWORD dwInDataLen, 
	OUT LPBYTE pbOutData,
	IN OUT LPDWORD pdwOutDataLen
	);

//-------------------------------------------------------------------
//	���ܣ�
//		����HASH
//
//	���أ�
//		TRUE:�ɹ�	FALSE:ʧ��
//
//  ������
//		IN ALG_ID algId			HASH�㷨��ʶ
//		IN LPBYTE pbInData		����
//		IN DWORD dwInDataLen	���ݵĳ��� 
//		OUT LPBYTE pbDigest		ժҪ
//
//  ˵����
//-------------------------------------------------------------------
BOOL WINAPI
CPSoftHash(
	IN ALG_ID algId,
	IN LPBYTE pbInData, 
	IN DWORD dwInDataLen, 
	OUT LPBYTE pbDigest
	);

/////////////////////////////////////////////////////////////////////
//
//	Only for Static Lib

#ifdef USE_TYCSPI_STATIC_LIB
BOOL WINAPI CPStaticLibInitialize();
BOOL WINAPI CPStaticLibFinalize();
#endif

#endif	// #ifndef __TYCSP_CRYPTSPI_H__