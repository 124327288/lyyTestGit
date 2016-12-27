//-------------------------------------------------------------------
//	���ļ�Ϊ MemCard ����ɲ���
//
//
//	��Ȩ���� ������Ϣ��ҵ���޹�˾ (c) 1996 - 2002 ����һ��Ȩ��
//-------------------------------------------------------------------
//	�û��ӿ�:�����ӿ�
//

#ifndef __MCARD_FILE_ACCESS_H__
#define __MCARD_FILE_ACCESS_H__

//�������Ͷ���
#include "MCTypeDef.h"

#define MCARD_API __stdcall

#ifdef __cplusplus
extern "C" {
#endif

//-------------------------------------------------------------------
//	���ܣ�
//		�뿨����
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_TYPE cardType		��Ƭ����
//		IN LPVOID pParameter			���Ӳ���
//		OUT MC_CARD_HANDLE* phCard		���صĿ�Ƭ���
//
//  ˵����
//		���cardTypeΪMC_CARDTYPE_DISKFILE����pParameter��ת��Ϊһchar���͵�ָ�룬
//	���ַ���Ϊ�����ļ���·����
//		���cardTypeΪMC_CARDTYPE_PCSCCARD����pParameter��ת��ΪһDWORD���͵�ָ�룬
//	��DWORD������Ҫ���ӵĿ���������
//		���cardTypeΪMC_CARDTYPE_TYKEY����pParameter��ת��ΪһDWORD���͵�ָ�룬
//	��DWORD������Ҫ���ӵĿ���������
//		���cardTypeΪMC_CARDTYPE_CYPRESSSB����pParameter��ת��ΪһDWORD���͵�ָ�룬
//	��DWORD������Ҫ���ӵĿ���������
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardConnect(
	IN MC_CARD_TYPE cardType,
	IN LPVOID pParameter,
	OUT MC_CARD_HANDLE* phCard
	);

//-------------------------------------------------------------------
//	���ܣ�
//		���ݴ���Ŀ�ƬͨѶ�������MemCard���󲢷��ض���ľ��
//
//	���أ�
//		�����
//
//  ������
//		IN MC_CARD_TYPE cardType		��Ƭ����
//		IN HANDLE hCardComm				��ƬͨѶ���
//		OUT MC_CARD_HANDLE* phCard		��Ƭ���
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardAttachCard(
	IN MC_CARD_TYPE cardType,
	IN HANDLE hCardComm,
	OUT MC_CARD_HANDLE* phCard
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�Ͽ��뿨Ƭ������
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardDisconnect(
	IN MC_CARD_HANDLE hCard
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�жϿ�Ƭ�Ƿ񻹴���
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardIsCardExist(
	IN MC_CARD_HANDLE hCard
	);

//-------------------------------------------------------------------
//	���ܣ�
//		������Ƭ���ļ�ϵͳ
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard					��Ƭ���
//		IN MC_SYSTEM_CREATE_INFO* pCreateInfo	������Ϣ
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardCreateFileSystem(
	IN MC_CARD_HANDLE hCard,
	IN MC_SYSTEM_CREATE_INFO* pCreateInfo
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ��Ƭϵͳ��Ϣ
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		OUT DWORD& dwVersion			�汾��
//		OUT DWORD& dwCardSize			��Ƭ�ߴ�
//		OUT BYTE& Align					�ļ��ֽڶ�����
//		OUT DWORD& dwFatItemCount		FAT�������Ŀ
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardGetSystemInfo(
	IN MC_CARD_HANDLE hCard,
	OUT DWORD& dwVersion,
	OUT DWORD& dwCardSize,
	OUT BYTE& Align,
	OUT DWORD& dwFatItemCount
	);

//-------------------------------------------------------------------
//	���ܣ�
//		����Ŀ¼
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard					��Ƭ���
//		IN MC_FILE_ID fileID					Ŀ¼��ʶ
//		IN MC_DIR_CREATE_INFO* pCreateInfo		����Ŀ¼����Ϣ
//		IN DWORD dwFlags						��־λ(����)
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardMakeDir(
	IN MC_CARD_HANDLE hCard,
	IN MC_FILE_ID fileID,
	IN MC_DIR_CREATE_INFO* pCreateInfo,
	IN DWORD dwFlags
	);

//-------------------------------------------------------------------
//	���ܣ�
//		ɾ��Ŀ¼
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_FILE_ID fileID			Ŀ¼��ʶ
//		IN DWORD dwFlags				��־λ(����)
//
//  ˵����
//		Ŀ¼����Ϊ��
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardDeleteDir(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_ID fileID,
	IN DWORD dwFlags
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�ı�Ŀ¼
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_FILE_ID* pPath			���ļ���ʶ��ɵ�·��
//		IN DWORD dwCount				�ļ���ʶ����Ŀ
//		IN MC_CD_TYPE cdType			�ı�Ŀ¼�ķ�ʽ
//
//  ˵����
//		����ִ�д��󲻻�ı䵱ǰĿ¼
//		���pPath = NULL��cdType = MC_CD_FROM_ROOT,��ص���Ŀ¼
//		���·����ʶΪ0xFFFF���ʾ���˵���һ��Ŀ¼
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardChangeDir(
	IN MC_CARD_HANDLE hCard,
	IN MC_FILE_ID* pPath,	
	IN DWORD dwCount,	
	IN MC_CD_TYPE cdType	
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�г���ǰĿ¼�������ļ�����Ŀ¼������
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN OUT MC_FILE_PROP* pFiles		�ļ�����
//		IN OUT DWORD& dwCount			�ļ�����Ŀ
//
//  ˵����
//		һ��Ҫ�������Ρ���һ��ʱpFiles = NULL,��������dwCount
//	�з����ļ�����Ŀ����ʱ�ٷ���ռ�Ȼ����еڶ��ε��á�
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardDirectory(
	IN MC_CARD_HANDLE hCard,
	IN OUT MC_FILE_PROP* pFiles,
	IN OUT DWORD& dwCount
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡһ�����õ��ļ���ʶ��
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN DWORD dwFlags				��־λ(����)
//		OUT MC_FILE_ID* pFileId			���ص��ļ���ʶ��
//		IN MC_FILE_ID startFileId		��ʼ�ļ���ʶ
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardGetWorkableFileId(
	IN MC_CARD_HANDLE hCard,
	IN DWORD dwFlags,
	OUT MC_FILE_ID* pFileId,
	IN MC_FILE_ID startFileId = MC_MIN_FILE_ID
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�����ļ�
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard				��Ƭ���
//		IN MC_FILE_ID fileID				�ļ���ʶ
//		IN MC_FILE_CREATE_INFO* pCreateInfo	�����ļ�����Ϣ
//		IN DWORD dwFlags					��־λ(����)
//		OUT MC_FILE_HANDLE phFile			���ص��ļ����
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardCreateFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_ID fileID,
	IN MC_FILE_CREATE_INFO* pCreateInfo,
	IN DWORD dwFlags,
	OUT MC_FILE_HANDLE* phFile
	);

//-------------------------------------------------------------------
//	���ܣ�
//		ɾ���ļ�
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_FILE_ID fileID			�ļ���ʶ
//		IN DWORD dwFlags				��־λ(����)
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardDeleteFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_ID fileID,
	IN DWORD dwFlags
	);

//-------------------------------------------------------------------
//	���ܣ�
//		���ļ�
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_FILE_ID fileID			�ļ���ʶ
//		IN DWORD dwFlags				��־λ(����)
//		OUT MC_FILE_HANDLE* phFile		���ص��ļ����
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardOpenFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_ID fileID,
	IN DWORD dwFlags,
	OUT MC_FILE_HANDLE* phFile
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�ر��ļ�
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_FILE_HANDLE hFile			�ļ����
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardCloseFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_HANDLE hFile
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ�ļ��Ĵ�С
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_FILE_HANDLE hFile			�ļ����
//		OUT LPDWORD pdwSize				���ص��ļ���С
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardGetFileSize(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_HANDLE hFile,
	OUT LPDWORD pdwSize
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ�ļ�������
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_FILE_HANDLE hFile			�ļ����
//		IN DWORD dwFlags				��־λ(����)
//		IN DWORD dwReadLen				��ȡ�ĳ���
//		IN LPBYTE pbReadBuffer			��Ŷ�ȡ���ݵĿռ�
//		OUT LPDWORD pdwRealReadLen		ʵ�ʶ�ȡ�ĳ���
//
//  ˵����
//		���ļ�����Ӱ���ļ�ָ���λ��
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardReadFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_HANDLE hFile,
	IN DWORD dwFlags,
	IN DWORD dwReadLen,
	IN LPBYTE pbReadBuffer,
	OUT LPDWORD pdwRealReadLen
	);

//-------------------------------------------------------------------
//	���ܣ�
//		д�����ݵ��ļ���
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_FILE_HANDLE hFile			�ļ����
//		IN DWORD dwFlags				��־λ(����)
//		IN LPBYTE pbWriteBuffer			���д�����ݵĿռ�
//		IN DWORD dwWriteLen				д�����ݵĳ���
//
//  ˵����
//		д�ļ�����Ӱ���ļ�ָ���λ��
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardWriteFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_HANDLE hFile,
	IN DWORD dwFlags,
	IN LPBYTE pbWriteBuffer,
	IN DWORD dwWriteLen
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�ƶ��ļ�ָ��
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_FILE_HANDLE hFile			�ļ����
//		IN MC_SEEK_TYPE seekType		�ƶ�����
//		IN LONG offset					�ƶ�����
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardSeekFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_HANDLE hFile,
	IN MC_SEEK_TYPE seekType,
	IN LONG offset
	); 

//-------------------------------------------------------------------
//	���ܣ�
//		ʹ�ļ���Ч
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_FILE_ID fileID			�ļ���ʶ
//		IN DWORD dwFlags				��־λ(����)
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardInvalidateFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_ID fileID,
	IN DWORD dwFlags
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�ָ��ļ�����Ч��
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_FILE_ID fileID			�ļ���ʶ
//		IN DWORD dwFlags				��־λ(����)
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardRehabilitateFile(
	IN MC_CARD_HANDLE hCard,			
	IN MC_FILE_ID fileID,
	IN DWORD dwFlags
	);

//-------------------------------------------------------------------
//	���ܣ�
//		���ӻ��޸���Կ
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_FILE_HANDLE hFile			�ļ����
//		IN MC_KEY_INFO* pKeyInfo		��Կ��Ϣ
//		IN BOOL bInstall				����(TRUE)���޸�(FALSE)
//		IN DWORD dwFlags				��־λ(����)
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardWriteKey(
	IN MC_CARD_HANDLE hCard,			
	IN MC_KEY_INFO* pKeyInfo,
	IN BOOL bInstall,
	IN DWORD dwFlags
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ�����
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		OUT LPBYTE pbRandom				��ȡ�������
//		IN DWORD dwRandomNum			���������Ŀ
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardGetChallenge(
	IN MC_CARD_HANDLE hCard,			
	OUT LPBYTE pbRandom,
	IN DWORD dwRandomNum
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�ⲿ��֤
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_KEY_ID keyId				��Կ��ʶ
//		IN LPBYTE pbEncryptedData		���ܵ�����(8�ֽ�)
//		OUT DWORD& dwRetryNum			�Ժ�����ԵĴ���
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardExternalAuthentication(
	IN MC_CARD_HANDLE hCard,			
	IN MC_KEY_ID keyId,
	IN LPBYTE pbEncryptedData,
	OUT DWORD& dwRetryNum
	);

//-------------------------------------------------------------------
//	���ܣ�
//		У���������
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_KEY_ID pinId				PIN��ʶ
//		IN LPBYTE pbPin					��������(1-16�ֽ�)
//		IN DWORD dwPinLen				��������ĳ���
//		OUT DWORD& dwRetryNum			�Ժ�����ԵĴ���
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardVerifyPin(
	IN MC_CARD_HANDLE hCard,
	IN MC_KEY_ID pinId,
	IN LPBYTE pbPin,
	IN DWORD dwPinLen,
	OUT DWORD& dwRetryNum
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��֤��������������
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//		IN MC_KEY_ID pinId				PIN��ʶ
//		IN LPBYTE pbOldPin				���˾�����(1-16�ֽ�)
//		IN DWORD dwOldPinLen			���˾�����ĳ���
//		IN LPBYTE pbNewPin				����������(1-16�ֽ�)
//		IN DWORD dwNewPinLen			����������ĳ���
//		OUT DWORD& dwRetryNum			�Ժ�����ԵĴ���
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API 
MCardVerifyAndChangePin(
	IN MC_CARD_HANDLE hCard,
	IN MC_KEY_ID pinId,
	IN LPBYTE pbOldPin,
	IN DWORD dwOldPinLen,
	IN LPBYTE pbNewPin,
	IN DWORD dwNewPinLen,
	OUT DWORD& dwRetryNum
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ʼһ������
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//
//  ˵����
//		�������������������ô���øú������߳̽�������ֱ�������������
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardBeginTransaction(
	IN MC_CARD_HANDLE hCard
	);

//-------------------------------------------------------------------
//	���ܣ�
//		����һ������
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_CARD_HANDLE hCard			��Ƭ���
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardEndTransaction(
	IN MC_CARD_HANDLE hCard
	);

//-------------------------------------------------------------------
//	���ܣ�
//		��ȡ��������
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN MC_RV errCode					������
//		OUT TCHAR errMsg[MC_ERRMSG_MAX_LEN]	����������
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardGetErrorMsg(
	IN MC_RV errCode,
	OUT char errMsg[MC_ERRMSG_MAX_LEN]
	);



/////////////////////////////////////////////////////////////////////
//
//	��������

//	�㷨��ʶ
#define ALG_HASH_MD5						1		//��ϣֵΪ16 Byte
#define ALG_HASH_SHA						2		//��ϣֵΪ20 Byte
#define ALG_SYMM_DES						3		//��Կ����Ϊ8 Byte���ֿ鳤��Ϊ8 Byte
#define ALG_SYMM_DES_EDE					4		//��Կ����Ϊ16 Byte���ֿ鳤��Ϊ8 Byte
#define ALG_SYMM_3DES						5		//��Կ����Ϊ24 Byte���ֿ鳤��Ϊ8 Byte

//	PKCS1 V1.5�������
#define PKCS_SIGNATURE_PADDING				1		//block	type 01		
#define PKCS_ENCRYPTION_PADDING				2		//block type 02

/*
	DigestInfo��ASN1��ʾ

	DigestInfo ::= SEQUENCE{
 		digestAlgorithm DigestAlgorithmIdentifier, 
		digest Digest 
		} 
	DigestAlgorithmIdentifier ::= AlgorithmIdentifier 
	Digest ::= OCTET STRING

	���������HASHֵ���������涨��ĳ������漴������SHA��MD5��DigestInfo
	Ȼ��PKCS1-V1.5�涨����block type 01�������RSA˽Կ���н�������õ�ǩ��

*/
const BYTE g_SHA_DigestInfo[] = {
	0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14
	};
const BYTE g_MD5_DigestInfo[] = {
	0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x04,0x10
	};

//-------------------------------------------------------------------
//	���ܣ�
//		����һ�����ݵĹ�ϣֵ
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN int nAlgId						HASH�㷨��ʶ
//		IN LPBYTE pbData					������HASH������
//		IN DWORD dwDataLen					���ݵĳ���
//		OUT unsigned char* pbHashValue		���ص�HASHֵ
//
//  ˵����
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardAuxHash(
	IN int nAlgId,
	IN LPBYTE pbData,
	IN DWORD dwDataLen,
	OUT LPBYTE pbHashValue
	);

//-------------------------------------------------------------------
//	���ܣ�
//		�ԳƼӽ���
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN int nAlgId				�Գ��㷨��ʶ
//		IN BOOL bEncrypt			1Ϊ���ܣ�0Ϊ����
//		IN LPBYTE pbKey				��Կֵ
//		IN LPBYTE pbInData			��������
//		IN DWORD dwInDataLen		�������ݵĳ���
//		OUT LPBYTE pbOutData		�������
//		OUT LPDWORD pdwOutDataLen	������ݵĳ���
//		IN BOOL bPadding			1��䣬0�����
//
//  ˵����
//		Ŀǰֻ֧��ECBģʽ
//		���bPaddingΪ 1 ���Զ����(����)��ȥ�����(����)
//		��bEncryptΪ 1 (����)ʱ�����bPaddingΪ 1 ���������ݵĳ��ȿ�
//	Ϊ����ֵ��������ݵĳ��Ȳ��ᳬ���������ݵĳ��ȼӿ鳤�����bPadding
//	Ϊ 0 ���������ݵĳ��ȱ���Ϊ�鳤����������������ݵĳ�������������
//	�ĳ�����ͬ	
//		��bEncryptΪ 0 (����)ʱ���������ݵĳ��ȱ���Ϊ�鳤������������
//	�����ݵĳ��ȵ�bPaddingΪ 0 ʱ���������ݵĳ�����ͬ����bPaddingΪ 1
//	ʱ���ᳬ���������ݵĳ���
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardAuxSymmCipher(
	IN int nAlgId,
	IN BOOL bEncrypt,
	IN LPBYTE pbKey,
	IN LPBYTE pbInData,
	IN DWORD dwInDataLen,
	OUT LPBYTE pbOutData,
	OUT LPDWORD pdwOutDataLen,
	IN BOOL bPadding
	);

//-------------------------------------------------------------------
//	���ܣ�
//		ΪRSA��/���ܻ�ǩ��/��֤��PKCS1-V1.5�����������
//
//	���أ�
//		MC_S_SUCCESS: �ɹ�            ����:ʧ��
//
//  ������
//		IN int nPaddingType			�������
//		IN BOOL bPadding			1Ϊ��䣬0Ϊȥ�����
//		IN DWORD dwBitsLen			RSA��Կ�Ե�ģ��(Bits)			
//		IN LPBYTE pbInData			��������
//		IN DWORD dwInDataLen		�������ݵĳ���
//		OUT LPBYTE pbOutData		�������
//		OUT LPDWORD pdwOutDataLen	������ݵĳ���
//
//  ˵��
//		���ۺ���������ͣ����bPaddingΪ1���������ݵĳ���ӦС�� 
//	dwBitsLen/8 - 11��������ݵĳ���Ϊ dwBitsLen / 8
//		
//-------------------------------------------------------------------
MC_RV MCARD_API
MCardAuxPKCSPadding(
	IN int nPaddingType,
	IN BOOL bPadding,
	IN DWORD dwBitsLen,
	IN LPBYTE pbInData,
	IN DWORD dwInDataLen,
	OUT LPBYTE pbOutData,
	OUT LPDWORD pdwOutDataLen
	);

#ifdef __cplusplus
}       // Balance extern "C" above
#endif

#endif