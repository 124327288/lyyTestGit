//Mac.h
#ifndef __MAC_H__
#define __MAC_H__
#include "CSPAfx.h"

class BlockTransformation;

#define DES_BLOCK_SIZE 8
///////////////////////////////////////////////////////////////////////////////////////////////////////////
class CMac
{
public:
		CMac();
		~CMac();

/////////////////////////////////////////////////////////////////////////
	//初始化一个Mac,准备接收数据计算MAC
//		BYTE *	pbVector,		//初始化向量,一般为随机数
//		BYTE *	pbKey,			//计算MAC用的密钥
//		int		nKeyLen,		//密钥长度, 8为DES, 16为DES-EDE
//		BYTE	bMode = 0x00	//填充及返回MAC长度的标记,见下面对CulMac的说明
/////////////////////////////////////////////////////////////////////////
	void Init(
		BYTE *pbVector, 
		BYTE *pbKey, 
		int nKeyLen, 
		BYTE bMode = 0x00
		);

/////////////////////////////////////////////////////////////////////////
	//添加一块数据
//	BYTE *pbData	添加的数据块,长度为8	
/////////////////////////////////////////////////////////////////////////
	BOOL Update(BYTE *pbData);

/////////////////////////////////////////////////////////////////////////
	//结束计算MAC
//	BYTE *pbData	最后一块数据,长度为8	
//	BYTE *pbMac		返回MAC的缓冲,根据最初MODE的指定,长度为4或8
/////////////////////////////////////////////////////////////////////////
	BOOL Final(BYTE *pbData, BYTE *pbMac);

protected:

private:
		BYTE m_pbData[DES_BLOCK_SIZE];
		BOOL m_bInited;
		BYTE m_bMode;
		DES_EDE_Encryption *m_pDESEDECipher;
		TripleDES_Encryption *m_pTripleDesCipher;
		DESEncryption * m_pDESCipher;
};
/////////////////////////////////////////////////////////////////////////////
//计算一段数据的MAC
/*
			BYTE *	pbKey,		//: key: 送入的过程密钥, 必须8字节
			int		nKeyLen,	//密钥长度,可以算出密钥算法
			BYTE *	pbData,		//：data:送入的待计算的数据 
			int		nDataLen,	//: data_len: 传入待计算数据的长度.
			BYTE *	pbMac,		//: mac: 返回4字节的加密结果
			BYTE *	pbVector,	//pvector:过程密钥初始化向量
			BYTE	bMode = 0x00
 */
/*mode的默认值为0，当最低位为0时，当数据长度为8的整数倍时仍然补80，
最低位为为1表示为8的整数倍时不继续补80，
主要用于PSAM卡计算MAC的比较。
当第二位为0时，产生的mac为4个字节，当第二位为1时，产生的mac为8个字节*/
///////////////////////////////////////////////////////////////////////////////
BOOL CulMac(BYTE *		pbKey, 
			int			nKeyLen,
			BYTE *		pbData,
			int			nDataLen, 
			BYTE *		pbMac,
			BYTE *		pbVector,
			BYTE		bMode = 0x00
		 );

#endif