//ssf33.cpp
#include "stdAfx.h"
#include "des.h"
#include "Mac.h"


CMac::CMac()
{
	memset(m_pbData, 0, DES_BLOCK_SIZE);
	m_bInited = FALSE;
	m_pTripleDesCipher = NULL;
	m_pDESEDECipher = NULL;
	m_pDESCipher = NULL;
}

CMac::~CMac()
{
	if(m_pDESEDECipher)
		delete m_pDESEDECipher;

	if(m_pTripleDesCipher)
		delete m_pTripleDesCipher;

	if(m_pDESCipher)
		delete m_pDESCipher;
}

/////////////////////////////////////////////////////////////////////////
	//初始化一个Mac,准备接收数据计算MAC
//		BYTE *	pbVector,		//初始化向量,一般为随机数
//		BYTE *	pbKey,			//计算MAC用的密钥
//		int		nKeyLen,		//密钥长度, 8为DES, 16为DES-EDE
//		BYTE	bMode = 0x00	//填充及返回MAC长度的标记,见下面对CulMac的说明
/////////////////////////////////////////////////////////////////////////
void CMac::Init(
	BYTE *		pbVector, 
	BYTE *		pbKey, 
	int			nKeyLen, 
	BYTE		bMode /*= 0x00*/
	)
{
	memcpy(m_pbData, pbVector, DES_BLOCK_SIZE);

	if(nKeyLen == (DES_BLOCK_SIZE * 2))
		m_pDESEDECipher = new DES_EDE_Encryption(pbKey);
	else if(nKeyLen == (DES_BLOCK_SIZE * 3))
		m_pTripleDesCipher = new TripleDES_Encryption(pbKey);

	m_pDESCipher = new DESEncryption(pbKey);

	ASSERT(m_pDESCipher != NULL);
	
	m_bInited = TRUE;
	m_bMode = bMode;
}
/////////////////////////////////////////////////////////////////////////
	//添加一块数据
//	BYTE *pbData	添加的数据块,长度为8	
/////////////////////////////////////////////////////////////////////////
BOOL CMac::Update(BYTE *pbData)
{
	if(!m_bInited)
		return m_bInited;

	for(int i = 0; i < DES_BLOCK_SIZE; i++)
		m_pbData[i] = m_pbData[i] ^ pbData[i];

	m_pDESCipher->ProcessBlock(m_pbData);
	
	return TRUE;
}

/////////////////////////////////////////////////////////////////////////
	//结束计算MAC
//	BYTE *pbData	最后一块数据,长度为8	
//	BYTE *pbMac		返回MAC的缓冲,根据最初MODE的指定,长度为4或8
/////////////////////////////////////////////////////////////////////////
BOOL CMac::Final(BYTE *pbData, BYTE *pbMac)
{
	//再做一次加密
	if(!m_bInited)
		return m_bInited;

	for(int i = 0; i < DES_BLOCK_SIZE; i++)
		m_pbData[i] = m_pbData[i] ^ pbData[i];

	if(m_pTripleDesCipher)
	{
		m_pTripleDesCipher->ProcessBlock(m_pbData);
		delete m_pTripleDesCipher;
		m_pTripleDesCipher = NULL;
	}
	else if(m_pDESEDECipher)
	{
		m_pDESEDECipher->ProcessBlock(m_pbData);
		delete m_pDESEDECipher;
		m_pDESEDECipher = NULL;
	}
	else 
		m_pDESCipher->ProcessBlock(m_pbData);
	
 	
	memcpy(pbMac, m_pbData, (m_bMode & 0x02) ? 8:4);
	memset(m_pbData, 0, DES_BLOCK_SIZE);
	m_bInited = FALSE;

	delete m_pDESCipher;
	m_pDESCipher = NULL;

	return TRUE;
}

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
			BYTE		bMode/* = 0x00*/
		 )
{
	BYTE pbPad[DES_BLOCK_SIZE] = {0x80};
	int nPadLen = DES_BLOCK_SIZE - nDataLen%DES_BLOCK_SIZE;
	if((bMode & 0x01) && (nPadLen == DES_BLOCK_SIZE))
		nPadLen = 0;
	int nSrcLen = nDataLen + nPadLen;

	BOOL bRet = FALSE;

	BYTE *pbSrc = new BYTE[nSrcLen];
	if(!pbSrc)
		return FALSE;

	memcpy(pbSrc, pbData, nDataLen);
	memcpy(pbSrc + nDataLen, pbPad, nPadLen);
	BOOL bSuc = FALSE;
	CMac macCaculator;

	macCaculator.Init(pbVector, pbKey, nKeyLen, bMode);

	BYTE *pbItor = pbSrc;
	BYTE *pbEnd = pbSrc + nSrcLen - DES_BLOCK_SIZE;//留下最后一块做final

	while (pbItor < pbEnd)
	{
		if(!macCaculator.Update(pbItor))
			break;
		pbItor += DES_BLOCK_SIZE;
	}
	
	if(pbItor == pbEnd)
	{
		bRet = macCaculator.Final(pbItor, pbMac);
	}

	delete pbSrc;

	return bRet;
}
