#ifndef __TYCSP_DERTOOL_H__
#define __TYCSP_DERTOOL_H__

/////////////////////////////////////////////////////////////////////
//	class DERTool
//		DER编码工具。当从卡中读取对象时，可用该类保存所读出的某一类
//	型的所有对象的DER编码，然后再一一创建对象。

class CDERTool{
//定义数据类型
private:
	//定义结构_DER，可保存一个对象的DER编码及编码的长度
	struct _DER{
		LPBYTE		pDEREncodeStr;			//DER编码
		ULONG		ulLength;				//长度

		_DER();
		_DER(LPBYTE pEncodeStr, ULONG ulLen);
		~_DER();
	};

//属性
private:
	//定义结构_DER的指针数组数据类型
	typedef CArrayTemplate<_DER*, _DER*> DERPtrArray;
	DERPtrArray		m_arDERs;				//DER编码集

//构造与析构函数
public:
	CDERTool(){}
	~CDERTool(){ Clear(); }

//方法
public:
	//清空DER编码集
	void Clear();
	//获取DER编码集的数目
	int GetCount() const { return m_arDERs.GetSize(); }
	//添加一条DER编码
	int Add(
		LPBYTE pDEREncodeStr,			//DER编码
		ULONG ulLength					//编码长度
		);
	//获取指定索引处的DER编码
	BOOL GetAt(
		int nIndex,						//索引
		LPBYTE& pDEREncodeStr,			//返回指向DER编码的指针
		ULONG& ulLength					//返回编码的长度
		) const;
};

#endif

