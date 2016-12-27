#ifndef __TYCSP_DERTOOL_H__
#define __TYCSP_DERTOOL_H__

/////////////////////////////////////////////////////////////////////
//	class DERTool
//		DER���빤�ߡ����ӿ��ж�ȡ����ʱ�����ø��ౣ����������ĳһ��
//	�͵����ж����DER���룬Ȼ����һһ��������

class CDERTool{
//������������
private:
	//����ṹ_DER���ɱ���һ�������DER���뼰����ĳ���
	struct _DER{
		LPBYTE		pDEREncodeStr;			//DER����
		ULONG		ulLength;				//����

		_DER();
		_DER(LPBYTE pEncodeStr, ULONG ulLen);
		~_DER();
	};

//����
private:
	//����ṹ_DER��ָ��������������
	typedef CArrayTemplate<_DER*, _DER*> DERPtrArray;
	DERPtrArray		m_arDERs;				//DER���뼯

//��������������
public:
	CDERTool(){}
	~CDERTool(){ Clear(); }

//����
public:
	//���DER���뼯
	void Clear();
	//��ȡDER���뼯����Ŀ
	int GetCount() const { return m_arDERs.GetSize(); }
	//���һ��DER����
	int Add(
		LPBYTE pDEREncodeStr,			//DER����
		ULONG ulLength					//���볤��
		);
	//��ȡָ����������DER����
	BOOL GetAt(
		int nIndex,						//����
		LPBYTE& pDEREncodeStr,			//����ָ��DER�����ָ��
		ULONG& ulLength					//���ر���ĳ���
		) const;
};

#endif

