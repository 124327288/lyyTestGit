///////////////////////////////////////////////////////////////////////////////
//	

#ifndef __ARRAY_TEMPLATE_H__
#define __ARRAY_TEMPLATE_H__

#ifndef _INC_NEW
	#include <new.h>
#endif

///////////////////////////////////////////////////////////////////////////////
//	Helper Functions

inline BOOL __IsValidAddress(const void* lp, unsigned int nBytes,
	BOOL bReadWrite)
{
	// simple version using Win-32 APIs for pointer validation.
	return (lp != NULL && !IsBadReadPtr(lp, nBytes) &&
		(!bReadWrite || !IsBadWritePtr((LPVOID)lp, nBytes)));
}

template<class TYPE>
inline void  __ConstructElements(TYPE* pElements, int nCount)
{
	assert(nCount == 0 ||
		__IsValidAddress(pElements, nCount * sizeof(TYPE), TRUE));

	// first do bit-wise zero initialization
	memset((void*)pElements, 0, nCount * sizeof(TYPE));

	// then call the constructor(s)
	for (; nCount--; pElements++)
		::new((void*)pElements) TYPE;
}

template<class TYPE>
inline void  __DestructElements(TYPE* pElements, int nCount)
{
	assert(nCount == 0 ||
		__IsValidAddress(pElements, nCount * sizeof(TYPE), TRUE));

	// call the destructor(s)
	for (; nCount--; pElements++)
		pElements->~TYPE();
}

template<class TYPE>
inline void  __CopyElements(TYPE* pDest, const TYPE* pSrc, int nCount)
{
	assert(nCount == 0 ||
		__IsValidAddress(pDest, nCount * sizeof(TYPE), TRUE));
	assert(nCount == 0 ||
		__IsValidAddress(pSrc, nCount * sizeof(TYPE), TRUE));

	// default is element-copy using assignment
	while (nCount--)
		*pDest++ = *pSrc++;
}

/////////////////////////////////////////////////////////////////////////////
// class CArrayTemplate

template<class TYPE, class ARG_TYPE>
class CArrayTemplate
{
public:
// Construction
	CArrayTemplate();

// Attributes
	int GetSize() const;
	int GetUpperBound() const;
	void SetSize(int nNewSize, int nGrowBy = -1);

// Operations
	// Clean up
	void FreeExtra();
	void RemoveAll();

	// Accessing elements
	TYPE GetAt(int nIndex) const;
	void SetAt(int nIndex, ARG_TYPE newElement);
	TYPE& ElementAt(int nIndex);

	// Direct Access to the element data (may return NULL)
	const TYPE* GetData() const;
	TYPE* GetData();

	// Potentially growing the array
	void SetAtGrow(int nIndex, ARG_TYPE newElement);
	int Add(ARG_TYPE newElement);
	int Append(const CArrayTemplate& src);
	void Copy(const CArrayTemplate& src);

	// overloaded operator helpers
	TYPE operator[](int nIndex) const;
	TYPE& operator[](int nIndex);

	// Operations that move elements around
	void InsertAt(int nIndex, ARG_TYPE newElement, int nCount = 1);
	void RemoveAt(int nIndex, int nCount = 1);
	void InsertAt(int nStartIndex, CArrayTemplate* pNewArray);

// Implementation
protected:
	TYPE* m_pData;   // the actual array of data
	int m_nSize;     // # of elements (upperBound - 1)
	int m_nMaxSize;  // max allocated
	int m_nGrowBy;   // grow amount

public:
	~CArrayTemplate();
};

/////////////////////////////////////////////////////////////////////////////
// CArrayTemplate<TYPE, ARG_TYPE> inline functions

template<class TYPE, class ARG_TYPE>
inline int CArrayTemplate<TYPE, ARG_TYPE>::GetSize() const
	{ return m_nSize; }
template<class TYPE, class ARG_TYPE>
inline int CArrayTemplate<TYPE, ARG_TYPE>::GetUpperBound() const
	{ return m_nSize-1; }
template<class TYPE, class ARG_TYPE>
inline void CArrayTemplate<TYPE, ARG_TYPE>::RemoveAll()
	{ SetSize(0, -1); }
template<class TYPE, class ARG_TYPE>
inline TYPE CArrayTemplate<TYPE, ARG_TYPE>::GetAt(int nIndex) const
	{ assert(nIndex >= 0 && nIndex < m_nSize);
		return m_pData[nIndex]; }
template<class TYPE, class ARG_TYPE>
inline void CArrayTemplate<TYPE, ARG_TYPE>::SetAt(int nIndex, ARG_TYPE newElement)
	{ assert(nIndex >= 0 && nIndex < m_nSize);
		m_pData[nIndex] = newElement; }
template<class TYPE, class ARG_TYPE>
inline TYPE& CArrayTemplate<TYPE, ARG_TYPE>::ElementAt(int nIndex)
	{ assert(nIndex >= 0 && nIndex < m_nSize);
		return m_pData[nIndex]; }
template<class TYPE, class ARG_TYPE>
inline const TYPE* CArrayTemplate<TYPE, ARG_TYPE>::GetData() const
	{ return (const TYPE*)m_pData; }
template<class TYPE, class ARG_TYPE>
inline TYPE* CArrayTemplate<TYPE, ARG_TYPE>::GetData()
	{ return (TYPE*)m_pData; }
template<class TYPE, class ARG_TYPE>
inline int CArrayTemplate<TYPE, ARG_TYPE>::Add(ARG_TYPE newElement)
	{ int nIndex = m_nSize;
		SetAtGrow(nIndex, newElement);
		return nIndex; }
template<class TYPE, class ARG_TYPE>
inline TYPE CArrayTemplate<TYPE, ARG_TYPE>::operator[](int nIndex) const
	{ return GetAt(nIndex); }
template<class TYPE, class ARG_TYPE>
inline TYPE& CArrayTemplate<TYPE, ARG_TYPE>::operator[](int nIndex)
	{ return ElementAt(nIndex); }


/////////////////////////////////////////////////////////////////////////////
// CArrayTemplate<TYPE, ARG_TYPE> out-of-line functions

template<class TYPE, class ARG_TYPE>
CArrayTemplate<TYPE, ARG_TYPE>::CArrayTemplate()
{
	m_pData = NULL;
	m_nSize = m_nMaxSize = m_nGrowBy = 0;
}

template<class TYPE, class ARG_TYPE>
CArrayTemplate<TYPE, ARG_TYPE>::~CArrayTemplate()
{
	if (m_pData != NULL)
	{
		__DestructElements<TYPE>(m_pData, m_nSize);
		delete[] (BYTE*)m_pData;
	}
}

template<class TYPE, class ARG_TYPE>
void CArrayTemplate<TYPE, ARG_TYPE>::SetSize(int nNewSize, int nGrowBy)
{
	assert(nNewSize >= 0);

	if (nGrowBy != -1)
		m_nGrowBy = nGrowBy;  // set new size

	if (nNewSize == 0)
	{
		// shrink to nothing
		if (m_pData != NULL)
		{
			__DestructElements<TYPE>(m_pData, m_nSize);
			delete[] (BYTE*)m_pData;
			m_pData = NULL;
		}
		m_nSize = m_nMaxSize = 0;
	}
	else if (m_pData == NULL)
	{
		// create one with exact size
#ifdef SIZE_T_MAX
		assert(nNewSize <= SIZE_T_MAX/sizeof(TYPE));    // no overflow
#endif
		m_pData = (TYPE*) new BYTE[nNewSize * sizeof(TYPE)];
		__ConstructElements<TYPE>(m_pData, nNewSize);
		m_nSize = m_nMaxSize = nNewSize;
	}
	else if (nNewSize <= m_nMaxSize)
	{
		// it fits
		if (nNewSize > m_nSize)
		{
			// initialize the new elements
			__ConstructElements<TYPE>(&m_pData[m_nSize], nNewSize-m_nSize);
		}
		else if (m_nSize > nNewSize)
		{
			// destroy the old elements
			__DestructElements<TYPE>(&m_pData[nNewSize], m_nSize-nNewSize);
		}
		m_nSize = nNewSize;
	}
	else
	{
		// otherwise, grow array
		int nGrowBy = m_nGrowBy;
		if (nGrowBy == 0)
		{
			// heuristically determine growth when nGrowBy == 0
			//  (this avoids heap fragmentation in many situations)
			nGrowBy = m_nSize / 8;
			nGrowBy = (nGrowBy < 4) ? 4 : ((nGrowBy > 1024) ? 1024 : nGrowBy);
		}
		int nNewMax;
		if (nNewSize < m_nMaxSize + nGrowBy)
			nNewMax = m_nMaxSize + nGrowBy;  // granularity
		else
			nNewMax = nNewSize;  // no slush

		assert(nNewMax >= m_nMaxSize);  // no wrap around
#ifdef SIZE_T_MAX
		assert(nNewMax <= SIZE_T_MAX/sizeof(TYPE)); // no overflow
#endif
		TYPE* pNewData = (TYPE*) new BYTE[nNewMax * sizeof(TYPE)];

		// copy new data from old
		memcpy(pNewData, m_pData, m_nSize * sizeof(TYPE));

		// construct remaining elements
		assert(nNewSize > m_nSize);
		__ConstructElements<TYPE>(&pNewData[m_nSize], nNewSize-m_nSize);

		// get rid of old stuff (note: no destructors called)
		delete[] (BYTE*)m_pData;
		m_pData = pNewData;
		m_nSize = nNewSize;
		m_nMaxSize = nNewMax;
	}
}

template<class TYPE, class ARG_TYPE>
int CArrayTemplate<TYPE, ARG_TYPE>::Append(const CArrayTemplate& src)
{
	assert(this != &src);   // cannot append to itself

	int nOldSize = m_nSize;
	SetSize(m_nSize + src.m_nSize);
	__CopyElements<TYPE>(m_pData + nOldSize, src.m_pData, src.m_nSize);
	return nOldSize;
}

template<class TYPE, class ARG_TYPE>
void CArrayTemplate<TYPE, ARG_TYPE>::Copy(const CArrayTemplate& src)
{
	assert(this != &src);   // cannot append to itself

	SetSize(src.m_nSize);
	__CopyElements<TYPE>(m_pData, src.m_pData, src.m_nSize);
}

template<class TYPE, class ARG_TYPE>
void CArrayTemplate<TYPE, ARG_TYPE>::FreeExtra()
{
	if (m_nSize != m_nMaxSize)
	{
		// shrink to desired size
#ifdef SIZE_T_MAX
		assert(m_nSize <= SIZE_T_MAX/sizeof(TYPE)); // no overflow
#endif
		TYPE* pNewData = NULL;
		if (m_nSize != 0)
		{
			pNewData = (TYPE*) new BYTE[m_nSize * sizeof(TYPE)];
			// copy new data from old
			memcpy(pNewData, m_pData, m_nSize * sizeof(TYPE));
		}

		// get rid of old stuff (note: no destructors called)
		delete[] (BYTE*)m_pData;
		m_pData = pNewData;
		m_nMaxSize = m_nSize;
	}
}

template<class TYPE, class ARG_TYPE>
void CArrayTemplate<TYPE, ARG_TYPE>::SetAtGrow(int nIndex, ARG_TYPE newElement)
{
	assert(nIndex >= 0);

	if (nIndex >= m_nSize)
		SetSize(nIndex+1, -1);
	m_pData[nIndex] = newElement;
}

template<class TYPE, class ARG_TYPE>
void CArrayTemplate<TYPE, ARG_TYPE>::InsertAt(int nIndex, ARG_TYPE newElement, int nCount /*=1*/)
{
	assert(nIndex >= 0);    // will expand to meet need
	assert(nCount > 0);     // zero or negative size not allowed

	if (nIndex >= m_nSize)
	{
		// adding after the end of the array
		SetSize(nIndex + nCount, -1);   // grow so nIndex is valid
	}
	else
	{
		// inserting in the middle of the array
		int nOldSize = m_nSize;
		SetSize(m_nSize + nCount, -1);  // grow it to new size
		// destroy intial data before copying over it
		__DestructElements<TYPE>(&m_pData[nOldSize], nCount);
		// shift old data up to fill gap
		memmove(&m_pData[nIndex+nCount], &m_pData[nIndex],
			(nOldSize-nIndex) * sizeof(TYPE));

		// re-init slots we copied from
		__ConstructElements<TYPE>(&m_pData[nIndex], nCount);
	}

	// insert new value in the gap
	assert(nIndex + nCount <= m_nSize);
	while (nCount--)
		m_pData[nIndex++] = newElement;
}

template<class TYPE, class ARG_TYPE>
void CArrayTemplate<TYPE, ARG_TYPE>::RemoveAt(int nIndex, int nCount)
{
	assert(nIndex >= 0);
	assert(nCount >= 0);
	assert(nIndex + nCount <= m_nSize);

	// just remove a range
	int nMoveCount = m_nSize - (nIndex + nCount);
	__DestructElements<TYPE>(&m_pData[nIndex], nCount);
	if (nMoveCount)
		memmove(&m_pData[nIndex], &m_pData[nIndex + nCount],
			nMoveCount * sizeof(TYPE));
	m_nSize -= nCount;
}

template<class TYPE, class ARG_TYPE>
void CArrayTemplate<TYPE, ARG_TYPE>::InsertAt(int nStartIndex, CArrayTemplate* pNewArray)
{
	assert(pNewArray != NULL);
	assert(nStartIndex >= 0);

	if (pNewArray->GetSize() > 0)
	{
		InsertAt(nStartIndex, pNewArray->GetAt(0), pNewArray->GetSize());
		for (int i = 0; i < pNewArray->GetSize(); i++)
			SetAt(nStartIndex + i, pNewArray->GetAt(i));
	}
}


#endif