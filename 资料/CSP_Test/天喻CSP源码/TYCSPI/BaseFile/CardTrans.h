/********************************************************************
	File: 			cardtrans.h
	Created:		2003/10/08
	Author:			���ػ�
	
	Description:	�Զ�ά�������¼�

	Update history:
*********************************************************************/
#ifndef __CARDTRANS_H__
#define __CARDTRANS_H__

#include "cspobject.h"

class CCardTrans
{
public:
	CCardTrans(CTYCSP * pCsp) {m_pCsp = pCsp;};
	~CCardTrans() {m_pCsp->EndTransaction();};
	BOOL BeginTrans() {return m_pCsp->BeginTransaction();};
protected:
	CTYCSP *m_pCsp;
};

#endif
