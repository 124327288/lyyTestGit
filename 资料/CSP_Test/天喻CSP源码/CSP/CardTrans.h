/********************************************************************
	File: 			cardtrans.h
	Created:		2003/10/08
	Author:			付秦华
	
	Description:	自动维护卡的事件

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
