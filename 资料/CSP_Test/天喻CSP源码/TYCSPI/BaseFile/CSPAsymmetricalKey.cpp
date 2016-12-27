//CSPAsymmetricalKey.cpp
#include <stdAfx.h>
#include "cspkey.h"

CCSPAsymmetricalKey::CCSPAsymmetricalKey(
		CCSPKeyContainer* pKeyContainer,
		ULONG ulAlgId,
		BOOL bToken
		//BOOL bExtractable,
		//BOOL bPrivate
		) :CCSPKey(pKeyContainer, ulAlgId,bToken/*,bExtractable,bPrivate*/)
{
	
}

CCSPAsymmetricalKey::CCSPAsymmetricalKey(
		CCSPAsymmetricalKey & src
		) : CCSPKey(src)
{
	
}
CCSPAsymmetricalKey::~CCSPAsymmetricalKey()
{

	CCSPKey::~CCSPKey();
}

BOOL CCSPAsymmetricalKey::Create(
		DWORD bitlen,
		DWORD dwFlags
		)
{
	return CCSPKey::Create(bitlen,dwFlags);
}

BOOL CCSPAsymmetricalKey::Encrypt(
	CCSPHashObject* pHash,		// in
	BOOL Final,					// in
	DWORD dwFlags,				// in
	BYTE *pbData,				// in, out
	DWORD *pdwDataLen,			// in, out
	DWORD dwBufLen				// in
	)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}

BOOL CCSPAsymmetricalKey::Decrypt(
	CCSPHashObject* pHash,			// in
	BOOL Final,						// in
	DWORD dwFlags,					// in
	BYTE *pbData,					// in, out
	DWORD *pdwDataLen				// in, out
	)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}


BOOL CCSPAsymmetricalKey::SignHash(
	CCSPHashObject* pHash,           // in
	LPCWSTR sDescription,			// in
	DWORD dwFlags,					// in
	BYTE *pbSignature,				// out
	DWORD *pdwSigLen				// in, out
	)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}

BOOL CCSPAsymmetricalKey::VerifySignature(
	CCSPHashObject* pHash,			// in
	CONST BYTE *pbSignature,		// in
	DWORD dwSigLen,					// in
	LPCWSTR sDescription,			// in
	DWORD dwFlags					// in
	)
{
	SETLASTERROR(NTE_BAD_KEY);
	return FALSE;
}
