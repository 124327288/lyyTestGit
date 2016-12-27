// TYKeyInt.h
//=============================================================================
//
// Wuhan Tianyu Infomation Corporation
// Wuhan,
// HUBEI, 430074, P.R.China
//
// Copyright (c) 2002 Wuhan Tianyu Infomation Corporation. All Rights Reserved.
// Unpublished - rights reserved under the Copyright laws of P.R.China
//
// Revision History:
//	J. WU	2002-04-01	Init Version		
//=============================================================================

// This is the programming interfaces header for the driver of TYUSB KEY

// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the TYKEYINT_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// TYKEYINT_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
#include "windef.h"
#ifdef __cplusplus
extern "C" {
#endif

#ifdef TYKEYINT_EXPORTS
#define TYKEYINT_API __declspec(dllexport) 
#else
#define TYKEYINT_API __declspec(dllimport) 
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

//typedef WORD TYKEYSTATUS;
typedef WORD TYKEYSTATUS;
typedef HANDLE TYKEYHANDLE ;


///////////////////////////////////////////////////////////////////////////////
//					PROGRAMMING INTERFACES(CPU CARD)						 //
///////////////////////////////////////////////////////////////////////////////
// Get all the status of TYKey, NOTEs:the space of keyStatus is greater than 16
TYKEYINT_API void _stdcall TYKey_Status( UCHAR* keyStatus );

// inform that the status of key is changed
TYKEYINT_API void _stdcall TYKey_Change();

// Retrieve the number of TYKey connected to PC
TYKEYINT_API TYKEYSTATUS _stdcall TYKey_ListTYKey(
	OUT	int *nNumber					// Number of TYkey
	);

// Open the specified TYKey
TYKEYINT_API TYKEYSTATUS _stdcall TYKey_OpenTYKey(
	IN	int			nKeyIndex,			// Valid key index(0,1,2,3...)
	OUT	TYKEYHANDLE *hKey				// TYkey handle
	);

// Close the specified TYKey
TYKEYINT_API TYKEYSTATUS _stdcall TYKey_CloseTYKey(
	IN	TYKEYHANDLE hKey				// TYkey handle
	);

// Cold reset the specified TYKey
TYKEYINT_API TYKEYSTATUS _stdcall TYKey_ColdReset(
	IN	TYKEYHANDLE		hKey,				// TYkey handle
	OUT	int				*nATRLen,				// ATR length
	OUT unsigned char	*pATRContext			// ATR Context
	);
					
// Send command to the specified TYKey
TYKEYINT_API TYKEYSTATUS _stdcall TYKey_SendCommand(
	IN	TYKEYHANDLE		hKey,				// TYkey handle
	IN	int				nCommandLen,			// Command length
	IN	unsigned char	*pCommandContext,		// Command context
	OUT	int				*nResponseLen,			// Response length (-1: Operation Failed)
	OUT	unsigned char	*pResponseContext		// Response context
	);

// Check whether the card exist or not
TYKEYINT_API int _stdcall TYKey_CardExist(
	IN TYKEYHANDLE		hKey					// TYkey handle
	);

// Check whether the Key exist or not
TYKEYINT_API int _stdcall TYKey_KeyExist(
	IN TYKEYHANDLE		hKey					// TYkey handle
	);

// Begin Send Command
TYKEYINT_API void _stdcall TYKey_BeginTrans(
	);

// End Send Command
TYKEYINT_API void _stdcall TYKey_EndTrans(
	);

// Power on TYKey
TYKEYINT_API int _stdcall TYKey_PowerOn(
	IN TYKEYHANDLE		hKey					// TYkey handle
	);

// Power down TYkey
TYKEYINT_API int _stdcall TYKey_PowerDown(
	IN TYKEYHANDLE		hKey					// TYkey handle
	);

///////////////////////////////////////////////////////////////////////////////
//					PROGRAMMING INTERFACES(MEMORY CARD)						 //
///////////////////////////////////////////////////////////////////////////////

// Read Data From Memory Card: AT24
TYKEYINT_API TYKEYSTATUS _stdcall TYKey_ReadAT24(
	IN	TYKEYHANDLE		hKey,
	IN	int				nOffset,
	IN	int				nLength,
	OUT	int				*nResponseLen,
	OUT unsigned char	*pResponseContext
	);
// Write Data to Memmory Card: AT24
TYKEYINT_API TYKEYSTATUS _stdcall TYKey_WriteAT24(
	IN	TYKEYHANDLE		hKey,
	IN	int				nOffset,
	IN	int				nLength,
	IN	unsigned char	*pData
	);

///////////////////////////////////////////////////////////////////////////////
//					STATUS MESSAGEs OF TYKEY								 //
///////////////////////////////////////////////////////////////////////////////

#define	STATUS_TYKEY_DEVICE_ERROR	0x8401		// device error

#define STATUS_TYKEY_NO_TYKEY		0x8402		// can't detect TYKEY

#define STATUS_TYKEY_CLOSE_ERROR	0x8403		// close error

#define STATUS_TYKEY_IO_TIMEOUT		0xff84		// time out

#define STATUS_TYKEY_NO_CARD		0xff85		// no card

#define STATUS_TYKEY_SUCCESS		0x9000		// operation successful

// Read throught the documents about the smart card you are using for other 
// status messages returned from the smart card
#ifdef __cplusplus
} //extern "C"
#endif