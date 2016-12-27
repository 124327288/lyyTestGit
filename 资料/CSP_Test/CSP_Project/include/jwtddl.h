// TPM Device Driver Library for the TCM package
// Copyright (C) 2008 : JetWay
// Author             : KooBoy


#ifndef _TDDL_H_
#define _TDDL_H_

#include "../include/jwtsm.h"

#if !defined(TDDLICALL)
#if !defined(WIN32) || defined (TDDL_STATIC)
// Linux, or a Win32 static library
#define TDDLICALL extern TSM_RESULT STDCALL
#elif defined (TDDL_EXPORTS)
// Win32 DLL build
#define TDDLICALL extern __declspec(dllexport) TSM_RESULT STDCALL
#else
// Win32 DLL import
#define TDDLICALL extern __declspec(dllimport) TSM_RESULT STDCALL
#endif
#endif // TSPICALL


#ifdef __cplusplus
extern "C"    {
#endif


// This function establishes a connection with the TPM device driver. Following a
// successful response to this function, the TPM device driver must be prepared to
// process TPM command requests from the calling application. The application
// utilizing the TPM DDL is guaranteed to have exclusive access to the TPM device. If
// this call fails, it may be an indication that the TPM device driver is not loaded,
// started, or the TPM cannot support any protected requests.
// This function must be called before calling Tddli_GetStatus, Tddli_GetCapability,
// Tddli_SetCapability, or Tddli_TransmitData.

// �ú�����TCM�豸������������. ʵ�ָú�����, TCM�豸��������׼����ִ��Ӧ�ó��������TCMָ��.
// TDDLȷ��Ӧ�ó���ͨ��Ψһ����ڷ���TCM�豸. ����ú�������ʧ��, ����TCM�豸��������û��װ�سɹ���
// û��������������TCM��֧���κ��ܱ���������.
// �ú���������Tddli_GetStatus, Tddli_GetCapability, Tddli_SetCapability��Tddli_TransmitData����֮ǰ����.
TDDLICALL Tddli_Open();

TDDLICALL Tddli_Close();

TDDLICALL Tddli_Cancel();

TDDLICALL
Tddli_GetStatus(
    UINT32                  ReqStatusType,      // in
    UINT32*                 pStatus             // out
    );

TDDLICALL
Tddli_TransmitData(
    BYTE*                   pTransmitBuf,       // in
    UINT32                  TransmitBufLen,     // in
    BYTE*                   pReceiveBuf,        // out
    UINT32*                 puntReceiveBufLen   // in, out
    );

TDDLICALL
Tddli_GetCapability(
    UINT32                  CapArea,            // in
    UINT32                  SubCap,             // in
    BYTE*                   pCapBuf,            // out
    UINT32*                 puntCapBufLen       // in, out
    );

TDDLICALL
Tddli_SetCapability(
    UINT32                  CapArea,            // in
    UINT32                  SubCap,             // in
    BYTE*                   pCapBuf,            // in
    UINT32                  SetCapBufLen        // in
    );


#ifdef __cplusplus
}
#endif

#endif