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

// 该函数与TCM设备驱动建立连接. 实现该函数后, TCM设备驱动必须准备好执行应用程序所需的TCM指令.
// TDDL确保应用程序通过唯一的入口访问TCM设备. 如果该函数调用失败, 表明TCM设备驱动可能没有装载成功、
// 没有正常启动或者TCM不支持任何受保护的请求.
// 该函数必须在Tddli_GetStatus, Tddli_GetCapability, Tddli_SetCapability和Tddli_TransmitData函数之前调用.
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