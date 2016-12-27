#ifndef TSS_TCS_DIFFERENT_H
#define TSS_TCS_DIFFERENT_H

#if !defined( TCSICALL )
#if !defined(WIN32) || defined (TCS_STATIC)
// Linux, or a Win32 static library
#define TCSICALL extern TSM_RESULT STDCALL
#elif defined (TCSDLL_EXPORTS)
// Win32 DLL build
#define TCSICALL extern __declspec(dllexport) TSM_RESULT STDCALL
#else
// Win32 DLL import
#define TCSICALL extern __declspec(dllimport) TSM_RESULT STDCALL
#endif
#endif /* TSPICALL */

#ifdef __cplusplus
extern "C" {
#endif

// Tcsi_OpenContext is used to obtain a handle to a new context.
// The context handle is used in various functions to assign resources to it. An
// application (i.e., TSP or application directly utilizing the TCS) may require more than
// one context open.
TCSICALL
Tcsi_OpenContext(
    TCS_CONTEXT_HANDLE*     hContext            // in
    );

// Tcsi_CloseContext releases all resources assigned to the given context and the
// context itself.
TCSICALL
Tcsi_CloseContext(
    TCS_CONTEXT_HANDLE      hContext            // in
    );

// Tcsi_FreeMemory frees memory allocated by TSS CS on a context base. If pMemory
// equals NULL all allocated memory blocks will be freed.
TCSICALL
Tcsi_FreeMemory(
    TCS_CONTEXT_HANDLE      hContext,           // in
    BYTE*                   pMemory             // in
    );

// Tcsi_GetCapability provides the capabilities of the TCS.
TCSICALL
Tcsi_GetCapability(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCM_CAPABILITY_AREA     capArea,            // in
    UINT32                  subCapSize,         // in
    BYTE*                   subCap,             // in
    UINT32*                 respSize,           // out
    BYTE**                  resp                // out
    );


TCSICALL
Tcsip_ReadPubek(
    TCS_CONTEXT_HANDLE      hContext,               // in
    TCM_NONCE               antiReplay,             // in
    UINT32*                 pubEndorsementKeySize,  // out
    BYTE**                  pubEndorsementKey,      // out
    TCM_DIGEST*             checksum                // out
    );

TCSICALL
Tcsip_EvictKey(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TCS_KEY_HANDLE          hKey                // in
    );

// Tcsi_RegisterKey allows registering a key  in the TCS Persistent Storage (PS). Only
// system specific keys (keys definitely bound to a certain system) should be registered
// in TCS PS.
// A key can be registered in TCS PS by providing:
// * A UUID for that key,
// * A UUID for its wrapping parent key and
// * The key blob itself.
// If the same UUID is used to register a key on different systems this key can be
// addressed on different systems by the same UUID. This may be done for a basic
// roaming key, which will wrap all user storage keys in the appropriate key hierarchy.
TCSICALL
Tcsi_RegisterKey(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_UUID                WrappingKeyUUID,    // in
    TSM_UUID                KeyUUID,            // in
    UINT32                  cKeySize,           // in
    BYTE*                   rgbKey,             // in
    UINT32                  cVendorDataSize,    // in
    BYTE*                   rgbVendorData       // in
    );

TCSICALL
Tcsi_UnregisterKey(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_UUID                KeyUUID             // in
    );

TCSICALL
Tcsi_EnumRegisteredKeys(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_UUID*               pKeyUUID,           // in
    UINT32*                 pcKeyHierarchySize, // out
    TSM_KM_KEYINFO**        ppKeyHierarchy      // out
    );

TCSICALL
Tcsi_GetRegisteredKey(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_UUID                KeyUUID,            // in
    TSM_KM_KEYINFO**        ppKeyInfo           // out
    );

TCSICALL
Tcsi_GetRegisteredKeyBlob(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_UUID                KeyUUID,            // in
    UINT32*                 pcKeySize,          // out
    BYTE**                  prgbKey             // out
    );

TCSICALL
Tcsi_GetRegisteredKeyByPublicInfo(
    TCS_CONTEXT_HANDLE      hContext,              // in
    TSM_ALGORITHM_ID        algID,                 // in
    UINT32                  ulPublicInfoLength,    // in
    BYTE*                   rgbPublicInfo,         // in
    UINT32*                 keySize,               // out
    BYTE**                  keyBlob                // out
    );

TCSICALL
Tcsi_LogPcrEvent(
    TCS_CONTEXT_HANDLE      hContext,           // in
    TSM_PCR_EVENT           Event,              // in
    UINT32*                 pNumber             // out
    );

TCSICALL
Tcsi_GetPcrEvent(
    TCS_CONTEXT_HANDLE      hContext,           // in
    UINT32                  PcrIndex,           // in
    UINT32*                 pNumber,            // in, out
    TSM_PCR_EVENT**         ppEvent             // out
    );

TCSICALL
Tcsi_GetPcrEventsByPcr(
    TCS_CONTEXT_HANDLE      hContext,           // in
    UINT32                  PcrIndex,           // in
    UINT32                  FirstEvent,         // in
    UINT32*                 pEventCount,        // in,out
    TSM_PCR_EVENT**         ppEvents            // out
    );

TCSICALL
Tcsi_GetPcrEventLog(
    TCS_CONTEXT_HANDLE      hContext,           // in
    UINT32*                 pEventCount,        // out
    TSM_PCR_EVENT**         ppEvents            // out
    );


#ifdef __cplusplus
}
#endif

#endif