#ifndef JW_TSM_ERROR_H
#define JW_TSM_ERROR_H


#pragma pack(push)
#pragma pack(1)

//#include "trousers/tss/tss_error.h"
//#include "trousers/tss/tcs_error.h"
//#include "trousers/tcslog.h"
//#include "trousers/tss/tddl_error.h"

//////////////////////////////////////////////////////////////////////////
// tsm/TSM_error.h
//////////////////////////////////////////////////////////////////////////

//
// error coding scheme for a Microsoft Windows platform -
// refer to the TSM Specification Parts
//
//  Values are 32 bit values layed out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------+-----------------------+
//  |Lev|C|R|     Facility          | Layer |         Code          |
//  +---+-+-+-----------------------+-------+-----------------------+
//  | Platform specific coding      | TSM error coding system       |
//  +---+-+-+-----------------------+-------+-----------------------+
//
//      Lev - is the Level code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag  (must actually be set)
//
//      R - is a reserved bit    (unused)
//
//      Facility - is the facility code: TCPA: proposal 0x028
//
//      Code - is the facility's status code
//

//
// definitions for the code level information
//
#define TSM_LEVEL_SUCCESS  0x00     // code level success 
#define TSM_LEVEL_INFO     0x40000000L    // code level information
#define TSM_LEVEL_WARNING  0x80000000L    // code level warning
#define TSM_LEVEL_ERROR    0xC0000000L    // code level error

//
// some defines for the platform specific information
//
#define FACILITY_TSM            0x28L     // facility number for TCPA return codes
#define FACILITY_TSM_CODEPOS   (FACILITY_TSM << 16)  // shift the facility info to the code 
                                                                        // position

#define TSM_CUSTOM_CODEFLAG     0x20000000L    // bit position for the custom flag in 
                                                                        // return code

#define TSM_LAYER_TDDL                          ((UINT32)0x00001000L)
#define TSM_LAYER_TCS                           ((UINT32)0x00002000L)
#define TSM_LAYER_TSP                           ((UINT32)0x00003000L)

//#define TSM_ERROR_LAYER(x)	(x & 0x3000)
//#define TSM_ERROR_CODE(x)	(x & TSM_MAX_ERROR)

#undef TSPERR
#define TSPERR(x)		(x | TSM_LAYER_TSP | TSM_LEVEL_ERROR)

#undef TCSERR
#define TCSERR(x)		(x | TSM_LAYER_TCS | TSM_LEVEL_ERROR)

#undef TDDLERR
#define TDDLERR(x)		(x | TSM_LAYER_TDDL | TSM_LEVEL_ERROR)

//
//
// TSM error return codes
//
//
#ifndef TSM_E_BASE
#define TSM_E_BASE    0x00000000L
#endif // TSM_E_BASE
#ifndef TSM_W_BASE
#define TSM_W_BASE    0x00000000L
#endif // TSM_W_BASE
#ifndef TSM_I_BASE
#define TSM_I_BASE    0x00000000L
#endif // TSM_I_BASE

//
// basic error return codes common to all TSM Service Provider Interface methods
// and returned by all TSM SW stack components
//

//
// MessageId: TSM_SUCCESS
//
// MessageText:
//
//  Successful completion of the operation.
//
#define TSM_SUCCESS     (UINT32)(0x00000000L)

//
// MessageId: TSM_E_FAIL
//
// MessageText:
//
//  An internal error has been detected, but the source is unknown.
//
#define TSM_E_FAIL     (UINT32)(TSM_E_BASE + 0x002L)

//
// MessageId: TSM_E_BAD_PARAMETER
//
// MessageText:
//
// One or more parameter is bad.
//
#define TSM_E_BAD_PARAMETER    (UINT32)(TSM_E_BASE + 0x003L)

//
// MessageId: TSM_E_INTERNAL_ERROR
//
// MessageText:
//
//  An internal SW error has been detected.
//
#define TSM_E_INTERNAL_ERROR    (UINT32)(TSM_E_BASE + 0x004L)

//
// MessageId: TSM_E_OUTOFMEMORY
//
// MessageText:
//
// Ran out of memory.
//
#define TSM_E_OUTOFMEMORY    (UINT32)(TSM_E_BASE + 0x005L)

//
// MessageId: TSM_E_NOTIMPL
//
// MessageText:
//
// Not implemented.
//
#define TSM_E_NOTIMPL     (UINT32)(TSM_E_BASE + 0x006L)

//
// MessageId: TSM_E_KEY_ALREADY_REGISTERED
//
// MessageText:
//
//  Key is already registered
//
#define TSM_E_KEY_ALREADY_REGISTERED  (UINT32)(TSM_E_BASE + 0x008L)


//
// MessageId: TSM_E_TCM_UNEXPECTED
//
// MessageText:
//
//  An unexpected TCM error has occurred.
//
#define TSM_E_TCM_UNEXPECTED    (UINT32)(TSM_E_BASE + 0x010L)

//
// MessageId: TSM_E_COMM_FAILURE
//
// MessageText:
//
//  A communications error with the TCM has been detected.
//
#define TSM_E_COMM_FAILURE    (UINT32)(TSM_E_BASE + 0x011L)

//
// MessageId: TSM_E_TIMEOUT
//
// MessageText:
//
//  The operation has timed out.
//
#define TSM_E_TIMEOUT     (UINT32)(TSM_E_BASE + 0x012L)

//
// MessageId: TSM_E_TCM_UNSUPPORTED_FEATURE
//
// MessageText:
//
//  The TCM does not support the requested feature.
//
#define TSM_E_TCM_UNSUPPORTED_FEATURE  (UINT32)(TSM_E_BASE + 0x014L)

//
// MessageId: TSM_E_CANCELED
//
// MessageText:
//
//  The action was canceled by request.
//
#define TSM_E_CANCELED     (UINT32)(TSM_E_BASE + 0x016L)

//
// MessageId: TSM_E_PS_KEY_NOTFOUND
//
// MessageText:
//
// The key cannot be found in the persistent storage database.
//
#define TSM_E_PS_KEY_NOTFOUND    (UINT32)(TSM_E_BASE + 0x020L)
//
// MessageId: TSM_E_PS_KEY_EXISTS
//
// MessageText:
//
// The key already exists in the persistent storage database.
//
#define TSM_E_PS_KEY_EXISTS            (UINT32)(TSM_E_BASE + 0x021L)

//
// MessageId: TSM_E_PS_BAD_KEY_STATE
//
// MessageText:
//
// The key data set not valid in the persistent storage database.
//
#define TSM_E_PS_BAD_KEY_STATE         (UINT32)(TSM_E_BASE + 0x022L)


//
// error codes returned by specific TSM Service Provider Interface methods
// offset TSM_TSPI_OFFSET
//

//
// MessageId: TSM_E_INVALID_OBJECT_TYPE
//
// MessageText:
//
// Object type not valid for this operation.
//
#define TSM_E_INVALID_OBJECT_TYPE   (UINT32)(TSM_E_BASE + 0x101L)

//
// MessageId: TSM_E_NO_CONNECTION
//
// MessageText:
//
// Core Service connection doesn't exist.
//
#define TSM_E_NO_CONNECTION    (UINT32)(TSM_E_BASE + 0x102L)
 
//
// MessageId: TSM_E_CONNECTION_FAILED
//
// MessageText:
//
// Core Service connection failed.
//
#define TSM_E_CONNECTION_FAILED   (UINT32)(TSM_E_BASE + 0x103L)

//
// MessageId: TSM_E_CONNECTION_BROKEN
//
// MessageText:
//
// Communication with Core Service failed.
//
#define TSM_E_CONNECTION_BROKEN   (UINT32)(TSM_E_BASE + 0x104L)

//
// MessageId: TSM_E_HASH_INVALID_ALG
//
// MessageText:
//
// Invalid hash algorithm.
//
#define TSM_E_HASH_INVALID_ALG   (UINT32)(TSM_E_BASE + 0x105L)

//
// MessageId: TSM_E_HASH_INVALID_LENGTH
//
// MessageText:
//
// Hash length is inconsistent with hash algorithm.
//
#define TSM_E_HASH_INVALID_LENGTH   (UINT32)(TSM_E_BASE + 0x106L)

//
// MessageId: TSM_E_HASH_NO_DATA
//
// MessageText:
//
// Hash object has no internal hash value.
//
#define TSM_E_HASH_NO_DATA    (UINT32)(TSM_E_BASE + 0x107L)


//
// MessageId: TSM_E_INVALID_ATTRIB_FLAG
//
// MessageText:
//
// Flag value for attrib-functions inconsistent.
//
#define TSM_E_INVALID_ATTRIB_FLAG   (UINT32)(TSM_E_BASE + 0x109L)

//
// MessageId: TSM_E_INVALID_ATTRIB_SUBFLAG
//
// MessageText:
//
// Subflag value for attrib-functions inconsistent.
//
#define TSM_E_INVALID_ATTRIB_SUBFLAG  (UINT32)(TSM_E_BASE + 0x10AL)

//
// MessageId: TSM_E_INVALID_ATTRIB_DATA
//
// MessageText:
//
// Data for attrib-functions invalid.
//
#define TSM_E_INVALID_ATTRIB_DATA   (UINT32)(TSM_E_BASE + 0x10BL)

//
// MessageId: TSM_E_INVALID_OBJECT_INITFLAG
//
// MessageText:
//
// Wrong flag information for object creation.
// 
// The alternate spelling is supported to be compatible with a typo
// in the 1.1b header files.
//
#define TSM_E_INVALID_OBJECT_INIT_FLAG  (UINT32)(TSM_E_BASE + 0x10CL)
#define TSM_E_INVALID_OBJECT_INITFLAG   TSM_E_INVALID_OBJECT_INIT_FLAG
 
//
// MessageId: TSM_E_NO_PCRS_SET
//
// MessageText:
//
// No PCR register are selected or set.
//
#define TSM_E_NO_PCRS_SET    (UINT32)(TSM_E_BASE + 0x10DL)

//
// MessageId: TSM_E_KEY_NOT_LOADED
//
// MessageText:
//
// The addressed key is currently not loaded.
//
#define TSM_E_KEY_NOT_LOADED    (UINT32)(TSM_E_BASE + 0x10EL)
 
//
// MessageId: TSM_E_KEY_NOT_SET
//
// MessageText:
//
// No key information is currently available.
//
#define TSM_E_KEY_NOT_SET    (UINT32)(TSM_E_BASE + 0x10FL)
      
//
// MessageId: TSM_E_VALIDATION_FAILED
//
// MessageText:
//
// Internal validation of data failed.
//
#define TSM_E_VALIDATION_FAILED   (UINT32)(TSM_E_BASE + 0x110L)

//
// MessageId: TSM_E_TSP_AUTHREQUIRED
//
// MessageText:
//
// Authorization is required.
//
#define TSM_E_TSP_AUTHREQUIRED   (UINT32)(TSM_E_BASE + 0x111L)

//
// MessageId: TSM_E_TSP_AUTH2REQUIRED
//
// MessageText:
//
// Multiple authorization is required.
//
#define TSM_E_TSP_AUTH2REQUIRED   (UINT32)(TSM_E_BASE + 0x112L)

//
// MessageId: TSM_E_TSP_AUTHFAIL
//
// MessageText:
//
// Authorization failed.
//
#define TSM_E_TSP_AUTHFAIL    (UINT32)(TSM_E_BASE + 0x113L)

//
// MessageId: TSM_E_TSP_AUTH2FAIL
//
// MessageText:
//
// Multiple authorization failed.
//
#define TSM_E_TSP_AUTH2FAIL    (UINT32)(TSM_E_BASE + 0x114L)
 
//
// MessageId: TSM_E_KEY_NO_MIGRATION_POLICY
//
// MessageText:
//
// There's no migration policy object set for the addressed key.
//
#define TSM_E_KEY_NO_MIGRATION_POLICY  (UINT32)(TSM_E_BASE + 0x115L) 

//
// MessageId: TSM_E_POLICY_NO_SECRET
//
// MessageText:
//
// No secret information is currently available for the addressed policy object.
//
#define TSM_E_POLICY_NO_SECRET   (UINT32)(TSM_E_BASE + 0x116L)

//
// MessageId: TSM_E_INVALID_OBJ_ACCESS
//
// MessageText:
//
// The operation failed due to an invalid object status.
//
#define TSM_E_INVALID_OBJ_ACCESS   (UINT32)(TSM_E_BASE + 0x117L)

//
// MessageId: TSM_E_INVALID_ENCSCHEME
//
// MessageText:
//
// 
//
#define TSM_E_INVALID_ENCSCHEME   (UINT32)(TSM_E_BASE + 0x118L)


//
// MessageId: TSM_E_INVALID_SIGSCHEME
//
// MessageText:
//
// 
//
#define TSM_E_INVALID_SIGSCHEME   (UINT32)(TSM_E_BASE + 0x119L)

//
// MessageId: TSM_E_ENC_INVALID_LENGTH
//
// MessageText:
//
// 
//
#define TSM_E_ENC_INVALID_LENGTH   (UINT32)(TSM_E_BASE + 0x120L)


//
// MessageId: TSM_E_ENC_NO_DATA
//
// MessageText:
//
// 
//
#define TSM_E_ENC_NO_DATA    (UINT32)(TSM_E_BASE + 0x121L)

//
// MessageId: TSM_E_ENC_INVALID_TYPE
//
// MessageText:
//
// 
//
#define TSM_E_ENC_INVALID_TYPE   (UINT32)(TSM_E_BASE + 0x122L)


//
// MessageId: TSM_E_INVALID_KEYUSAGE
//
// MessageText:
//
// 
//
#define TSM_E_INVALID_KEYUSAGE   (UINT32)(TSM_E_BASE + 0x123L)

//
// MessageId: TSM_E_VERIFICATION_FAILED
//
// MessageText:
//
// 
//
#define TSM_E_VERIFICATION_FAILED   (UINT32)(TSM_E_BASE + 0x124L)

//
// MessageId: TSM_E_HASH_NO_IDENTIFIER
//
// MessageText:
//
// Hash algorithm identifier not set.
//
#define TSM_E_HASH_NO_IDENTIFIER   (UINT32)(TSM_E_BASE + 0x125L)

//
// MessageId: TSM_E_INVALID_HANDLE
//
// MessageText:
//
//  An invalid handle
//
#define TSM_E_INVALID_HANDLE    (UINT32)(TSM_E_BASE + 0x126L)

//
// MessageId: TSM_E_SILENT_CONTEXT
//
// MessageText:
//
//  A silent context requires user input
//
#define TSM_E_SILENT_CONTEXT           (UINT32)(TSM_E_BASE + 0x127L)

//
// MessageId: TSM_E_EK_CHECKSUM
//
// MessageText:
//
// TSP is instructed to verify the EK checksum and it does not verify.
//
#define TSM_E_EK_CHECKSUM             (UINT32)(TSM_E_BASE + 0x128L)


//
// MessageId: TSM_E_DELGATION_NOTSET
//
// MessageText:
//
// The Policy object does not have a delegation blob set.
//
#define TSM_E_DELEGATION_NOTSET      (UINT32)(TSM_E_BASE + 0x129L)

//
// MessageId: TSM_E_DELFAMILY_NOTFOUND
//
// MessageText:
//
// The specified delegation family was not found
//
#define TSM_E_DELFAMILY_NOTFOUND       (UINT32)(TSM_E_BASE + 0x130L)

//
// MessageId: TSM_E_DELFAMILY_ROWEXISTS
//
// MessageText:
//
// The specified delegation family table row is already in use and
// the command flags does not allow the TSM to overwrite the existing
// entry.
//
#define TSM_E_DELFAMILY_ROWEXISTS    (UINT32)(TSM_E_BASE + 0x131L)

//
// MessageId: TSM_E_VERSION_MISMATCH
//
// MessageText:
//
// The specified delegation family table row is already in use and
// the command flags does not allow the TSM to overwrite the existing
// entry.
//
#define TSM_E_VERSION_MISMATCH       (UINT32)(TSM_E_BASE + 0x132L)

//
//  MessageId: TSM_E_DAA_AR_DECRYPTION_ERROR
//
//  Decryption of the encrypted pseudonym has failed, due to
//  either a wrong secret key or a wrong decryption condition.
//
#define TSM_E_DAA_AR_DECRYPTION_ERROR             (UINT32)(TSM_E_BASE + 0x133L)

//
//  MessageId: TSM_E_DAA_AUTHENTICATION_ERROR
//
//  The TCM could not be authenticated by the DAA Issuer.
//
#define TSM_E_DAA_AUTHENTICATION_ERROR            (UINT32)(TSM_E_BASE + 0x134L)

//
//  MessageId: TSM_E_DAA_CHALLENGE_RESPONSE_ERROR
//
//  DAA Challenge response error.
//
#define TSM_E_DAA_CHALLENGE_RESPONSE_ERROR        (UINT32)(TSM_E_BASE + 0x135L)

//
//  MessageId: TSM_E_DAA_CREDENTIAL_PROOF_ERROR
//
//  Verification of the credential TSM_DAA_CRED_ISSUER issued by
//  the DAA Issuer has failed.
//
#define TSM_E_DAA_CREDENTIAL_PROOF_ERROR          (UINT32)(TSM_E_BASE + 0x136L)

//
//  MessageId: TSM_E_DAA_CREDENTIAL_REQUEST_PROOF_ERROR
//
//  Verification of the platform's credential request
//  TSM_DAA_CREDENTIAL_REQUEST has failed.
//
#define TSM_E_DAA_CREDENTIAL_REQUEST_PROOF_ERROR  (UINT32)(TSM_E_BASE + 0x137L)

//
//  MessageId: TSM_E_DAA_ISSUER_KEY_ERROR
//
//  DAA Issuer's authentication key chain could not be verified or
//  is not correct.
//
#define TSM_E_DAA_ISSUER_KEY_ERROR                (UINT32)(TSM_E_BASE + 0x138L)

//
//  MessageId: TSM_E_DAA_PSEUDONYM_ERROR
//
//  While verifying the pseudonym of the TCM, the private key of the
//  TCM was found on the rogue list.
//
#define TSM_E_DAA_PSEUDONYM_ERROR                 (UINT32)(TSM_E_BASE + 0x139L)

//
//  MessageId: TSM_E_INVALID_RESOURCE
//
//  Pointer to memory wrong.
//
#define TSM_E_INVALID_RESOURCE                    (UINT32)(TSM_E_BASE + 0x13AL)

//
//  MessageId: TSM_E_NV_AREA_EXIST
//
//  The NV area referenced already exists
//
#define TSM_E_NV_AREA_EXIST                       (UINT32)(TSM_E_BASE + 0x13BL)

//
//  MessageId: TSM_E_NV_AREA_NOT_EXIST
//
//  The NV area referenced doesn't exist
//
#define TSM_E_NV_AREA_NOT_EXIST                   (UINT32)(TSM_E_BASE + 0x13CL)

//
//  MessageId: TSM_E_TSP_TRANS_AUTHFAIL
//
//  The transport session authorization failed
//
#define TSM_E_TSP_TRANS_AUTHFAIL                  (UINT32)(TSM_E_BASE + 0x13DL)

//
//  MessageId: TSM_E_TSP_TRANS_AUTHREQUIRED
//
//  Authorization for transport is required
//
#define TSM_E_TSP_TRANS_AUTHREQUIRED              (UINT32)(TSM_E_BASE + 0x13EL)

//
//  MessageId: TSM_E_TSP_TRANS_NOT_EXCLUSIVE
//
//  A command was executed outside of an exclusive transport session.
//
#define TSM_E_TSP_TRANS_NOTEXCLUSIVE              (UINT32)(TSM_E_BASE + 0x13FL)

//
//  MessageId: TSM_E_TSP_TRANS_FAIL
//
//  Generic transport protection error.
//
#define TSM_E_TSP_TRANS_FAIL                     (UINT32)(TSM_E_BASE + 0x140L)

//
//  MessageId: TSM_E_TSP_TRANS_NO_PUBKEY
//
//  A command could not be executed through a logged transport session
//  because the command used a key and the key's public key is not
//  known to the TSP.
//
#define TSM_E_TSP_TRANS_NO_PUBKEY                (UINT32)(TSM_E_BASE + 0x141L)

//
//  MessageId: TSM_E_NO_ACTIVE_COUNTER
//
//  The TCM active counter has not been set yet.
//
#define TSM_E_NO_ACTIVE_COUNTER                  (UINT32)(TSM_E_BASE + 0x142L)

// TCM error code

#define TCM_E_BASE                              ((UINT32)(0x00000000))
#define TCM_SUCCESS                             ((UINT32)(TCM_E_BASE + 0x00))
#define TCM_E_AUTHFAIL                          ((UINT32)(TCM_E_BASE + 0x01))
#define TCM_E_BADINDEX                          ((UINT32)(TCM_E_BASE + 0x02))
#define TCM_E_BAD_PARAMETER                     ((UINT32)(TCM_E_BASE + 0x03))
#define TCM_E_CLEAR_DISABLE                     ((UINT32)(TCM_E_BASE + 0x05))
#define TCM_E_DISABLED_CMD                      ((UINT32)(TCM_E_BASE + 0x08))
#define TCM_E_FAIL                              ((UINT32)(TCM_E_BASE + 0x09))
#define TCM_E_INSTALL_DISABLED                  ((UINT32)(TCM_E_BASE + 0x0B))
#define TCM_E_INVALID_KEYHANDLE                 ((UINT32)(TCM_E_BASE + 0x0C))
#define TCM_E_KEYNOTFOUND                       ((UINT32)(TCM_E_BASE + 0x0D))
#define TCM_E_MIGRATEFAIL                       ((UINT32)(TCM_E_BASE + 0x0F))
#define TCM_E_INVALID_PCR_INFO                  ((UINT32)(TCM_E_BASE + 0x10))
#define TCM_E_NOSPACE                           ((UINT32)(TCM_E_BASE + 0x11))
#define TCM_E_NOTSEALED_BLOB                    ((UINT32)(TCM_E_BASE + 0x13))
#define TCM_E_OWNER_SET                         ((UINT32)(TCM_E_BASE + 0x14))
#define TCM_E_RESOURCES                         ((UINT32)(TCM_E_BASE + 0x15))
#define TCM_E_WRONGPCRVAL                       ((UINT32)(TCM_E_BASE + 0x18))
#define TCM_E_BAD_PARAM_SIZE                    ((UINT32)(TCM_E_BASE + 0x19))
#define TCM_E_SM3_THREAD                        ((UINT32)(TCM_E_BASE + 0x1A))
#define TCM_E_FAILEDSELFTEST                    ((UINT32)(TCM_E_BASE + 0x1C))
#define TCM_E_BADTAG                            ((UINT32)(TCM_E_BASE + 0x1E))
#define TCM_E_BAD_TAG                           ((UINT32)(TCM_E_BASE + 0x1E))
#define TCM_E_INVALID_AUTHHANDLE                ((UINT32)(TCM_E_BASE + 0x22))
#define TCM_E_NO_ENDORSEMENT                    ((UINT32)(TCM_E_BASE + 0x23))
#define TCM_E_INVALID_KEYUSAGE                  ((UINT32)(TCM_E_BASE + 0x24))
#define TCM_E_WRONG_ENTITYTYPE                  ((UINT32)(TCM_E_BASE + 0x25))
#define TCM_E_INVALID_POSTINIT                  ((UINT32)(TCM_E_BASE + 0x26))
#define TCM_E_BAD_KEY_PROPERTY                  ((UINT32)(TCM_E_BASE + 0x28))
#define TCM_E_BAD_MIGRATION                     ((UINT32)(TCM_E_BASE + 0x29))
#define TCM_E_BAD_SCHEME                        ((UINT32)(TCM_E_BASE + 0x2A))
#define TCM_E_BAD_DATASIZE                      ((UINT32)(TCM_E_BASE + 0x2B))
#define TCM_E_BAD_MODE                          ((UINT32)(TCM_E_BASE + 0x2C))
#define TCM_E_BAD_PRESENCE                      ((UINT32)(TCM_E_BASE + 0x2D))
#define TCM_E_INVALID_RESOURCE                  ((UINT32)(TCM_E_BASE + 0x35))
#define TCM_E_AUTH_CONFLICT                     ((UINT32)(TCM_E_BASE + 0x3B))
#define TCM_E_AREA_LOCKED                       ((UINT32)(TCM_E_BASE + 0x3C))
#define TCM_E_PER_NOWRITE                       ((UINT32)(TCM_E_BASE + 0x3F))
#define TCM_E_INVALID_STRUCTURE                 ((UINT32)(TCM_E_BASE + 0x43))
#define TCM_E_BAD_COUNTER                       ((UINT32)(TCM_E_BASE + 0x45))
#define TCM_E_NOT_FULLWRITE                     ((UINT32)(TCM_E_BASE + 0x46))
#define TCM_E_CONTEXT_GAP                       ((UINT32)(TCM_E_BASE + 0x47))
#define TCM_E_MAXNVWRITES                       ((UINT32)(TCM_E_BASE + 0x48))
#define TCM_E_NOOPERATOR                        ((UINT32)(TCM_E_BASE + 0x49))
#define TCM_E_RESOURCEMISSING                   ((UINT32)(TCM_E_BASE + 0x4A))
#define TCM_E_BAD_HANDLE                        ((UINT32)(TCM_E_BASE + 0x58))
#define TCM_E_BADCONTEXT                        ((UINT32)(TCM_E_BASE + 0x5A))
#define TCM_E_TOOMANYCONTEXTS                   ((UINT32)(TCM_E_BASE + 0x5B))
#define TCM_E_PERMANENTEK                       ((UINT32)(TCM_E_BASE + 0x61))
#define TCM_E_NOCONTEXTSPACE                    ((UINT32)(TCM_E_BASE + 0x63))
#define TCM_E_TEST                              ((UINT32)(TCM_E_BASE + 0x64))
#define TCM_E_LSF_ON                            ((UINT32)(TCM_E_BASE + 0x65))
#define TCM_E_LOM_ON                            ((UINT32)(TCM_E_BASE + 0x66))
#define TCM_E_STF_ON                            ((UINT32)(TCM_E_BASE + 0x67))
#define TCM_E_CA_ERROR                          ((UINT32)(TCM_E_BASE + 0x68))

#pragma pack(pop)

#endif