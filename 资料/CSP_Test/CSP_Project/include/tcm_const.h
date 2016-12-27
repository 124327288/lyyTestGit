#ifndef __TCM_CONST_DEFINE_HEADER_
#define __TCM_CONST_DEFINE_HEADER_

#include "jwplatform.h"

//////////////////////////////////////////////////////////////////////////
// 结构标记定义
//////////////////////////////////////////////////////////////////////////

typedef UINT16  TCM_STRUCTURE_TAG;
#define TCM_TAG_CONTEXTBLOB                     ((UINT16)0x0001)
#define TCM_TAG_CONTEXT_SENSITIVE               ((UINT16)0x0002)
#define TCM_TAG_SIGNINFO                        ((UINT16)0x0005)
#define TCM_TAG_PCR_INFO_LONG                   ((UINT16)0x0006)
#define TCM_TAG_PERSISTENT_FLAGS                ((UINT16)0x0007)
#define TCM_TAG_VOLATILE_FLAGS                  ((UINT16)0x0008)
#define TCM_TAG_PERSISTENT_DATA                 ((UINT16)0x0009)
#define TCM_TAG_EK_BLOB                         ((UINT16)0x000c)
#define TCM_TAG_EK_BLOB_AUTH                    ((UINT16)0x000d)
#define TCM_TAG_COUNTER_VALUE                   ((UINT16)0x000e)
#define TCM_TAG_TRANSPORT_INTERNAL              ((UINT16)0x000f)
#define TCM_TAG_AUDIT_EVENT_IN                  ((UINT16)0x0012)
#define TCM_TAG_AUDIT_EVENT_OUT                 ((UINT16)0x0013)
#define TCM_TAG_CURRENT_TICKS                   ((UINT16)0x0014)
#define TCM_TAG_KEY                             ((UINT16)0x0015)
#define TCM_TAG_STORED_DATA                     ((UINT16)0x0016)
#define TCM_TAG_NV_ATTRIBUTES                   ((UINT16)0x0017)
#define TCM_TAG_NV_DATA_PUBLIC                  ((UINT16)0x0018)
#define TCM_TAG_NV_DATA_SENSITIVE               ((UINT16)0x0019)
#define TCM_TAG_TRANSPORT_AUTH                  ((UINT16)0x001d)
#define TCM_TAG_TRANSPORT_PUBLIC                ((UINT16)0x001e)
#define TCM_TAG_PERMANENT_FLAGS                 ((UINT16)0x001f)
#define TCM_TAG_STCLEAR_FLAGS                   ((UINT16)0x0020)
#define TCM_TAG_STANY_FLAGS                     ((UINT16)0x0021)
#define TCM_TAG_PERMANENT_DATA                  ((UINT16)0x0022)
#define TCM_TAG_STCLEAR_DATA                    ((UINT16)0x0023)
#define TCM_TAG_STANY_DATA                      ((UINT16)0x0024)
#define TCM_TAG_CERTIFY_INFO                    ((UINT16)0x0029)
#define TCM_TAG_EK_BLOB_ACTIVATE                ((UINT16)0x002b)
#define TCM_TAG_CAP_VERSION_INFO                ((UINT16)0x0030)
#define TCM_TAG_QUOTE_INFO                      ((UINT16)0x0036)

//////////////////////////////////////////////////////////////////////////
// 类型定义
//////////////////////////////////////////////////////////////////////////

typedef UINT32 TCM_RESOURCE_TYPE;
#define TCM_RT_KEY                              ((UINT32)0x00000001)
#define TCM_RT_AUTH                             ((UINT32)0x00000002)
#define TCM_RT_HASH                             ((UINT32)0x00000003)
#define TCM_RT_TRANS                            ((UINT32)0x00000004)
#define TCM_RT_CONTEXT                          ((UINT32)0x00000005)
#define TCM_RT_COUNTER                          ((UINT32)0x00000006)

typedef BYTE TCM_PAYLOAD_TYPE;
#define TCM_PT_SYM                              ((BYTE)0x00)
#define TCM_PT_ASYM                             ((BYTE)0x01)
#define TCM_PT_BIND                             ((BYTE)0x02)
#define TCM_PT_SEAL                             ((BYTE)0x05)
#define TCM_PT_SYM_MIGRATE                      ((BYTE)0x08)
#define TCM_PT_ASYM_MIGRATE                     ((BYTE)0x09)

typedef UINT16 TCM_ENTITY_TYPE;
#define TCM_ET_KEYHANDLE                        ((BYTE)0x0001)
#define TCM_ET_OWNER                            ((BYTE)0x0002)
#define TCM_ET_DATA                             ((BYTE)0x0003)
#define TCM_ET_SMK                              ((BYTE)0x0004)
#define TCM_ET_KEY                              ((BYTE)0x0005)
#define TCM_ET_REVOKE                           ((BYTE)0x0006)
#define TCM_ET_COUNTER                          ((BYTE)0x000A)
#define TCM_ET_NV                               ((BYTE)0x000B)
#define TCM_ET_KEYXOR                           ((BYTE)0x0010)
#define TCM_ET_KEYSMS4                          ((BYTE)0x0011)
#define TCM_ET_NONE                             ((BYTE)0x0012)
#define TCM_ET_AUTHDATA_ID                      ((BYTE)0x0013)
#define TCM_ET_AUTHDATA                         ((BYTE)0x0014)
#define TCM_ET_OPERATOR                         ((BYTE)0x0015)
#define TCM_ET_OWENERSMS4                       ((BYTE)0x0016)
#define TCM_ET_OWNERXOR                         ((BYTE)0x0017)
#define TCM_ET_RESERVED_HANDLE                  ((BYTE)0x0040)

typedef UINT32 TCM_KEY_HANDLE;
#define TCM_KH_SMK                              ((UINT32)0x40000000)
#define TCM_KH_OWNER                            ((UINT32)0x40000001)
#define TCM_KH_REVOKE                           ((UINT32)0x40000002)
#define TCM_KH_TRANSPORT                        ((UINT32)0x40000003)
#define TCM_KH_OPERATOR                         ((UINT32)0x40000004)
//#define TCM_KH_ADMIN                            ((UINT32)0x40000005)
#define TCM_KH_EK                               ((UINT32)0x40000006)

typedef UINT16 TCM_STARTUP_TYPE;
#define TCM_ST_CLEAR                            ((UINT16)0x0001)
#define TCM_ST_STATE                            ((UINT16)0x0002)
#define TCM_ST_DEACTIVATED                      ((UINT16)0x0003)

typedef UINT16 TCM_PROTOCOL_ID;
#define TCM_PID_OWNER                           ((UINT16)0x0005)
#define TCM_PID_TRANSPORT                       ((UINT16)0x0007)
#define TCM_PID_AP                              ((UINT16)0x0008)

typedef UINT32 TCM_ALGORITHM_ID;
#define TCM_ALG_KDF                             ((UINT32)0x00000007)
#define TCM_ALG_XOR                             ((UINT32)0x0000000A)
#define TCM_ALG_SM2                             ((UINT32)0x0000000B)
#define TCM_ALG_SMS4                            ((UINT32)0x0000000C)
#define TCM_ALG_SM3                             ((UINT32)0x0000000D)
#define TCM_ALG_HMAC                            ((UINT32)0x0000000E)

typedef UINT16              TCM_ENC_SCHEME;
#define TCM_ES_SM2NONE                          ((UINT16)0x0004)
#define TCM_ES_SM2                              ((UINT16)0x0006)
#define TCM_ES_SMS4_CBC                         ((UINT16)0x0008)
#define TCM_ES_SMS4_ECB                         ((UINT16)0x000A)

typedef UINT16              TCM_SIG_SCHEME;
#define TCM_SS_SM2NONE                          ((UINT16)0x0001)
#define TCM_SS_SM2                              ((UINT16)0x0005)

typedef UINT16              TCM_PHYSICAL_PRESENCE;
#define TCM_PHYSICAL_PRESENCE_LOCK              ((UINT16)0x0004)
#define TCM_PHYSICAL_PRESENCE_PRESENT           ((UINT16)0x0008)
#define TCM_PHYSICAL_PRESENCE_NOTPRESENT        ((UINT16)0x0010)
#define TCM_PHYSICAL_PRESENCE_CMD_ENABLE        ((UINT16)0x0020)
#define TCM_PHYSICAL_PRESENCE_HW_ENABLE         ((UINT16)0x0040)
#define TCM_PHYSICAL_PRESENCE_LIFETIME_LOCK     ((UINT16)0x0080)
#define TCM_PHYSICAL_PRESENCE_CMD_DISABLE       ((UINT16)0x0100)
#define TCM_PHYSICAL_PRESENCE_HW_DISABLE        ((UINT16)0x0200)

typedef UINT16              TCM_MIGRATE_SCHEME;
#define TCM_MS_MIGRATE                          ((UINT16)0x0001)
#define TCM_MS_REWRAP                           ((UINT16)0x0002)

typedef UINT16              TCM_EK_TYPE;
#define TCM_EK_TYPE_ACTIVATE                    ((UINT16)0x0001)
#define TCM_EK_TYPE_AUTH                        ((UINT16)0x0002)

//////////////////////////////////////////////////////////////////////////
// 属性定义
//////////////////////////////////////////////////////////////////////////

typedef UINT32              TCM_CAPABILITY_AREA;
#define TCM_CAP_ORD                             ((UINT32)0x00000001)
#define TCM_CAP_ALG                             ((UINT32)0x00000002)
#define TCM_CAP_PID                             ((UINT32)0x00000003)
#define TCM_CAP_FLAG                            ((UINT32)0x00000004)
#define TCM_CAP_PROPERTY                        ((UINT32)0x00000005) // 1.1b
#define TCM_CAP_VERSION                         ((UINT32)0x00000006)
#define TCM_CAP_KEY_HANDLE                      ((UINT32)0x00000007)
#define TCM_CAP_CHECK_LOADED                    ((UINT32)0x00000008)
#define TCM_CAP_SYM_MODE                        ((UINT32)0x00000009)
#define TCM_CAP_KEY_STATUS                      ((UINT32)0x0000000C)
#define TCM_CAP_NV_LIST                         ((UINT32)0x0000000D)
#define TCM_CAP_MFR                             ((UINT32)0x00000010)
#define TCM_CAP_NV_INDEX                        ((UINT32)0x00000011)
#define TCM_CAP_TRANS_ALG                       ((UINT32)0x00000012)
#define TCM_CAP_HANDLE                          ((UINT32)0x00000014)
#define TCM_CAP_TRANS_ES                        ((UINT32)0x00000015)
#define TCM_CAP_AUTH_ENCRYPT                    ((UINT32)0x00000017)
#define TCM_CAP_SELECT_SIZE                     ((UINT32)0x00000018)
#define TCM_CAP_VERSION_VAL                     ((UINT32)0x0000001A)

// SetCapability Values
#define TCM_SET_PERM_FLAGS                      ((UINT32)0x00000001)
#define TCM_SET_PERM_DATA                       ((UINT32)0x00000002)
#define TCM_SET_STCLEAR_FLAGS                   ((UINT32)0x00000003)
#define TCM_SET_STCLEAR_DATA                    ((UINT32)0x00000004)
#define TCM_SET_STANY_FLAGS                     ((UINT32)0x00000005)
#define TCM_SET_STANY_DATA                      ((UINT32)0x00000006)
#define TCM_SET_VENDOR                          ((UINT32)0x00000007)

// Subcap values for CAP_PROPERTY	
#define TCM_CAP_PROP_PCR                        ((UINT32)0x00000101)
#define TCM_CAP_PROP_MANUFACTURER               ((UINT32)0x00000103)
#define TCM_CAP_PROP_KEYS                       ((UINT32)0x00000104)
#define TCM_CAP_PROP_SLOTS                      (TCM_CAP_PROP_KEYS)	
#define TCM_CAP_PROP_MIN_COUNTER                ((UINT32)0x00000107)
#define TCM_CAP_FLAG_PERMANENT                  ((UINT32)0x00000108)    // Subcap values for CAP_FLAG
#define TCM_CAP_FLAG_VOLATILE                   ((UINT32)0x00000109)    // Subcap values for CAP_FLAG
#define TCM_CAP_PROP_AUTHSESS                   ((UINT32)0x0000010A)
#define TCM_CAP_PROP_TRANSESS                   ((UINT32)0x0000010B)
#define TCM_CAP_PROP_COUNTERS                   ((UINT32)0x0000010C)
#define TCM_CAP_PROP_MAX_AUTHSESS               ((UINT32)0x0000010D)
#define TCM_CAP_PROP_MAX_TRANSESS               ((UINT32)0x0000010E)
#define TCM_CAP_PROP_MAX_COUNTERS               ((UINT32)0x0000010F)
#define TCM_CAP_PROP_MAX_KEYS                   ((UINT32)0x00000110)
#define TCM_CAP_PROP_OWNER                      ((UINT32)0x00000111)
#define TCM_CAP_PROP_CONTEXT                    ((UINT32)0x00000112)
#define TCM_CAP_PROP_MAX_CONTEXT                ((UINT32)0x00000113)
#define TCM_CAP_PROP_STARTUP_EFFECT             ((UINT32)0x00000116)
#define TCM_CAP_PROP_CONTEXT_DIST               ((UINT32)0x0000011B)
#define TCM_CAP_PROP_SESSIONS                   ((UINT32)0X0000011D)
#define TCM_CAP_PROP_MAX_SESSIONS               ((UINT32)0x0000011E)
#define TCM_CAP_PROP_DURATION                   ((UINT32)0x00000120)
#define TCM_CAP_PROP_ACTIVE_COUNTER             ((UINT32)0x00000122)
#define TCM_CAP_PROP_MAX_NV_AVAILABLE           ((UINT32)0x00000123)
#define TCM_CAP_PROP_INPUT_BUFFER               ((UINT32)0x00000124)

// 与TSS不同
#define TCM_PF_DISABLE                          ((UINT32)0x00000001)
#define TCM_PF_OWNERSHIP                        ((UINT32)0x00000002)
#define TCM_PF_DEACTIVATED                      ((UINT32)0x00000004)
#define TCM_PF_READPUBEK                        ((UINT32)0x00000008)
#define TCM_PF_DISABLEOWNERCLEAR                ((UINT32)0x00000010)
#define TCM_PF_PHYSICALPRESENCELIFETIMELOCK     ((UINT32)0x00000040)
#define TCM_PF_PHYSICALPRESENCEHWENABLE         ((UINT32)0x00000080)
#define TCM_PF_PHYSICALPRESENCECMDENABLE        ((UINT32)0x00000100)
#define TCM_PF_CEKPUSED                         ((UINT32)0x00000200)
#define TCM_PF_TCMPOST                          ((UINT32)0x00000400)
#define TCM_PF_TCMPOSTLOCK                      ((UINT32)0x00000800)
#define TCM_PF_OPERATOR                         ((UINT32)0x00002000)
#define TCM_PF_ENABLEREVOKEEK                   ((UINT32)0x00004000)
#define TCM_PF_NV_LOCKED                        ((UINT32)0x00008000)
#define TCM_PF_TCMESTABLISHED                   ((UINT32)0x00020000)

// 与TSS不同
#define TCM_SF_DEACTIVATED                      ((UINT32)0x00000001)
#define TCM_SF_DISABLEFORCECLEAR                ((UINT32)0x00000002)
#define TCM_SF_PHYSICALPRESENCE                 ((UINT32)0x00000004)
#define TCM_SF_PHYSICALPRESENCELOCK             ((UINT32)0x00000008)

typedef UINT32              TCM_KEY_FLAGS;
// 可迁移密钥
#define TCM_MIGRATABLE                          ((UINT32)0x00000002)
//易失性密钥，在启动(ST_Clear方式)时不需要重新加载
#define TCM_VOLATILE                            ((UINT32)0x00000004)
//TRUE时, 在获取公钥时不检查PCR
//FLASE时, 在获取公钥检查PCR
#define TCM_PCRIGNOREDONREAD                    ((UINT32)0x00000008)

typedef UINT32              TCM_KEY_HANDLE;
// SMK密钥句柄
#define TCM_KH_SMK                              ((UINT32)0x40000000)
// TCM所有者句柄
#define TCM_KH_OWNER                            ((UINT32)0x40000001)
// 可撤销EK句柄
#define TCM_KH_REVOKE                           ((UINT32)0x40000002)
// 创建传输会话句柄
#define TCM_KH_TRANSPORT                        ((UINT32)0x40000003)
// 操作者授权句柄
#define TCM_KH_OPERATOR                         ((UINT32)0x40000004)
// EK句柄
#define TCM_KH_EK                               ((UINT32)0x40000006)

//////////////////////////////////////////////////////////////////////////
// PCR定义
//////////////////////////////////////////////////////////////////////////
#define TCM_LOC_FOUR                            ((BYTE)(1<<4))
#define TCM_LOC_THREE                           ((BYTE)(1<<3))
#define TCM_LOC_TWO                             ((BYTE)(1<<2))
#define TCM_LOC_ONE                             ((BYTE)(1<<1))
#define TCM_LOC_ZERO                            ((BYTE)(1<<0))

//////////////////////////////////////////////////////////////////////////
// NV 定义
//////////////////////////////////////////////////////////////////////////

typedef UINT32 TCM_NV_INDEX;
#define TCM_NV_INDEX_LOCK       0xFFFFFFFF
#define TCM_NV_INDEX0           0x00000000
#define TCM_NV_INDEX_EKCert     0x0000F000
#define TCM_NV_INDEX_TSM        0x00011100
#define TCM_NV_INDEX_PC         0x00011200
#define TCM_NV_INDEX_SERVER     0x00011300
#define TCM_NV_INDEX_MOBILE     0x00011400
#define TCM_NV_INDEX_PERIPHERAL 0x00011500
#define TCM_NV_INDEX_CPIO       0x00011600


#define TCM_NV_PER_READ_STCLEAR    0x80000000
#define TCM_NV_PER_AUTHREAD        0x00040000
#define TCM_NV_PER_OWNERREAD       0x00020000
#define TCM_NV_PER_PPREAD          0x00010000
#define TCM_NV_PER_GLOBALLOCK      0x00008000
#define TCM_NV_PER_WRITE_STCLEAR   0x00004000
#define TCM_NV_PER_WRITEDEFINE     0x00002000
#define TCM_NV_PER_WRITEALL        0x00001000
#define TCM_NV_PER_AUTHWRITE       0x00000004
#define TCM_NV_PER_OWNERWRITE      0x00000002
#define TCM_NV_PER_PPWRITE         0x00000001

#endif
