#ifndef __TSM_CONST_DEFINE_HEADER_
#define __TSM_CONST_DEFINE_HEADER_

#include "jwplatform.h"

#define TSM_SMK_UUID    ((TSM_UUID *)("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"))
#define TSM_NULL_UUID   ((TSM_UUID *)("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))

#define TSM_PIK_UUID    ((TSM_UUID *)("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"))
#define TSM_PEK_UUID    ((TSM_UUID *)("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"))

//////////////////////////////////////////////////////////////////////////
// 对象类型定义
//////////////////////////////////////////////////////////////////////////
// 策略对象
#define TSM_OBJECT_TYPE_POLICY                  TSS_OBJECT_TYPE_POLICY
// 密钥对象(包括对称与非对称)
// 与TSS不同, TSM包含对称和非对称, TSS只有非对称
#define TSM_OBJECT_TYPE_KEY                     TSS_OBJECT_TYPE_RSAKEY
// 加密数据对象；限定使用范围的数据、密封数据或信封封装数据
#define TSM_OBJECT_TYPE_ENCDATA                 TSS_OBJECT_TYPE_ENCDATA
// PCR对象
#define TSM_OBJECT_TYPE_PCRS                    TSS_OBJECT_TYPE_PCRS
// 杂凑对象
#define TSM_OBJECT_TYPE_HASH                    TSS_OBJECT_TYPE_HASH
// 非易失性存储对象
#define TSM_OBJECT_TYPE_NV                      TSS_OBJECT_TYPE_NV
// 迁移数据处理对象
#define TSM_OBJECT_TYPE_MIGDATA                 TSS_OBJECT_TYPE_MIGDATA
// 密钥协商对象
#define TSM_OBJECT_TYPE_EXCHANGE                (0x0000000C)

//////////////////////////////////////////////////////////////////////////
// 对象初始化定义
//////////////////////////////////////////////////////////////////////////

//
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//                                                              |x x|Auth
//                                                            |x|    Volatility
//                                                          |x|      Migration
//                                                  |x x x x|        Type
//                                          |x x x x|                Size
//                                      |x x|                        CMK
//                                |x x x|                            Version
//              |0 0 0 0 0 0 0 0 0|                                  Reserved
//  |x x x x x x|                                                    Fixed Type
//

//  Authorization:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//
//   Never                                                      |0 0|
//   Always                                                     |0 1|
//   Private key always                                         |1 0|
//
// 无需授权的密钥(缺省属性)
#define TSM_KEY_NO_AUTHORIZATION                TSS_KEY_NO_AUTHORIZATION
// 使用需授权的密钥
#define TSM_KEY_AUTHORIZATION                   TSS_KEY_AUTHORIZATION
// 密钥的私钥部分使用时需授权的密钥
#define TSM_KEY_AUTHORIZATION_PRIV_USE_ONLY     TSS_KEY_AUTHORIZATION_PRIV_USE_ONLY

//
//  Volatility
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//
//   Non Volatile                                             |0|
//   Volatile                                                 |1|
//
// 非易失性密钥，启动时可以不加载
#define TSM_KEY_NON_VOLATILE                    TSS_KEY_NON_VOLATILE
// 易失性密钥，启动时必须加载
#define TSM_KEY_VOLATILE                        TSS_KEY_VOLATILE

//
//  Migration
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//
//   Non Migratable                                         |0|
//   Migratable                                             |1|
//
// 不可迁移密钥(缺省属性)
#define TSM_KEY_NOT_MIGRATABLE                  TSS_KEY_NOT_MIGRATABLE
// 可迁移的密钥
#define TSM_KEY_MIGRATABLE                      TSS_KEY_MIGRATABLE

//
//  Usage/Type
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//
//   Default (Legacy)                               |0 0 0 0|
//   SM2 Signing                                    |0 0 0 1|
//   SM2 Storage                                    |0 0 1 0|
//   SM2 Identity                                   |0 0 1 1|
//   SM2 AuthChange                                 |0 1 0 0|
//   SM2 Bind                                       |0 1 0 1|
//   TSS Legacy                                     |0 1 1 0|
//   SM2 Migrate                                    |0 1 1 1|
//   SMS4 Storage                                   |1 0 0 0|
//   SMS4 Bind                                      |1 0 0 1|
//
// SM2 存储加密密钥
#define TSM_SM2KEY_TYPE_STORAGE                 (TSS_KEY_TYPE_STORAGE)
// SM2 签名密钥
#define TSM_SM2KEY_TYPE_SIGNING                 (TSS_KEY_TYPE_SIGNING)
// SM2 加密密钥
#define TSM_SM2KEY_TYPE_BIND                    (TSS_KEY_TYPE_BIND)
// SM2 身份标识密钥
#define TSM_SM2KEY_TYPE_IDENTITY                (TSS_KEY_TYPE_IDENTITY)
// 临时性 SM2 密钥，用于改变授权数据值
#define TSM_SM2KEY_TYPE_AUTHCHANGE              (TSS_KEY_TYPE_AUTHCHANGE)
// SM2 迁移保护密钥
#define TSM_SM2KEY_TYPE_MIGRATE                 (TSS_KEY_TYPE_MIGRATE)
// SM2 平台加密密钥
#define TSM_SM2KEY_TYPE_PEK                     ((UINT32)0x00000080)
// SMS4存储加密密钥
#define TSM_SMS4KEY_TYPE_STORAGE                ((UINT32)0x00000090)
// SMS4加密密钥
#define TSM_SMS4KEY_TYPE_BIND                   ((UINT32)0x000000A0)
// SMS4可迁移密钥
#define TSM_SMS4KEY_TYPE_MIGRATE                ((UINT32)0x000000B0)
#define TSM_KEY_TYPE_BITMASK                    (TSS_KEY_TYPE_MASK)

//
//  Key size
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//
// DEFAULT                                  |0 0 0 0|
// 128 (SYM Default)                        |0 0 0 1|
// 256 (ASY Default)                        |0 0 1 0|
//
// 缺省的密钥长度
#define TSM_KEY_SIZE_DEFAULT                    TSS_KEY_SIZE_DEFAULT
// 缺省的对称密钥长度
#define TSM_KEY_SIZE_DEFAULT_SYM                TSM_KEY_SIZE_DEFAULT
// 缺省的非对称密钥长度
#define TSM_KEY_SIZE_DEFAULT_ASY                TSM_KEY_SIZE_DEFAULT
// SMS4的密钥长度为128-bit
#define TSM_KEY_SIZE_128                        (UINT32)(0x00000100)
// SM2的私钥长度为256-bit
#define TSM_KEY_SIZE_256                        (UINT32)(0x00000200)
// SM2的公钥长度为512-bit
#define TSM_KEY_SIZE_512                        (UINT32)(0x00000300)
// SM2的公钥长度为520-bit
#define TSM_KEY_SIZE_520                        (UINT32)(0x00000400)
#define TSM_KEY_SIZE_BITMASK                    TSS_KEY_SIZE_BITMASK

//
//  Specification version
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//
// Context default                |0 0 0|
// TPM_KEY 1.1b key               |0 0 1|
// TPM_KEY12 1.2 key              |0 1 0| default
//
// 使用TCM密钥对象

#define TSM_KEY_STRUCT_DEFAULT                  ((UINT32)(0x00000000))
#define TSM_KEY_STRUCT_KEY                      TSS_KEY_STRUCT_KEY12
#define TSM_KEY_STRUCT_BITMASK                  TSS_KEY_STRUCT_BITMASK

//
//  fixed KeyTypes (templates)
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//
//  |0 0 0 0 0 0|                             Empty Key
//  |0 0 0 0 0 1|                             Storage Root Key
//
// 非TCM密钥模板(空TSM密钥对象)
#define TSM_KEY_EMPTY_KEY                       TSS_KEY_EMPTY_KEY
// 使用 TCM SMK 模板(用于SMK的TSM密钥对象)
#define TSM_KEY_TSP_SMK                         TSS_KEY_TSP_SRK
#define TSM_KEY_TEMPLATE_BITMASK                TSS_KEY_TEMPLATE_BITMASK

//
// Flags for creating ENCDATA object:
//

//
//  Type
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//
//   Seal                                                     |0 0 1|
//   Bind                                                     |0 1 0|
//   TSS规范 Legacy                                           |0 1 1|
//   Envelop                                                  |1 0 0|
//
//   ENCDATA Reserved:
//  |x x x x x x x x x x x x x x x x x x x x x x x x x x x x x|
//
// 用于数据封装操作的数据对象
#define TSM_ENCDATA_SEAL                        TSS_ENCDATA_SEAL
// 用于加密操作的数据对象
#define TSM_ENCDATA_BIND                        TSS_ENCDATA_BIND
// 用于数字信封操作的数据对象
#define TSM_ENCDATA_ENVELOP                     (0x00000004)
#define TSM_ENCDATA_TYPE_BITMASK                (0x00000007)

//
// Flags for creating HASH object:
//

//
//  Algorithm
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//
//   DEFAULT               
//  |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0|
//  TSS规范 SHA1
//  |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1|
//   OTHER
//  |1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1|
//
// 缺省密码杂凑算法
#define TSM_HASH_DEFAULT                        TSS_HASH_DEFAULT
#define TSM_HASH_SHA1                           (0x00000001)
// SM3算法的杂凑对象
#define TSM_HASH_SM3                            (0x00000002)
// 其它算法的杂凑对象
#define TSM_HASH_OTHER                          TSS_HASH_OTHER

//
// Flags for creating POLICY object:
//

//
//  Type
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//
//   Usage                                                    |0 0 1|
//   Migration                                                |0 1 0|
//   Operator                                                 |0 1 1|
//
//   POLICY Reserved:
//  |x x x x x x x x x x x x x x x x x x x x x x x x x x x x x x|
//
// 用于授权的策略对象
#define TSM_POLICY_USAGE                        TSS_POLICY_USAGE
// 用于密钥迁移的策略对象
#define TSM_POLICY_MIGRATION                    TSS_POLICY_MIGRATION
// 用于操作者授权的策略对象
#define TSM_POLICY_OPERATOR                     TSS_POLICY_OPERATOR

//
// Flags for creating PCRComposite object:
//

//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//                                                              |x x| Struct
//  |x x x x x x x x x x x x x x x x x x x x x x x x x x x x x x|     Reserved
//

//  PCRComposite Version:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
// TPM_PCR_DEFAULT                                            |0 0 0|
// TPM_PCR_INFO                                               |0 0 1|
// TPM_PCR_INFO_LONG                                          |0 1 0|
// TPM_PCR_INFO_SHORT                                         |0 1 1|
//
// 使用TCM的PCR对象
#define TSM_PCRS_STRUCT_INFO                    TSS_PCRS_STRUCT_INFO_LONG

//////////////////////////////////////////////////////////////////////////
// 上下文对象的属性定义
//////////////////////////////////////////////////////////////////////////
// 属性标记
// 获取或设置一个上下文对象的休眠模式
#define TSM_TSPATTRIB_CONTEXT_SILENT_MODE                   TSS_TSPATTRIB_CONTEXT_SILENT_MODE
// 获得TSM的机器名
#define TSM_TSPATTRIB_CONTEXT_MACHINE_NAME                  TSS_TSPATTRIB_CONTEXT_MACHINE_NAME
// 获取或设置版本，该信息可用于处理上下文对象的模式 
#define TSM_TSPATTRIB_CONTEXT_VERSION_MODE                  TSS_TSPATTRIB_CONTEXT_VERSION_MODE
// 获得连接的最高支持版本(TSM和TCM的最高通用版本) 
#define TSM_TSPATTRIB_CONTEXT_CONNECTION_VERSION            TSS_TSPATTRIB_CONTEXT_CONNECTION_VERSION
// 获取或设置与该上下文对象相关联的传输会话的相关属性
#define TSM_TSPATTRIB_CONTEXT_TRANSPORT                     TSS_TSPATTRIB_CONTEXT_TRANSPORT
// 获得/设置上下文或策略对象的杂凑操作模式
#define TSM_TSPATTRIB_SECRET_HASH_MODE                      TSS_TSPATTRIB_SECRET_HASH_MODE

// TSM_TSPATTRIB_CONTEXT_TRANSPORT 子属性
// 打开与关闭传输会话
#define TSM_TSPATTRIB_CONTEXTTRANS_CONTROL                  TSS_TSPATTRIB_CONTEXTTRANS_CONTROL
// 控制传输会话的特性
#define TSM_TSPATTRIB_CONTEXTTRANS_MODE                     TSS_TSPATTRIB_CONTEXTTRANS_MODE
// TSM_TSPATTRIB_SECRET_HASH_MODE 子属性
// 获取或设置在弹出模式下杂凑操作
#define TSM_TSPATTRIB_SECRET_HASH_MODE_POPUP                TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP


// TSM_TSPATTRIB_CONTEXT_SILENT_MODE 属性值
// 请求用户提供密码时，显示 TSM 对话框
#define TSM_TSPATTRIB_CONTEXT_NOT_SILENT                    TSS_TSPATTRIB_CONTEXT_NOT_SILENT
//不显示 TSM对话框(默认)
#define TSM_TSPATTRIB_CONTEXT_SILENT                        TSS_TSPATTRIB_CONTEXT_SILENT

// TSM_TSPATTRIB_SECRET_HASH_MODE -> TSM_TSPATTRIB_SECRET_HASH_MODE_POPUP
#define TSM_TSPATTRIB_HASH_MODE_NOT_NULL                    TSS_TSPATTRIB_HASH_MODE_NOT_NULL
#define TSM_TSPATTRIB_HASH_MODE_NULL                        TSS_TSPATTRIB_HASH_MODE_NULL

//
// TSM_TSPATTRIB_CONTEXT_TRANSPORT -> TSM_TSPATTRIB_CONTEXT_TRANS_CONTROL
//
#define TSM_TSPATTRIB_DISABLE_TRANSPORT                     TSS_TSPATTRIB_DISABLE_TRANSPORT
#define TSM_TSPATTRIB_ENABLE_TRANSPORT                      TSS_TSPATTRIB_ENABLE_TRANSPORT

// TSM_TSPATTRIB_CONTEXT_TRANSPORT -> TSM_TSPATTRIB_CONTEXT_TRANS_MODE
// 使传输会话中数据加密功能关闭
#define TSM_TSPATTRIB_TRANSPORT_NO_DEFAULT_ENCRYPTION       TSS_TSPATTRIB_TRANSPORT_NO_DEFAULT_ENCRYPTION
// 使传输会话中数据加密功能打开
#define TSM_TSPATTRIB_TRANSPORT_DEFAULT_ENCRYPTION          TSS_TSPATTRIB_TRANSPORT_DEFAULT_ENCRYPTION
// 排它传输模式
#define TSM_TSPATTRIB_TRANSPORT_EXCLUSIVE                   TSS_TSPATTRIB_TRANSPORT_EXCLUSIVE

//////////////////////////////////////////////////////////////////////////
// TCM 对象属性定义
//////////////////////////////////////////////////////////////////////////
// 允许厂商在TCM中按照常规受保护区域位置的需求设置特定区域
#define TSM_TSPATTRIB_TCMCAP_SET_VENDOR         ((UINT32)0x00000004)
// 向审计列表添加或清除一个命令码
#define TSM_TSPATTRIB_TCM_ORDINAL_AUDIT_STATUS  TSS_TSPATTRIB_TPM_ORDINAL_AUDIT_STATUS
//  表示单调计数器递增的最小时间间隔，该间隔以 1/10 秒为度量单位。 
#define TSM_TSPATTRIB_TCMCAP_MIN_COUNTER        ((UINT32)0x00000005)
//  返回 TCM 启动标志。
#define TSM_TSPATTRIB_TCMCAP_FLAG_VOLATILE      ((UINT32)0x00000006)
//
#define TSM_TSPATTRIB_TCM_CREDENTIAL            TSS_TSPATTRIB_TPM_CREDENTIAL

// TSM_TSPATTRIB_TCM_ORDINAL_AUDIT_STATUS 子属性
// 向审计列表中加入一个命令码
#define TCM_CAP_PROP_TCM_SET_ORDINAL_AUDIT      TPM_CAP_PROP_TPM_SET_ORDINAL_AUDIT
// 要添加到审计列表中或者要从审计列表钟删除的命令码
#define TCM_CAP_PROP_TCM_CLEAR_ORDINAL_AUDIT    TPM_CAP_PROP_TPM_CLEAR_ORDINAL_AUDIT

// TSM_TSPATTRIB_TCM_CREDENTIAL 子属性
// 密码模块证书blob
#define TSM_TCMATTRIB_EKCERT                    TSS_TPMATTRIB_EKCERT
// 平台身份证书 blob
#define TSM_TCMATTRIB_PLATFORMCERT              TSS_TPMATTRIB_PLATFORMCERT 

//////////////////////////////////////////////////////////////////////////
// 策略对象属性定义
//////////////////////////////////////////////////////////////////////////
// 属性标记
// 获得/设置上下文或策略对象的杂凑操作模式
//#define TSM_TSPATTRIB_SECRET_HASH_MODE                  TSS_TSPATTRIB_SECRET_HASH_MODE
#define TSM_TSPATTRIB_POLICY_SECRET_LIFETIME            TSS_TSPATTRIB_POLICY_SECRET_LIFETIME
#define TSM_TSPATTRIB_POLICY_POPUPSTRING                TSS_TSPATTRIB_POLICY_POPUPSTRING

// TSM_TSPATTRIB_POLICY_POPUPSTRING 子属性
#define TSM_TCPATTRIB_POLICY_DELEGATION_INFO            TSS_TSPATTRIB_POLICY_DELEGATION_INFO
#define TSM_TCPATTRIB_POLICY_DELEGATION_PCR             TSS_TSPATTRIB_POLICY_DELEGATION_PCR

// TSM_TSPATTRIB_SECRET_HASH_MODE 子属性
// 获取或设置在弹出模式下杂凑操作
//#define TSM_TSPATTRIB_SECRET_HASH_MODE_POPUP            TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP

//
//  Flags used for the 'mode' parameter in Tspi_Policy_SetSecret()
//
#define TSM_SECRET_MODE_NONE                TSS_SECRET_MODE_NONE
#define TSM_SECRET_MODE_PLAIN               TSS_SECRET_MODE_PLAIN
#define TSM_SECRET_MODE_POPUP               TSS_SECRET_MODE_POPUP
#define TSM_SECRET_MODE_SM3                 (0x00004000)

//////////////////////////////////////////////////////////////////////////
// 密钥对象属性定义
//////////////////////////////////////////////////////////////////////////
// 属性标记
// 获得/设置密钥所注册的永久存储区
#define TSM_TSPATTRIB_KEY_REGISTER              TSS_TSPATTRIB_KEY_REGISTER
// 获得/设置密钥 blob
#define TSM_TSPATTRIB_KEY_BLOB                  TSS_TSPATTRIB_KEY_BLOB
// 获得密钥信息
#define TSM_TSPATTRIB_KEY_INFO                  TSS_TSPATTRIB_KEY_INFO
// 获得 TSM_UUID结构，该结构包含为密钥所分配的 UUID 
#define TSM_TSPATTRIB_KEY_UUID                  TSS_TSPATTRIB_KEY_UUID
// 获得密钥所封装到的 PCR信息(用于采用TSM_KEY_STRUCT_KEY 结构的密钥)
#define TSM_TSPATTRIB_KEY_PCR                   TSS_TSPATTRIB_KEY_PCR_LONG
// 获得加载的密钥属性 
#define TSM_TSPATTRIB_KEY_CONTROLBIT            TSS_TSPATTRIB_KEY_CONTROLBIT

// TSM_TSPATTRIB_KEY_REGISTER 子属性
// 密钥注册到用户永久存储区
#define TSM_TSPATTRIB_KEYREGISTER_USER          TSS_TSPATTRIB_KEYREGISTER_USER
// 密钥注册到系统永久存储区
#define TSM_TSPATTRIB_KEYREGISTER_SYSTEM        TSS_TSPATTRIB_KEYREGISTER_SYSTEM
// 密钥未注册到永久存储区
#define TSM_TSPATTRIB_KEYREGISTER_NO            TSS_TSPATTRIB_KEYREGISTER_NO

// TSM_TSPATTRIB_KEY_BLOB 子属性
// 密钥 blob 形式的密钥信息
#define TSM_TSPATTRIB_KEYBLOB_BLOB              TSS_TSPATTRIB_KEYBLOB_BLOB
// 公钥 blob 形式的公钥信息
#define TSM_TSPATTRIB_KEYBLOB_PUBLIC_KEY        TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY
// 私钥 blob，是加密的私钥信息
#define TSM_TSPATTRIB_KEYBLOB_PRIVATE_KEY       TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY

// TSM_TSPATTRIB_KEY_INFO 子属性
// 密钥的比特长度
#define TSM_TSPATTRIB_KEYINFO_SIZE              TSS_TSPATTRIB_KEYINFO_SIZE
// 密钥使用信息
#define TSM_TSPATTRIB_KEYINFO_USAGE             TSS_TSPATTRIB_KEYINFO_USAGE
// 密钥标志
#define TSM_TSPATTRIB_KEYINFO_KEYFLAGS          TSS_TSPATTRIB_KEYINFO_KEYFLAGS
// 密钥授权使用信息
#define TSM_TSPATTRIB_KEYINFO_AUTHUSAGE         TSS_TSPATTRIB_KEYINFO_AUTHUSAGE
// 密钥算法标识
#define TSM_TSPATTRIB_KEYINFO_ALGORITHM         TSS_TSPATTRIB_KEYINFO_ALGORITHM
// 密钥签名方案
#define TSM_TSPATTRIB_KEYINFO_SIGSCHEME         TSS_TSPATTRIB_KEYINFO_SIGSCHEME
// 密钥加密方案
#define TSM_TSPATTRIB_KEYINFO_ENCSCHEME         TSS_TSPATTRIB_KEYINFO_ENCSCHEME
// 若为真则密钥是可迁移的
#define TSM_TSPATTRIB_KEYINFO_MIGRATABLE        TSS_TSPATTRIB_KEYINFO_MIGRATABLE
// 若为真则密钥是易失性的
#define TSM_TSPATTRIB_KEYINFO_VOLATILE          TSS_TSPATTRIB_KEYINFO_VOLATILE
// 若为真则需要授权
#define TSM_TSPATTRIB_KEYINFO_AUTHDATAUSAGE     TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE
// TSM 版本结构信息
#define TSM_TSPATTRIB_KEYINFO_VERSION           TSS_TSPATTRIB_KEYINFO_VERSION
// 密钥结构类型
#define TSM_TSPATTRIB_KEYINFO_KEYSTRUCT         TSS_TSPATTRIB_KEYINFO_KEYSTRUCT

// TSM_TSPATTRIB_KEY_PCR 子属性
// 创建 blob 时的 Locality 不确定
#define TSM_TSPATTRIB_KEYPCR_LOCALITY_ATCREATION            TSS_TSPATTRIB_KEYPCRLONG_LOCALITY_ATCREATION
// 使用密钥所需要的 locality
#define TSM_TSPATTRIB_KEYPCR_LOCALITY_ATRELEASE             TSS_TSPATTRIB_KEYPCRLONG_LOCALITY_ATRELEASE
// 选定创建 blob 时活动的 PCR
#define TSM_TSPATTRIB_KEYPCR_CREATION_SELECTION             TSS_TSPATTRIB_KEYPCRLONG_CREATION_SELECTION
// 选定使用密钥所需要的 PCR
#define TSM_TSPATTRIB_KEYPCR_RELEASE_SELECTION              TSS_TSPATTRIB_KEYPCRLONG_RELEASE_SELECTION
// digestAtCreation 值
#define TSM_TSPATTRIB_KEYPCR_DIGEST_ATCREATION              TSS_TSPATTRIB_KEYPCRLONG_DIGEST_ATCREATION
// digestAtRelease 值
#define TSM_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE               TSS_TSPATTRIB_KEYPCRLONG_DIGEST_ATRELEASE

// TSM_TSPATTRIB_KEY_INFO->TSM_TSPATTRIB_KEYINFO_USAGE 属性值
#define TSM_KEYUSAGE_SM2BIND                    TSS_KEYUSAGE_BIND
#define TSM_KEYUSAGE_SM2IDENTITY                TSS_KEYUSAGE_IDENTITY
#define TSM_KEYUSAGE_SM2SIGNING                 TSS_KEYUSAGE_SIGN
#define TSM_KEYUSAGE_SM2STORAGE                 TSS_KEYUSAGE_STORAGE
#define TSM_KEYUSAGE_SM2AUTHCHANGE              TSS_KEYUSAGE_AUTHCHANGE
#define TSM_KEYUSAGE_SM2MIGRATE                 TSS_KEYUSAGE_MIGRATE
#define TSM_KEYUSAGE_SMS4BIND                   ((UINT32)0x00000007)
#define TSM_KEYUSAGE_SMS4STORAGE                ((UINT32)0x00000008)
#define TSM_KEYUSAGE_SMS4MIGRATE                ((UINT32)0x00000009)

//////////////////////////////////////////////////////////////////////////
// 永久存储区标记定义
// persistent storage registration definitions
//////////////////////////////////////////////////////////////////////////
// 密钥被注册到用户永久存储空间
#define TSM_PS_TYPE_USER                        TSS_PS_TYPE_USER
// 密钥被注册到系统永久存储空间
#define TSM_PS_TYPE_SYSTEM                      TSS_PS_TYPE_SYSTEM

//////////////////////////////////////////////////////////////////////////
// Capability flag definitions
//////////////////////////////////////////////////////////////////////////
// TCS Capabilities
#define TSM_TCSCAP_ALG                          TSS_TCSCAP_ALG
#define TSM_TCSCAP_VERSION                      TSS_TCSCAP_VERSION
#define TSM_TCSCAP_MANUFACTURER                 TSS_TCSCAP_MANUFACTURER
#define TSM_TCSCAP_CACHING                      TSS_TCSCAP_CACHING
#define TSM_TCSCAP_PERSSTORAGE                  TSS_TCSCAP_PERSSTORAGE
#define TSM_TCSCAP_TRANSPORT                    TSS_TCSCAP_TRANSPORT

// TCM Capabilities
#define TSM_TCMCAP_ORD                          TSS_TPMCAP_ORD
#define TSM_TCMCAP_ALG                          TSS_TPMCAP_ALG
#define TSM_TCMCAP_FLAG                         TSS_TPMCAP_FLAG
#define TSM_TCMCAP_PROPERTY                     TSS_TPMCAP_PROPERTY
#define TSM_TCMCAP_VERSION                      TSS_TPMCAP_VERSION
#define TSM_TCMCAP_NV_LIST                      TSS_TPMCAP_NV_LIST
#define TSM_TCMCAP_NV_INDEX                     TSS_TPMCAP_NV_INDEX
#define TSM_TCMCAP_MFR                          TSS_TPMCAP_MFR
#define TSM_TCMCAP_SYM_MODE                     TSS_TPMCAP_SYM_MODE
#define TSM_TCMCAP_HANDLE                       TSS_TPMCAP_HANDLE
#define TSM_TCMCAP_TRANS_ES                     TSS_TPMCAP_TRANS_ES
#define TSM_TCMCAP_AUTH_ENCRYPT                 TSS_TPMCAP_AUTH_ENCRYPT
#define TSM_TCMCAP_VERSION_VAL					TSS_TPMCAP_VERSION_VAL
// TSM Service Provider Capabilities
#define TSM_TSPCAP_ALG                          TSS_TSPCAP_ALG
#define TSM_TSPCAP_VERSION                      TSS_TSPCAP_VERSION
#define TSM_TSPCAP_PERSSTORAGE                  TSS_TSPCAP_PERSSTORAGE
#define TSM_TSPCAP_MANUFACTURER                 TSS_TSPCAP_MANUFACTURER
#define TSM_TSPCAP_RETURNVALUE_INFO             TSS_TSPCAP_RETURNVALUE_INFO

// Sub-Capability Flags for TSS_TPMCAP_PROPERTY
#define TSM_TCMCAP_PROP_PCR                     TSS_TPMCAP_PROP_PCR
//#define TSM_TCMCAP_PROP_PCRMAP                  TSS_TPMCAP_PROP_DIR
#define TSM_TCMCAP_PROP_MANUFACTURER            TSS_TPMCAP_PROP_MANUFACTURER
#define TSM_TCMCAP_PROP_SLOTS                   TSS_TPMCAP_PROP_SLOTS
#define TSM_TCMCAP_PROP_KEYS                    TSS_TPMCAP_PROP_KEYS
#define TSM_TCMCAP_PROP_OWNER                   TSS_TPMCAP_PROP_OWNER
#define TSM_TCMCAP_PROP_MAXKEYS                 TSS_TPMCAP_PROP_MAXKEYS
#define TSM_TCMCAP_PROP_AUTHSESSIONS            TSS_TPMCAP_PROP_AUTHSESSIONS
#define TSM_TCMCAP_PROP_MAXAUTHSESSIONS         TSS_TPMCAP_PROP_MAXAUTHSESSIONS
#define TSM_TCMCAP_PROP_TRANSESSIONS            TSS_TPMCAP_PROP_TRANSESSIONS
#define TSM_TCMCAP_PROP_MAXTRANSESSIONS         TSS_TPMCAP_PROP_MAXTRANSESSIONS
#define TSM_TCMCAP_PROP_SESSIONS                TSS_TPMCAP_PROP_SESSIONS
#define TSM_TCMCAP_PROP_MAXSESSIONS             TSS_TPMCAP_PROP_MAXSESSIONS
#define TSM_TCMCAP_PROP_CONTEXTS                TSS_TPMCAP_PROP_CONTEXTS
#define TSM_TCMCAP_PROP_MAXCONTEXTS             TSS_TPMCAP_PROP_MAXCONTEXTS
#define TSM_TCMCAP_PROP_COUNTERS                TSS_TPMCAP_PROP_COUNTERS
#define TSM_TCMCAP_PROP_MAXCOUNTERS             TSS_TPMCAP_PROP_MAXCOUNTERS
#define TSM_TCMCAP_PROP_MIN_COUNTER             TSS_TPMCAP_PROP_MIN_COUNTER
//#define TSM_TSPATTRIB_TCMCAP_MIN_COUNTER        TSM_TCMCAP_PROP_MIN_COUNTER    // 不确定: TSS_TPMCAP_PROP_MIN_COUNTER
#define TSM_TCMCAP_PROP_MINCOUNTERINCTIME       ((UINT32)0x00000034)
#define TSM_TCMCAP_PROP_ACTIVECOUNTER           TSS_TPMCAP_PROP_ACTIVECOUNTER
#define TSM_TCMCAP_PROP_TISTIMEOUTS             TSS_TPMCAP_PROP_TISTIMEOUTS
#define TSM_TCMCAP_PROP_STARTUPEFFECTS          TSS_TPMCAP_PROP_STARTUPEFFECTS
#define TSM_TCMCAP_PROP_MAXCONTEXTCOUNTDIST     TSS_TPMCAP_PROP_MAXCONTEXTCOUNTDIST
#define TSM_TCMCAP_PROP_DURATION                TSS_TPMCAP_PROP_DURATION
#define TSM_TCMCAP_PROP_MAXNVAVAILABLE          TSS_TPMCAP_PROP_MAXNVAVAILABLE
#define TSM_TCMCAP_PROP_INPUTBUFFERSIZE         TSS_TPMCAP_PROP_INPUTBUFFERSIZE
#define TSM_TCMCAP_PROP_REVISION                TSS_TPMCAP_PROP_REVISION
#define TSM_TCMCAP_PROP_LOCALITIES_AVAIL        TSS_TPMCAP_PROP_LOCALITIES_AVAIL
#define TSM_TCMCAP_PROP_PCRMAP                  ((UINT32)0x00000033)    // 不确定: TSS_TPMCAP_PROP_DIR
#define TSM_TCMCAP_PROP_MAXNVWRITE              ((UINT32)0x00000035)


//
//  algorithm ID definitions

//   Tspi_Context_GetCapability(TSS_TSPCAP_ALG)
//   Tspi_Context_GetCapability(TSS_TCSCAP_ALG)
#define TSM_ALG_HMAC                            TCM_ALG_HMAC
#define TSM_ALG_XOR                             TCM_ALG_XOR
#define TSM_ALG_SM2                             TCM_ALG_SM2
#define TSM_ALG_SMS4                            TCM_ALG_SMS4
#define TSM_ALG_SM3                             TCM_ALG_SM3
#define TSM_ALG_KDF                             TCM_ALG_KDF

#define TSM_ALG_DEFAULT                         TSS_ALG_DEFAULT
#define TSM_ALG_DEFAULT_SIZE                    TSS_ALG_DEFAULT_SIZE


// value for TSM_TCSCAP_MANUFACTURER
#define TSM_TCSCAP_PROP_MANUFACTURER_STR        TSS_TCSCAP_PROP_MANUFACTURER_STR
#define TSM_TCSCAP_PROP_MANUFACTURER_ID         TSS_TCSCAP_PROP_MANUFACTURER_ID
// value for TSM_TSPCAP_MANUFACTURER
#define TSM_TSPCAP_PROP_MANUFACTURER_STR        TSS_TSPCAP_PROP_MANUFACTURER_STR
#define TSM_TSPCAP_PROP_MANUFACTURER_ID         TSS_TSPCAP_PROP_MANUFACTURER_ID

// value for TSM_TCSCAP_CACHING
#define TSM_TCSCAP_PROP_KEYCACHE                TSS_TCSCAP_PROP_KEYCACHE
#define TSM_TCSCAP_PROP_AUTHCACHE               TSS_TCSCAP_PROP_AUTHCACHE

// value for TSM_TSPCAP_RETURNVALUE_INFO
#define TSM_TSPCAP_PROP_RETURNVALUE_INFO        TSS_TSPCAP_PROP_RETURNVALUE_INFO


//////////////////////////////////////////////////////////////////////////
// 算法支持
//////////////////////////////////////////////////////////////////////////


//
// key size definitions
//
#define TSM_KEY_SIZEVAL_128BIT                  (0x0080)
#define TSM_KEY_SIZEVAL_256BIT                  (0x0100)
#define TSM_KEY_SIZEVAL_512BIT                  (0x0200)
#define TSM_KEY_SIZEVAL_520BIT                  (0x0208)
#define TSM_KEY_SIZEVAL_1024BIT                 (0x0400)
#define TSM_KEY_SIZEVAL_2048BIT                 (0x0800)
#define TSM_KEY_SIZEVAL_4096BIT                 (0x1000)
#define TSM_KEY_SIZEVAL_8192BIT                 (0x2000)
#define TSM_KEY_SIZEVAL_16384BIT                (0x4000)

#define TSM_KEY_SIZEVAL_128BYTE                 (TSM_KEY_SIZEVAL_128BIT   / 8)
#define TSM_KEY_SIZEVAL_256BYTE                 (TSM_KEY_SIZEVAL_256BIT   / 8)
#define TSM_KEY_SIZEVAL_512BYTE                 (TSM_KEY_SIZEVAL_512BIT   / 8)
#define TSM_KEY_SIZEVAL_520BYTE                 (TSM_KEY_SIZEVAL_520BIT   / 8)
#define TSM_KEY_SIZEVAL_1024BYTE                (TSM_KEY_SIZEVAL_1024BIT  / 8)
#define TSM_KEY_SIZEVAL_2048BYTE                (TSM_KEY_SIZEVAL_2048BIT  / 8)
#define TSM_KEY_SIZEVAL_4096BYTE                (TSM_KEY_SIZEVAL_4096BIT  / 8)
#define TSM_KEY_SIZEVAL_8192BYTE                (TSM_KEY_SIZEVAL_8192BIT  / 8)
#define TSM_KEY_SIZEVAL_16384BYTE               (TSM_KEY_SIZEVAL_16384BIT / 8)

// \trousers\capabilities.h
/* TSP */
/* BOOL */
#define TSM_CAP_TSP_ALG_HMAC                    TRUE
#define TSM_CAP_TSP_ALG_SM2                     TRUE
#define TSM_CAP_TSP_ALG_SMS4                    FALSE
#define TSM_CAP_TSP_ALG_SM3                     TRUE
#define TSM_CAP_TSP_ALG_KDF                     FALSE
#define TSM_CAP_TSP_ALG_DEFAULT		            TSM_ALG_SM2
#define TSM_CAP_TSP_ALG_DEFAULT_SIZE	        TSM_KEY_SIZEVAL_256BIT

/* TCS */
/* BOOL */
#define TSM_CAP_TCS_ALG_HMAC                    FALSE
#define TSM_CAP_TCS_ALG_SM2                     FALSE
#define TSM_CAP_TCS_ALG_SMS4                    FALSE
#define TSM_CAP_TCS_ALG_SM3                     TRUE
#define TSM_CAP_TCS_ALG_KDF                     FALSE
#define TSM_CAP_TSP_ALG_DEFAULT		            TSM_ALG_SM2
#define TSM_CAP_TSP_ALG_DEFAULT_SIZE	        TSM_KEY_SIZEVAL_256BIT

#endif
