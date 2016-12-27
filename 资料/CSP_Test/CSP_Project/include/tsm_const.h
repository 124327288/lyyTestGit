#ifndef __TSM_CONST_DEFINE_HEADER_
#define __TSM_CONST_DEFINE_HEADER_

#include "jwplatform.h"

#define TSM_SMK_UUID    ((TSM_UUID *)("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"))
#define TSM_NULL_UUID   ((TSM_UUID *)("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))

#define TSM_PIK_UUID    ((TSM_UUID *)("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"))
#define TSM_PEK_UUID    ((TSM_UUID *)("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"))

//////////////////////////////////////////////////////////////////////////
// �������Ͷ���
//////////////////////////////////////////////////////////////////////////
// ���Զ���
#define TSM_OBJECT_TYPE_POLICY                  TSS_OBJECT_TYPE_POLICY
// ��Կ����(�����Գ���ǶԳ�)
// ��TSS��ͬ, TSM�����ԳƺͷǶԳ�, TSSֻ�зǶԳ�
#define TSM_OBJECT_TYPE_KEY                     TSS_OBJECT_TYPE_RSAKEY
// �������ݶ����޶�ʹ�÷�Χ�����ݡ��ܷ����ݻ��ŷ��װ����
#define TSM_OBJECT_TYPE_ENCDATA                 TSS_OBJECT_TYPE_ENCDATA
// PCR����
#define TSM_OBJECT_TYPE_PCRS                    TSS_OBJECT_TYPE_PCRS
// �Ӵն���
#define TSM_OBJECT_TYPE_HASH                    TSS_OBJECT_TYPE_HASH
// ����ʧ�Դ洢����
#define TSM_OBJECT_TYPE_NV                      TSS_OBJECT_TYPE_NV
// Ǩ�����ݴ������
#define TSM_OBJECT_TYPE_MIGDATA                 TSS_OBJECT_TYPE_MIGDATA
// ��ԿЭ�̶���
#define TSM_OBJECT_TYPE_EXCHANGE                (0x0000000C)

//////////////////////////////////////////////////////////////////////////
// �����ʼ������
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
// ������Ȩ����Կ(ȱʡ����)
#define TSM_KEY_NO_AUTHORIZATION                TSS_KEY_NO_AUTHORIZATION
// ʹ������Ȩ����Կ
#define TSM_KEY_AUTHORIZATION                   TSS_KEY_AUTHORIZATION
// ��Կ��˽Կ����ʹ��ʱ����Ȩ����Կ
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
// ����ʧ����Կ������ʱ���Բ�����
#define TSM_KEY_NON_VOLATILE                    TSS_KEY_NON_VOLATILE
// ��ʧ����Կ������ʱ�������
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
// ����Ǩ����Կ(ȱʡ����)
#define TSM_KEY_NOT_MIGRATABLE                  TSS_KEY_NOT_MIGRATABLE
// ��Ǩ�Ƶ���Կ
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
// SM2 �洢������Կ
#define TSM_SM2KEY_TYPE_STORAGE                 (TSS_KEY_TYPE_STORAGE)
// SM2 ǩ����Կ
#define TSM_SM2KEY_TYPE_SIGNING                 (TSS_KEY_TYPE_SIGNING)
// SM2 ������Կ
#define TSM_SM2KEY_TYPE_BIND                    (TSS_KEY_TYPE_BIND)
// SM2 ��ݱ�ʶ��Կ
#define TSM_SM2KEY_TYPE_IDENTITY                (TSS_KEY_TYPE_IDENTITY)
// ��ʱ�� SM2 ��Կ�����ڸı���Ȩ����ֵ
#define TSM_SM2KEY_TYPE_AUTHCHANGE              (TSS_KEY_TYPE_AUTHCHANGE)
// SM2 Ǩ�Ʊ�����Կ
#define TSM_SM2KEY_TYPE_MIGRATE                 (TSS_KEY_TYPE_MIGRATE)
// SM2 ƽ̨������Կ
#define TSM_SM2KEY_TYPE_PEK                     ((UINT32)0x00000080)
// SMS4�洢������Կ
#define TSM_SMS4KEY_TYPE_STORAGE                ((UINT32)0x00000090)
// SMS4������Կ
#define TSM_SMS4KEY_TYPE_BIND                   ((UINT32)0x000000A0)
// SMS4��Ǩ����Կ
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
// ȱʡ����Կ����
#define TSM_KEY_SIZE_DEFAULT                    TSS_KEY_SIZE_DEFAULT
// ȱʡ�ĶԳ���Կ����
#define TSM_KEY_SIZE_DEFAULT_SYM                TSM_KEY_SIZE_DEFAULT
// ȱʡ�ķǶԳ���Կ����
#define TSM_KEY_SIZE_DEFAULT_ASY                TSM_KEY_SIZE_DEFAULT
// SMS4����Կ����Ϊ128-bit
#define TSM_KEY_SIZE_128                        (UINT32)(0x00000100)
// SM2��˽Կ����Ϊ256-bit
#define TSM_KEY_SIZE_256                        (UINT32)(0x00000200)
// SM2�Ĺ�Կ����Ϊ512-bit
#define TSM_KEY_SIZE_512                        (UINT32)(0x00000300)
// SM2�Ĺ�Կ����Ϊ520-bit
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
// ʹ��TCM��Կ����

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
// ��TCM��Կģ��(��TSM��Կ����)
#define TSM_KEY_EMPTY_KEY                       TSS_KEY_EMPTY_KEY
// ʹ�� TCM SMK ģ��(����SMK��TSM��Կ����)
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
//   TSS�淶 Legacy                                           |0 1 1|
//   Envelop                                                  |1 0 0|
//
//   ENCDATA Reserved:
//  |x x x x x x x x x x x x x x x x x x x x x x x x x x x x x|
//
// �������ݷ�װ���������ݶ���
#define TSM_ENCDATA_SEAL                        TSS_ENCDATA_SEAL
// ���ڼ��ܲ��������ݶ���
#define TSM_ENCDATA_BIND                        TSS_ENCDATA_BIND
// ���������ŷ���������ݶ���
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
//  TSS�淶 SHA1
//  |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1|
//   OTHER
//  |1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1|
//
// ȱʡ�����Ӵ��㷨
#define TSM_HASH_DEFAULT                        TSS_HASH_DEFAULT
#define TSM_HASH_SHA1                           (0x00000001)
// SM3�㷨���Ӵն���
#define TSM_HASH_SM3                            (0x00000002)
// �����㷨���Ӵն���
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
// ������Ȩ�Ĳ��Զ���
#define TSM_POLICY_USAGE                        TSS_POLICY_USAGE
// ������ԿǨ�ƵĲ��Զ���
#define TSM_POLICY_MIGRATION                    TSS_POLICY_MIGRATION
// ���ڲ�������Ȩ�Ĳ��Զ���
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
// ʹ��TCM��PCR����
#define TSM_PCRS_STRUCT_INFO                    TSS_PCRS_STRUCT_INFO_LONG

//////////////////////////////////////////////////////////////////////////
// �����Ķ�������Զ���
//////////////////////////////////////////////////////////////////////////
// ���Ա��
// ��ȡ������һ�������Ķ��������ģʽ
#define TSM_TSPATTRIB_CONTEXT_SILENT_MODE                   TSS_TSPATTRIB_CONTEXT_SILENT_MODE
// ���TSM�Ļ�����
#define TSM_TSPATTRIB_CONTEXT_MACHINE_NAME                  TSS_TSPATTRIB_CONTEXT_MACHINE_NAME
// ��ȡ�����ð汾������Ϣ�����ڴ��������Ķ����ģʽ 
#define TSM_TSPATTRIB_CONTEXT_VERSION_MODE                  TSS_TSPATTRIB_CONTEXT_VERSION_MODE
// ������ӵ����֧�ְ汾(TSM��TCM�����ͨ�ð汾) 
#define TSM_TSPATTRIB_CONTEXT_CONNECTION_VERSION            TSS_TSPATTRIB_CONTEXT_CONNECTION_VERSION
// ��ȡ��������������Ķ���������Ĵ���Ự���������
#define TSM_TSPATTRIB_CONTEXT_TRANSPORT                     TSS_TSPATTRIB_CONTEXT_TRANSPORT
// ���/���������Ļ���Զ�����Ӵղ���ģʽ
#define TSM_TSPATTRIB_SECRET_HASH_MODE                      TSS_TSPATTRIB_SECRET_HASH_MODE

// TSM_TSPATTRIB_CONTEXT_TRANSPORT ������
// ����رմ���Ự
#define TSM_TSPATTRIB_CONTEXTTRANS_CONTROL                  TSS_TSPATTRIB_CONTEXTTRANS_CONTROL
// ���ƴ���Ự������
#define TSM_TSPATTRIB_CONTEXTTRANS_MODE                     TSS_TSPATTRIB_CONTEXTTRANS_MODE
// TSM_TSPATTRIB_SECRET_HASH_MODE ������
// ��ȡ�������ڵ���ģʽ���Ӵղ���
#define TSM_TSPATTRIB_SECRET_HASH_MODE_POPUP                TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP


// TSM_TSPATTRIB_CONTEXT_SILENT_MODE ����ֵ
// �����û��ṩ����ʱ����ʾ TSM �Ի���
#define TSM_TSPATTRIB_CONTEXT_NOT_SILENT                    TSS_TSPATTRIB_CONTEXT_NOT_SILENT
//����ʾ TSM�Ի���(Ĭ��)
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
// ʹ����Ự�����ݼ��ܹ��ܹر�
#define TSM_TSPATTRIB_TRANSPORT_NO_DEFAULT_ENCRYPTION       TSS_TSPATTRIB_TRANSPORT_NO_DEFAULT_ENCRYPTION
// ʹ����Ự�����ݼ��ܹ��ܴ�
#define TSM_TSPATTRIB_TRANSPORT_DEFAULT_ENCRYPTION          TSS_TSPATTRIB_TRANSPORT_DEFAULT_ENCRYPTION
// ��������ģʽ
#define TSM_TSPATTRIB_TRANSPORT_EXCLUSIVE                   TSS_TSPATTRIB_TRANSPORT_EXCLUSIVE

//////////////////////////////////////////////////////////////////////////
// TCM �������Զ���
//////////////////////////////////////////////////////////////////////////
// ��������TCM�а��ճ����ܱ�������λ�õ����������ض�����
#define TSM_TSPATTRIB_TCMCAP_SET_VENDOR         ((UINT32)0x00000004)
// ������б���ӻ����һ��������
#define TSM_TSPATTRIB_TCM_ORDINAL_AUDIT_STATUS  TSS_TSPATTRIB_TPM_ORDINAL_AUDIT_STATUS
//  ��ʾ������������������Сʱ�������ü���� 1/10 ��Ϊ������λ�� 
#define TSM_TSPATTRIB_TCMCAP_MIN_COUNTER        ((UINT32)0x00000005)
//  ���� TCM ������־��
#define TSM_TSPATTRIB_TCMCAP_FLAG_VOLATILE      ((UINT32)0x00000006)
//
#define TSM_TSPATTRIB_TCM_CREDENTIAL            TSS_TSPATTRIB_TPM_CREDENTIAL

// TSM_TSPATTRIB_TCM_ORDINAL_AUDIT_STATUS ������
// ������б��м���һ��������
#define TCM_CAP_PROP_TCM_SET_ORDINAL_AUDIT      TPM_CAP_PROP_TPM_SET_ORDINAL_AUDIT
// Ҫ��ӵ�����б��л���Ҫ������б���ɾ����������
#define TCM_CAP_PROP_TCM_CLEAR_ORDINAL_AUDIT    TPM_CAP_PROP_TPM_CLEAR_ORDINAL_AUDIT

// TSM_TSPATTRIB_TCM_CREDENTIAL ������
// ����ģ��֤��blob
#define TSM_TCMATTRIB_EKCERT                    TSS_TPMATTRIB_EKCERT
// ƽ̨���֤�� blob
#define TSM_TCMATTRIB_PLATFORMCERT              TSS_TPMATTRIB_PLATFORMCERT 

//////////////////////////////////////////////////////////////////////////
// ���Զ������Զ���
//////////////////////////////////////////////////////////////////////////
// ���Ա��
// ���/���������Ļ���Զ�����Ӵղ���ģʽ
//#define TSM_TSPATTRIB_SECRET_HASH_MODE                  TSS_TSPATTRIB_SECRET_HASH_MODE
#define TSM_TSPATTRIB_POLICY_SECRET_LIFETIME            TSS_TSPATTRIB_POLICY_SECRET_LIFETIME
#define TSM_TSPATTRIB_POLICY_POPUPSTRING                TSS_TSPATTRIB_POLICY_POPUPSTRING

// TSM_TSPATTRIB_POLICY_POPUPSTRING ������
#define TSM_TCPATTRIB_POLICY_DELEGATION_INFO            TSS_TSPATTRIB_POLICY_DELEGATION_INFO
#define TSM_TCPATTRIB_POLICY_DELEGATION_PCR             TSS_TSPATTRIB_POLICY_DELEGATION_PCR

// TSM_TSPATTRIB_SECRET_HASH_MODE ������
// ��ȡ�������ڵ���ģʽ���Ӵղ���
//#define TSM_TSPATTRIB_SECRET_HASH_MODE_POPUP            TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP

//
//  Flags used for the 'mode' parameter in Tspi_Policy_SetSecret()
//
#define TSM_SECRET_MODE_NONE                TSS_SECRET_MODE_NONE
#define TSM_SECRET_MODE_PLAIN               TSS_SECRET_MODE_PLAIN
#define TSM_SECRET_MODE_POPUP               TSS_SECRET_MODE_POPUP
#define TSM_SECRET_MODE_SM3                 (0x00004000)

//////////////////////////////////////////////////////////////////////////
// ��Կ�������Զ���
//////////////////////////////////////////////////////////////////////////
// ���Ա��
// ���/������Կ��ע������ô洢��
#define TSM_TSPATTRIB_KEY_REGISTER              TSS_TSPATTRIB_KEY_REGISTER
// ���/������Կ blob
#define TSM_TSPATTRIB_KEY_BLOB                  TSS_TSPATTRIB_KEY_BLOB
// �����Կ��Ϣ
#define TSM_TSPATTRIB_KEY_INFO                  TSS_TSPATTRIB_KEY_INFO
// ��� TSM_UUID�ṹ���ýṹ����Ϊ��Կ������� UUID 
#define TSM_TSPATTRIB_KEY_UUID                  TSS_TSPATTRIB_KEY_UUID
// �����Կ����װ���� PCR��Ϣ(���ڲ���TSM_KEY_STRUCT_KEY �ṹ����Կ)
#define TSM_TSPATTRIB_KEY_PCR                   TSS_TSPATTRIB_KEY_PCR_LONG
// ��ü��ص���Կ���� 
#define TSM_TSPATTRIB_KEY_CONTROLBIT            TSS_TSPATTRIB_KEY_CONTROLBIT

// TSM_TSPATTRIB_KEY_REGISTER ������
// ��Կע�ᵽ�û����ô洢��
#define TSM_TSPATTRIB_KEYREGISTER_USER          TSS_TSPATTRIB_KEYREGISTER_USER
// ��Կע�ᵽϵͳ���ô洢��
#define TSM_TSPATTRIB_KEYREGISTER_SYSTEM        TSS_TSPATTRIB_KEYREGISTER_SYSTEM
// ��Կδע�ᵽ���ô洢��
#define TSM_TSPATTRIB_KEYREGISTER_NO            TSS_TSPATTRIB_KEYREGISTER_NO

// TSM_TSPATTRIB_KEY_BLOB ������
// ��Կ blob ��ʽ����Կ��Ϣ
#define TSM_TSPATTRIB_KEYBLOB_BLOB              TSS_TSPATTRIB_KEYBLOB_BLOB
// ��Կ blob ��ʽ�Ĺ�Կ��Ϣ
#define TSM_TSPATTRIB_KEYBLOB_PUBLIC_KEY        TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY
// ˽Կ blob���Ǽ��ܵ�˽Կ��Ϣ
#define TSM_TSPATTRIB_KEYBLOB_PRIVATE_KEY       TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY

// TSM_TSPATTRIB_KEY_INFO ������
// ��Կ�ı��س���
#define TSM_TSPATTRIB_KEYINFO_SIZE              TSS_TSPATTRIB_KEYINFO_SIZE
// ��Կʹ����Ϣ
#define TSM_TSPATTRIB_KEYINFO_USAGE             TSS_TSPATTRIB_KEYINFO_USAGE
// ��Կ��־
#define TSM_TSPATTRIB_KEYINFO_KEYFLAGS          TSS_TSPATTRIB_KEYINFO_KEYFLAGS
// ��Կ��Ȩʹ����Ϣ
#define TSM_TSPATTRIB_KEYINFO_AUTHUSAGE         TSS_TSPATTRIB_KEYINFO_AUTHUSAGE
// ��Կ�㷨��ʶ
#define TSM_TSPATTRIB_KEYINFO_ALGORITHM         TSS_TSPATTRIB_KEYINFO_ALGORITHM
// ��Կǩ������
#define TSM_TSPATTRIB_KEYINFO_SIGSCHEME         TSS_TSPATTRIB_KEYINFO_SIGSCHEME
// ��Կ���ܷ���
#define TSM_TSPATTRIB_KEYINFO_ENCSCHEME         TSS_TSPATTRIB_KEYINFO_ENCSCHEME
// ��Ϊ������Կ�ǿ�Ǩ�Ƶ�
#define TSM_TSPATTRIB_KEYINFO_MIGRATABLE        TSS_TSPATTRIB_KEYINFO_MIGRATABLE
// ��Ϊ������Կ����ʧ�Ե�
#define TSM_TSPATTRIB_KEYINFO_VOLATILE          TSS_TSPATTRIB_KEYINFO_VOLATILE
// ��Ϊ������Ҫ��Ȩ
#define TSM_TSPATTRIB_KEYINFO_AUTHDATAUSAGE     TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE
// TSM �汾�ṹ��Ϣ
#define TSM_TSPATTRIB_KEYINFO_VERSION           TSS_TSPATTRIB_KEYINFO_VERSION
// ��Կ�ṹ����
#define TSM_TSPATTRIB_KEYINFO_KEYSTRUCT         TSS_TSPATTRIB_KEYINFO_KEYSTRUCT

// TSM_TSPATTRIB_KEY_PCR ������
// ���� blob ʱ�� Locality ��ȷ��
#define TSM_TSPATTRIB_KEYPCR_LOCALITY_ATCREATION            TSS_TSPATTRIB_KEYPCRLONG_LOCALITY_ATCREATION
// ʹ����Կ����Ҫ�� locality
#define TSM_TSPATTRIB_KEYPCR_LOCALITY_ATRELEASE             TSS_TSPATTRIB_KEYPCRLONG_LOCALITY_ATRELEASE
// ѡ������ blob ʱ��� PCR
#define TSM_TSPATTRIB_KEYPCR_CREATION_SELECTION             TSS_TSPATTRIB_KEYPCRLONG_CREATION_SELECTION
// ѡ��ʹ����Կ����Ҫ�� PCR
#define TSM_TSPATTRIB_KEYPCR_RELEASE_SELECTION              TSS_TSPATTRIB_KEYPCRLONG_RELEASE_SELECTION
// digestAtCreation ֵ
#define TSM_TSPATTRIB_KEYPCR_DIGEST_ATCREATION              TSS_TSPATTRIB_KEYPCRLONG_DIGEST_ATCREATION
// digestAtRelease ֵ
#define TSM_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE               TSS_TSPATTRIB_KEYPCRLONG_DIGEST_ATRELEASE

// TSM_TSPATTRIB_KEY_INFO->TSM_TSPATTRIB_KEYINFO_USAGE ����ֵ
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
// ���ô洢����Ƕ���
// persistent storage registration definitions
//////////////////////////////////////////////////////////////////////////
// ��Կ��ע�ᵽ�û����ô洢�ռ�
#define TSM_PS_TYPE_USER                        TSS_PS_TYPE_USER
// ��Կ��ע�ᵽϵͳ���ô洢�ռ�
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
//#define TSM_TSPATTRIB_TCMCAP_MIN_COUNTER        TSM_TCMCAP_PROP_MIN_COUNTER    // ��ȷ��: TSS_TPMCAP_PROP_MIN_COUNTER
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
#define TSM_TCMCAP_PROP_PCRMAP                  ((UINT32)0x00000033)    // ��ȷ��: TSS_TPMCAP_PROP_DIR
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
// �㷨֧��
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
