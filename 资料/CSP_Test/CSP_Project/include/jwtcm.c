
//#include "jwtcm.h"
//#include "jwtcs.h"
#include "jwtsm.h"
#include "loaddll/load_tddl.h"


#define UINT32_BYTE0(i)     ((BYTE)((i >> 24) & 0x000000FF))
#define UINT32_BYTE1(i)	    ((BYTE)((i >> 16) & 0x000000FF))
#define UINT32_BYTE2(i)     ((BYTE)((i >>  8) & 0x000000FF))
#define UINT32_BYTE3(i)     ((BYTE)(i & 0x000000FF))

#define B2I32_0(i)          (((UINT32)i << 24) & 0xFF000000)
#define B2I32_1(i)          (((UINT32)i << 16) & 0x00FF0000)
#define B2I32_2(i)          (((UINT32)i <<  8) & 0x0000FF00)
#define B2I32_3(i)          (((UINT32)i      ) & 0x000000FF)

#define BYTEBUF2UIN32(i)    (B2I32_0((i)[0]) | B2I32_1((i)[1]) | B2I32_2((i)[2]) | B2I32_3((i)[3]))

TSM_RESULT send_command(BYTE* data, BYTE* recv_buf, UINT32* recv_len)
{
	UINT32 len = BYTEBUF2UIN32(&data[2]);
	return gTddlModule.Tddli_TransmitData(data, len, recv_buf, recv_len);
}

//void TCM_Init(U8 *data_in,U8 *data_out);
TSM_RESULT TCM_Startup(UINT16 data, BYTE* recv_buf, UINT32* recv_len)
{
// �����ʽ
// ��ʶ ���ݳ��� ������ ��������
// 2B   4B       4B     2B

// ��ʶ:     TCM_TAG_RQU_COMMAND == 0x00C1
// ���ݳ���: 0x0000000C
// ������:   TCM_ORD_Startup == 0x00000099
// ��������: TCM_ST_CLEAR == 0x0001; TCM_ST_STATE == 0x0002; TCM_ST_DEACTIVED == 0x0003;

// ������ݸ�ʽ:
// ��ʶ ���ݳ��� ������
// 2B   4B       4B

// ��ʶ:     TCM_TAG_RSP_COMMAND == 0x00C4
// ���ݳ���: 0x0000000A
// ������:   Ϊ�������Ľ��(�������붨���)

	UINT32 len = 0x0C;
	BYTE buf[12] = {
		    TPM_TAG_RQU_COMMAND,
			UINT32_BYTE0(len), UINT32_BYTE1(len), UINT32_BYTE2(len), UINT32_BYTE3(len),
			TCM_ORD_Startup,
			(BYTE)(data >> 8 & 0x00FF), (BYTE)(data & 0x00FF)
			};

	return gTddlModule.Tddli_TransmitData(buf, len, recv_buf, recv_len);

}
