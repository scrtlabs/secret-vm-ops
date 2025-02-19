#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "tdx_attest.h"
#include <assert.h>
#include <cstring>

namespace Hex {

	char ChFromHex(uint8_t v)
	{
		return v + ((v < 10) ? '0' : ('a' - 10));
	}

	uint8_t Ch2Hex(uint8_t c)
	{
		if (c >= 'a' && c <= 'f')
			return 0xa + (c - 'a');

		if (c >= 'A' && c <= 'F')
			return 0xa + (c - 'A');

		return c - '0';
	}

	void PrintNoZTerm(const uint8_t* pDst, uint32_t nDst, char* sz)
	{
		for (uint32_t i = 0; i < nDst; i++)
		{
			sz[i * 2] = ChFromHex(pDst[i] >> 4);
			sz[i * 2 + 1] = ChFromHex(pDst[i] & 0xf);
		}
	}

	static const uint32_t s_Block = 256;

	void PrintBlockToFile(const uint8_t* pDst, uint32_t nDst, FILE* pf)
	{
		assert(nDst <= s_Block);
		char szBuf[s_Block * 2];

		PrintNoZTerm(pDst, nDst, szBuf);
		fwrite(szBuf, 1, nDst * 2, pf);
	}

	void PrintToFile(const uint8_t* pDst, uint32_t nDst, FILE* pf)
	{
		const uint32_t nBlock = 256;
		char szBuf[nBlock*2 /* + 1 */];

		while (nDst > s_Block)
		{
			PrintBlockToFile(pDst, s_Block, pf);
			pDst += s_Block;
			nDst -= s_Block;
		}

		PrintBlockToFile(pDst, nDst, pf);
	}

	void PrintField(const uint8_t* pDst, uint32_t nDst, FILE* pf, const char* szName)
	{
		fputs(szName, pf);
		fputs(": ", pf);
		PrintToFile(pDst, nDst, pf);
		fputc('\n', pf);
	}

	template <typename T>
	void PrintField_T(const T& x, const char* szName)
	{
		PrintField((const uint8_t*) &x, sizeof(T), stdout, szName);
	}

	uint32_t Scan(uint8_t* pDst, const char* sz, uint32_t nTxtLen)
	{
		uint32_t ret = 0;
		for (; ret < nTxtLen; ret++)
		{
			uint8_t x = Ch2Hex(sz[ret]);
			if (x > 0xf)
				break;

			if (1 & ret)
				*pDst++ |= x;
			else
				*pDst = (x << 4);
		}

		return ret;
	}


}

bool WrapTdxCall(int tdxRes, const char* szOpName)
{
	if (TDX_ATTEST_SUCCESS == tdxRes)
		return true;

	fprintf(stderr, "Failed %s retval %d\n", szOpName, tdxRes);
	return false;
}

#define CommandsAll(macro) \
	macro(report) \
	macro(attest) \
	macro(extendrt)

#define IMPL_CMD(command) int OnCommand_##command(int argc, char* argv[])

#pragma pack (push, 1)

struct TdxReport {

	uint8_t m_pOpaque1[128];
	uint8_t m_pReportData[64];
	uint8_t m_pOpaque2[72];
	uint8_t m_pTcbSvn[16];
	uint8_t m_pMrSeam[48];
	uint8_t m_pOpaque3[200];
	uint8_t m_pMrTd[48];
	uint8_t m_pMrConfigId[48];
	uint8_t m_pMrOwner[48];
	uint8_t m_pMrOwnerConfig[48];
	uint8_t m_pRtmr0[48];
	uint8_t m_pRtmr1[48];
	uint8_t m_pRtmr2[48];
	uint8_t m_pRtmr3[48];

	// continued
};
#pragma pack (pop)

IMPL_CMD(report)
{
    tdx_report_data_t report_data = {{0}};
	
	if (argc >= 1)
		Hex::Scan(report_data.d, argv[0], sizeof(report_data.d) * 2);
	
	tdx_report_t tdx_report = {{0}};
	if (!WrapTdxCall(tdx_att_get_report(&report_data, &tdx_report), "tdx_att_get_report"))
		return 1;

	static_assert(sizeof(TdxReport) <= sizeof(tdx_report_t), "");
	const auto& r = reinterpret_cast<const TdxReport&>(tdx_report);

	Hex::PrintField_T(r.m_pTcbSvn, "TCB_SVN");
	Hex::PrintField_T(r.m_pMrSeam, "MRSEAM");
	Hex::PrintField_T(r.m_pMrTd, "MRTD");
	Hex::PrintField_T(r.m_pRtmr0, "RTMR0");
	Hex::PrintField_T(r.m_pRtmr1, "RTMR1");
	Hex::PrintField_T(r.m_pRtmr2, "RTMR2");
	Hex::PrintField_T(r.m_pRtmr3, "RTMR3");

	return 0;
}

IMPL_CMD(attest)
{
	if (argc < 1)
	{
		printf("report data not specified\n");
		return 1;
	}

    tdx_report_data_t report_data = {{0}};
	Hex::Scan(report_data.d, argv[0], sizeof(report_data.d) * 2);

    tdx_report_t tdx_report = {{0}};
	if (!WrapTdxCall(tdx_att_get_report(&report_data, &tdx_report), "tdx_att_get_report"))
		return 1;

	tdx_uuid_t selected_att_key_id = {0};
	uint8_t* pQuote = NULL;
	uint32_t nQuote = 0;

	if (!WrapTdxCall(tdx_att_get_quote(&report_data, NULL, 0, &selected_att_key_id, &pQuote, &nQuote, 0), "tdx_att_get_quote"))
		return 1;

	Hex::PrintToFile(pQuote, nQuote, stdout);

	tdx_att_free_quote(pQuote);

	return 0;
}

IMPL_CMD(extendrt)
{
	if (argc < 2)
	{
		printf("rt index and data not specified\n");
		return 1;
	}

	tdx_rtmr_event_t rtmr_event = { 0 };


	rtmr_event.version = 1;
	rtmr_event.event_data_size = 0; // not supported by api atm

	rtmr_event.rtmr_index = atoi(argv[0]);
	Hex::Scan(rtmr_event.extend_data, argv[1], sizeof(rtmr_event.extend_data) * 2);

	if (!WrapTdxCall(tdx_att_extend(&rtmr_event), "tdx_att_extend"))
		return 1;

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		printf("command missing\n");
		return 1;
	}

	auto szCmd = argv[1];
	argv += 2;
	argc -= 2;

#define THE_MACRO(command) if (!strcmp(szCmd, #command)) return OnCommand_##command(argc, argv);
	CommandsAll(THE_MACRO)
#undef THE_MACRO

	printf("Unrecoginzed command\n");
	return 1;
}
