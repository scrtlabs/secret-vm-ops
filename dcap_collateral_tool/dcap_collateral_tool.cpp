#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>
#include <cstring>
#include <vector>
#include "sgx_dcap_quoteverify.h"

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

void SerializeCollateral(std::vector<uint8_t>& ret, const uint8_t* pColl, uint32_t nColl)
{
        if (nColl < sizeof(sgx_ql_qve_collateral_t))
                return;

        const auto* p_ql_col = reinterpret_cast<const sgx_ql_qve_collateral_t*>(pColl);
        
        uint32_t size_extra = p_ql_col->pck_crl_issuer_chain_size
                + p_ql_col->root_ca_crl_size
                + p_ql_col->pck_crl_size
                + p_ql_col->tcb_info_issuer_chain_size
                + p_ql_col->tcb_info_size
                + p_ql_col->qe_identity_issuer_chain_size
                + p_ql_col->qe_identity_size;

        if (nColl < sizeof(sgx_ql_qve_collateral_t) + size_extra)
                return;

#pragma pack (push, 1)
        struct QlQveCollateral {
                uint32_t tee_type;
                uint32_t pck_crl_issuer_chain_size;
                uint32_t root_ca_crl_size;
                uint32_t pck_crl_size;
                uint32_t tcb_info_issuer_chain_size;
                uint32_t tcb_info_size;
                uint32_t qe_identity_issuer_chain_size;
                uint32_t qe_identity_size;
        };
#pragma pack (pop)
                    
        
        uint32_t out_size = sizeof(QlQveCollateral) + size_extra;

        ret.resize(out_size);
        auto& x = *reinterpret_cast<QlQveCollateral*>(&ret.front());

        x.tee_type = p_ql_col->tee_type;
        x.pck_crl_issuer_chain_size = p_ql_col->pck_crl_issuer_chain_size;
        x.root_ca_crl_size = p_ql_col->root_ca_crl_size;
        x.pck_crl_size = p_ql_col->pck_crl_size;
        x.tcb_info_issuer_chain_size = p_ql_col->tcb_info_issuer_chain_size;
        x.tcb_info_size = p_ql_col->tcb_info_size;
        x.qe_identity_issuer_chain_size = p_ql_col->qe_identity_issuer_chain_size;
        x.qe_identity_size = p_ql_col->qe_identity_size;

        uint32_t offs = sizeof(QlQveCollateral);
        
        memcpy(&ret.front() + offs, p_ql_col->pck_crl_issuer_chain, x.pck_crl_issuer_chain_size);
        offs += x.pck_crl_issuer_chain_size;

        memcpy(&ret.front() + offs, p_ql_col->root_ca_crl, x.root_ca_crl_size);
        offs += x.root_ca_crl_size;
        
        memcpy(&ret.front() + offs, p_ql_col->pck_crl, x.pck_crl_size);
        offs += x.pck_crl_size;
        
        memcpy(&ret.front() + offs, p_ql_col->tcb_info_issuer_chain, x.tcb_info_issuer_chain_size);
        offs += x.tcb_info_issuer_chain_size;
        
        memcpy(&ret.front() + offs, p_ql_col->tcb_info, x.tcb_info_size);
        offs += x.tcb_info_size;

        memcpy(&ret.front() + offs, p_ql_col->qe_identity_issuer_chain, x.qe_identity_issuer_chain_size);
        offs += x.qe_identity_issuer_chain_size;

        memcpy(&ret.front() + offs, p_ql_col->qe_identity, x.qe_identity_size);
        offs += x.qe_identity_issuer_chain_size;
}


int main(int argc, char *argv[])
{
        if (argc < 2)
        {
                printf("Quote missing\n");
                return 1;
        }

	auto szQuote = argv[1];
	auto nLenQuote = strlen(szQuote);
	auto nQuote = nLenQuote / 2;

	if (!nQuote)
	{
                printf("Quote is empty\n");
                return 1;
 	}

	std::vector<uint8_t> vQuote, vColl;
	vQuote.resize(nQuote);

	nLenQuote = Hex::Scan(&vQuote.front(), szQuote, nLenQuote);
	nQuote = nLenQuote / 2;

	uint32_t nColl = 0;
	uint8_t* pColl = nullptr;

	auto res = tee_qv_get_collateral(&vQuote.front(), nQuote, &pColl, &nColl);

	if (!pColl)
	{
	        printf("Failed to get collateral: %d\n", res);
        	return 1;
	}

	SerializeCollateral(vColl, pColl, nColl);

	printf("\nFetched Collateral: \n");
        if (!vColl.empty())
	        Hex::PrintToFile(&vColl.front(), (uint32_t) vColl.size(), stdout);
	printf("\n\n");

	uint32_t nExpStatus = 0;
	sgx_ql_qv_result_t qvRes = SGX_QL_QV_RESULT_UNSPECIFIED;
	auto tNow = time(nullptr);
	res = sgx_qv_verify_quote(&vQuote.front(), nQuote, (const sgx_ql_qve_collateral_t*) pColl, tNow, &nExpStatus, &qvRes, nullptr, 0, nullptr);

	tee_qv_free_collateral(pColl);

	if (SGX_QL_SUCCESS != res)
	{
                printf("Failed to verify quote: %d\n", res);
                return 1;
 	}

	printf("Quote verification result: %d\n", qvRes);
	printf("Collateral expiration status: %d\n", nExpStatus);
 	
        return 0;
}

