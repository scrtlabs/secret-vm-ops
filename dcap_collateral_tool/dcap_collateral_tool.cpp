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

#pragma pack (push, 1)

struct tdx_quote_hdr_t {
        uint16_t version;
        uint16_t key_type;
        uint32_t tee_type;
        uint32_t reserved;
        uint8_t qe_vendor_id[16];
        uint8_t user_data[20];
};

struct tdx_quote_t {
        tdx_quote_hdr_t header;
        uint8_t tcb_svn [16];
        uint8_t mr_seam [48];
        uint8_t mr_signer_seam [48];
        uint8_t seam_attributes [8];
        uint8_t td_attributes [8];
        uint8_t xfam [8];
        uint8_t mr_td [48];
        uint8_t mr_config_id [48];
        uint8_t mr_owner [48];
        uint8_t mr_config [48];
        uint8_t rtmr0 [48];
        uint8_t rtmr1 [48];
        uint8_t rtmr2 [48];
        uint8_t rtmr3 [48];
        uint8_t report_data [64];
};
    
#pragma pack (pop)

struct JsonObj
{
        bool m_NonEmpty = false;

        JsonObj()
        {
                printf("{");
        }

        ~JsonObj()
        {
                printf("}");
        }

        struct Quotes
        {
                Quotes()
                {
                        printf("\"");
                }
                ~Quotes()
                {
                        printf("\"");
                }
        };

        void Value(int n, const char* fmt = nullptr)
        {
                Quotes q;
                printf(fmt ? fmt : "%d", n);
        }

        template <uint32_t n>
        void Value(const uint8_t (&p)[n], const char*)
        {
                Quotes q;
                Hex::PrintToFile(p, n, stdout);
        }

        void AddElement(const char* sz)
        {
                if (m_NonEmpty)
                        printf(",");
                else
                        m_NonEmpty = true;
                        
                printf(" \"%s\": ", sz);
        }

        template <typename T>
        void AddField(const char* szField, const T& val, const char* fmt = nullptr)
        {
                AddElement(szField);
                Value(val, fmt);
        }
};

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

        JsonObj obj0;
        obj0.AddElement("collateral");

	std::vector<uint8_t> vQuote, vColl;
	vQuote.resize(nQuote);

	nLenQuote = Hex::Scan(&vQuote.front(), szQuote, nLenQuote);
	nQuote = nLenQuote / 2;

	uint32_t nColl = 0;
	uint8_t* pColl = nullptr;

	auto res = tee_qv_get_collateral(&vQuote.front(), nQuote, &pColl, &nColl);
        if (pColl)
        {
                {
                        JsonObj::Quotes q1;

                        SerializeCollateral(vColl, pColl, nColl);
                        if (!vColl.empty())
                                Hex::PrintToFile(&vColl.front(), (uint32_t) vColl.size(), stdout);
                }

                {
                        obj0.AddElement("status");
                        JsonObj obj1;

                        uint32_t nExpStatus = 0;
                        sgx_ql_qv_result_t qvRes = SGX_QL_QV_RESULT_UNSPECIFIED;
                        auto tNow = time(nullptr);
                        res = sgx_qv_verify_quote(&vQuote.front(), nQuote, (const sgx_ql_qve_collateral_t*) pColl, tNow, &nExpStatus, &qvRes, nullptr, 0, nullptr);
                
                        if (SGX_QL_SUCCESS == res)
                        {
                                obj1.AddField("result", qvRes);
                                obj1.AddField("exp_status", nExpStatus);
        
                        }
                        else
                                obj1.AddField("error", res);
                }

                if (nQuote >= sizeof(tdx_quote_hdr_t))
                {
                        const tdx_quote_hdr_t& hdr = *reinterpret_cast<const tdx_quote_hdr_t*>(&vQuote.front());

                        obj0.AddElement("quote");
                        JsonObj obj1;

                        obj1.AddField("version", hdr.version);
                        obj1.AddField("tee_type", hdr.tee_type, "%08x");

                        if ((4 == hdr.version) && (0x81 == hdr.tee_type) && (nQuote >= sizeof(tdx_quote_t)))
                        {
                                const tdx_quote_t& quote = *reinterpret_cast<const tdx_quote_t*>(&vQuote.front());
                                obj1.AddField("tcb_svn", quote.tcb_svn);
                                obj1.AddField("mr_seam", quote.mr_seam);
                                obj1.AddField("mr_signer_seam", quote.mr_signer_seam);
                                obj1.AddField("td_attributes", quote.td_attributes);
                                obj1.AddField("xfam", quote.xfam);
                                obj1.AddField("mr_td", quote.mr_td);
                                obj1.AddField("mr_config_id", quote.mr_config_id);
                                obj1.AddField("mr_owner", quote.mr_owner);
                                obj1.AddField("mr_config", quote.mr_config);
                                obj1.AddField("rtmr0", quote.rtmr0);
                                obj1.AddField("rtmr1", quote.rtmr1);
                                obj1.AddField("rtmr2", quote.rtmr2);
                                obj1.AddField("rtmr3", quote.rtmr3);
                                obj1.AddField("report_data", quote.report_data);
                        }
                        
                }
         
                tee_qv_free_collateral(pColl);
        }
        else
        {
                JsonObj obj1;
                obj1.AddElement("error");
                obj1.Value(res);
        }

 	
        return 0;
}

