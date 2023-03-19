#pragma once

#include <stdexcept>
#include <cstdint>
#include <cstring>
#include <vector>
#include <map>
#include <arpa/inet.h>

struct comon_netflow_header
{
    uint16_t version, count;
};

namespace netflow_v5
{
    struct Header
    {
        struct comon_netflow_header comon;
        uint32_t sys_uptime, unix_secs, unix_nsecs, flow_sequence;
        uint8_t engine_type, engine_id;
        struct
        {
#if __BYTE_ORDER == __BIG_ENDIAN
            uint8_t sampling_mode : 2;
            uint16_t sample_rate : 14;
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN
            uint16_t sample_rate : 14;
            uint8_t sampling_mode : 2;
#endif
        } sampling_interval;
    };

    struct FlowRecord
    {
        uint32_t srcaddr, dstaddr, nexthop;
        uint16_t input, output;
        uint32_t dPkts, dOctets, first, last;
        uint16_t srcport, dstport;
        uint8_t pad1, tcp_flags, prot, tos;
        uint16_t src_as, dst_as;
        uint8_t src_mask, dst_mask;
        uint16_t pad2;
    };

    /**
     * @param data -> the data packet after the netflow header
     * @param pack_len -> current length of data packet
     *
     * @brief
     * if the calculated size of DataFlowRecord_array is higher then data packet length,
     * this function will throw an length_error
     */
    std::vector<FlowRecord> parseFlow(Header &header, const unsigned char *data, const int pack_len)
    {
        if (pack_len < sizeof(FlowRecord) * ntohs(header.comon.count))
            throw std::length_error("the size of the data packet does not match the calculated size");
        std::vector<FlowRecord> flowset;
        for (int i = 0; i < ntohs(header.comon.count); i++)
        {
            flowset.push_back(*(FlowRecord *)(data + (sizeof(FlowRecord) * i)));
        }

        return flowset;
    }
};

namespace netflow_v9_v10
{

    struct header{
        struct comon_netflow_header comon;
        uint32_t sysUptime, UnixSecs, SequenceNumber, SID;
    };

    class NF9{
    private:

        // source = https://www.rfc-editor.org/rfc/rfc3954.html#section-8
        enum RecordTypes : uint8_t{
            IN_BYTES = 1,
            IN_PKTS = 2,
            FLOWS = 3,
            PROTOCOL = 4,
            TOS = 5,
            TCP_FLAGS = 6,
            L4_SRC_PORT = 7,
            IPV4_SRC_ADDR = 8,
            SRC_MASK = 9,
            INPUT_SNMP = 10,
            L4_DST_PORT = 11,
            IPV4_DST_ADDR = 12,
            DST_MASK = 13,
            OUTPUT_SNMP = 14,
            IPV4_NEXT_HOP = 15,
            SRC_AS = 16,
            DST_AS = 17,
            BGP_IPV4_NEXT_HOP = 18,
            MUL_DST_PKTS = 19,
            MUL_DST_BYTES = 20 ,
            LAST_SWITCHED = 21 ,
            FIRST_SWITCHED = 22 ,
            OUT_BYTES = 23,
            OUT_PKTS = 24 ,
            IPV6_SRC_ADDR = 27 ,
            IPV6_DST_ADDR = 28 ,
            IPV6_SRC_MASK = 29,
            IPV6_DST_MASK = 30,
            IPV6_FLOW_LABEL = 31,
            ICMP_TYPE = 32,
            MUL_IGMP_TYPE = 33,
            SAMPLING_INTERVAL = 34,
            SAMPLING_ALGORITHM = 35,
            FLOW_ACTIVE_TIMEOUT = 36,
            FLOW_INACTIVE_TIMEOUT = 37,
            ENGINE_TYPE = 38,
            ENGINE_ID = 39,
            TOTAL_BYTES_EXP = 40,
            TOTAL_PKTS_EXP = 41,
            TOTAL_FLOWS_EXP = 42,
            MPLS_TOP_LABEL_TYPE = 46,
            MPLS_TOP_LABEL_IP_ADDR = 47,
            FLOW_SAMPLER_ID = 48,
            FLOW_SAMPLER_MODE = 49,
            FLOW_SAMPLER_RANDOM_INTERVAL = 50,
            DST_TOS = 55,
            SRC_MAC = 56,
            DST_MAC = 57,
            SRC_VLAN = 58,
            DST_VLAN = 59,
            IP_PROTOCOL_VERSION = 60,
            DIRECTION = 61,
            IPV6_NEXT_HOP = 62,
            BGP_IPV6_NEXT_HOP = 63,
            IPV6_OPTION_HEADERS = 64,
            MPLS_LABEL_1 = 70,
            MPLS_LABEL_2 = 71,
            MPLS_LABEL_3 = 72,
            MPLS_LABEL_4 = 73,
            MPLS_LABEL_5 = 74,
            MPLS_LABEL_6 = 75,
            MPLS_LABEL_7 = 76,
            MPLS_LABEL_8 = 77,
            MPLS_LABEL_9 = 78,
            MPLS_LABEL_10 = 79,
        };

        // Data/Option Template
        class DO_Template{
        private:
            struct field{
                uint16_t type = 0;
                uint16_t length = 0;
            };
            uint16_t id = 0;
            uint16_t fieldcount = 0;
            uint16_t bitesize = 0;
            field *fields = nullptr;

        public:
            DO_Template() = delete;

            DO_Template(u_char const * const buf){
                id = ntohs(*(uint16_t*)buf);

                fieldcount = ntohs(*(uint16_t*)(buf + sizeof(uint16_t)));

                fields = new field[fieldcount];

                for (uint16_t i = 0; i < (fieldcount * 2); i += 2){
                    fields[i].type = *(uint16_t*)(buf + sizeof(uint16_t) * (2 + i));
                    fields[i].length = *(uint16_t*)(buf + sizeof(uint16_t) * (3 + i));
                    bitesize += sizeof(uint16_t);
                }
            }
            ~DO_Template(){
                if (fields == nullptr){ return; } 
                delete fields;
                fields = nullptr;
            }

            uint16_t const& get_fieldcount() const { return fieldcount; }
            uint16_t const& get_templateID() const { return id; }
        };

        class DynamicFlowRecord{
        private:
            class Flow{};

        public:
        
        private:
            std::vector<int, Flow> flows;

        };

    public:
        NF9() = default;
        NF9(u_char const * const buff, uint16_t len){ parse_buff(buff, len); }

        void parse_buff(u_char const * const buff, uint16_t len){
            char b[len];
            memcpy(b, buff, len);
            head = *(header*)(b);
        }

    private:
        header head;
        static std::map<int, DO_Template> tmpls;
        std::vector<int, DynamicFlowRecord> flowsets;

    };

};