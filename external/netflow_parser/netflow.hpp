#pragma once

#include <stdexcept>
#include <cstdint>
#include <vector>
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

namespace netflow_v9
{
    struct comon_field{
        const char* data;
        int len;
    }
};