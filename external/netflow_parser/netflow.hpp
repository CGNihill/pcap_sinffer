#pragma once

#include <exception>
#include <stdexcept>
#include <cstdint>
#include <cstring>
#include <vector>
#include <map>
#include <netinet/in.h>

struct comon_netflow_header
{
    uint16_t version, count;

    constexpr void to_current_byte_order(){
            #if __BYTE_ORDER == __LITTLE_ENDIAN
            version = ntohs(version);
            count = ntohs(count);
            #endif
        }
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

        constexpr void to_current_byte_order(){
            #if __BYTE_ORDER == __LITTLE_ENDIAN
            comon.to_current_byte_order();
            sys_uptime = ntohl(sys_uptime);
            unix_secs = ntohl(unix_secs);
            unix_nsecs = ntohl(unix_nsecs);
            flow_sequence = ntohl(flow_sequence);
            sampling_interval.sample_rate = ntohs(sampling_interval.sample_rate);
            #endif
        }
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

        constexpr void to_current_byte_order(){
            #if __BYTE_ORDER == __LITTLE_ENDIAN
            srcaddr = ntohl(srcaddr);
            dstaddr = ntohl(dstaddr);
            nexthop = ntohl(nexthop);
            dPkts = ntohl(dPkts);
            dOctets = ntohl(dOctets);
            first = ntohl(first);
            last = ntohl(last);
            input = ntohs(input);
            output = ntohs(output);
            srcport = ntohs(srcport);
            dstport = ntohs(dstport);
            src_as = ntohs(src_as);
            dst_as = ntohs(dst_as);
            pad2 = ntohs(pad2);
            #endif
        }
    };

    /**
     * @param data -> the data packet after the netflow header
     * @param pack_len -> current length of data packet
     *
     * @brief
     * if the calculated size of DataFlowRecord_array is higher then data packet length,
     * this function will throw an length_error
     */
    std::vector<FlowRecord> parseFlow(Header &header, const unsigned char *data, const size_t pack_len)
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

        constexpr void to_current_byte_order(){
            #if __BYTE_ORDER == __LITTLE_ENDIAN
            comon.to_current_byte_order();
            sysUptime = ntohl(sysUptime);
            UnixSecs = ntohl(UnixSecs);
            SequenceNumber = ntohl(SequenceNumber);
            SID = ntohl(SID);
            #endif
        }
    };

    class NF9_Pack{
        private:
            header head;

            // frequently used structure used for : FlowSet_header, Field, DATA Template...
            struct Comon_str{
                uint16_t id, len;
                
                constexpr void to_current_byte_order(){
                #if __BYTE_ORDER == __LITTLE_ENDIAN
                id = ntohs(id);
                len = ntohs(len);
                #endif
                }
            };

            struct Option_header{
                uint16_t id, len;
                
                constexpr void to_current_byte_order(){
                #if __BYTE_ORDER == __LITTLE_ENDIAN
                id = ntohs(id);
                len = ntohs(len);
                #endif
                }
            };

            class Template{
            private:

                std::vector<Comon_str> fields;
                uint16_t id, count; 

            public:
                Template() = default;
                Template(u_char const * const template_buff, const size_t len){ from_buffer(template_buff, len); }

                void from_buffer(u_char const * const template_buff, const size_t len){

                    #if __BYTE_ORDER == __LITTLE_ENDIAN
                    id = ntohs(*(uint16_t*)template_buff);
                    count = ntohs(*(uint16_t*)(template_buff + sizeof(uint16_t)));
                    #endif
                    #if __BYTE_ORDER == __BIG_ENDIAN
                    id = *(uint16_t*)template_buff;
                    count = *(uint16_t*)(template_buff + sizeof(uint16_t));
                    #endif

                    if (len < (sizeof(uint16_t) * 2 + sizeof(Comon_str) * count)){
                        throw std::runtime_error("Template buffer length is insufficient.");
                    }

                    for(size_t i = 0; i < count; i++){
                        Comon_str field = *(Comon_str*)(template_buff + (sizeof(uint16_t) * 2 + sizeof(Comon_str) * i));

                        field.to_current_byte_order();

                        fields.push_back(field);
                    }
                }

                ~Template() = default;

            };

            class Options{
            private:

                std::vector<Comon_str> fields;
                uint16_t id, scope_len, length; 

            public:
                Options() = default;
                Options(u_char const * const options_buff, const size_t len){ from_buffer(options_buff, len); }

                void from_buffer(u_char const * const options_buff, const size_t len){

                    #if __BYTE_ORDER == __LITTLE_ENDIAN
                    id = ntohs(*(uint16_t*)options_buff);
                    scope_len = ntohs(*(uint16_t*)(options_buff + sizeof(uint16_t)));
                    length = ntohs(*(uint16_t*)(options_buff + sizeof(uint16_t) * 2));
                    #endif
                    #if __BYTE_ORDER == __BIG_ENDIAN
                    id = *(uint16_t*)options_buff;
                    scope_len = *(uint16_t*)(options_buff + sizeof(uint16_t));
                    length = *(uint16_t*)(options_buff + sizeof(uint16_t) * 2);
                    #endif

                    uint16_t count = scope_len + length;

                    if (len < (sizeof(uint16_t) * 2 + sizeof(Comon_str) * count)){
                        throw std::runtime_error("Template buffer length is insufficient.");
                    }

                    for(size_t i = 0; i < count; i++){
                        Comon_str field = *(Comon_str*)(options_buff + (sizeof(uint16_t) * 2 + sizeof(Comon_str) * i));
                        
                        field.to_current_byte_order();

                        fields.push_back(field);
                    }
                }

                ~Options() = default;

            };

            static std::map<uint16_t, Template> tmpls; // all templates
            static std::map<uint16_t, Options> optns;  // all options

        public:
            NF9_Pack() = default;

            void from_buffer(u_char const * const buffer, size_t length){
                head = *(header*)buffer;

                head.to_current_byte_order();

                size_t flow_buf_index = sizeof(header);
                for(size_t i = 0; flow_buf_index < length; i++){
                    Comon_str flow_hdr = *(Comon_str*)(buffer + flow_buf_index);

                    flow_hdr.to_current_byte_order();

                    if ((sizeof(header) + flow_buf_index + flow_hdr.len) > length){
                        throw std::runtime_error("Buffer length is insufficient for the next flowset.");
                    }

                    flow_buf_index += sizeof(Comon_str);
                    uint16_t current_base_index = flow_buf_index;

                    u_char *temp_buff = nullptr; 
                    if (flow_hdr.id == 0){
                        for(;flow_buf_index < (current_base_index + flow_hdr.len);){
                            //get template id and template count
                            Comon_str template_head = *(Comon_str*)(buffer + flow_buf_index);
                            template_head.to_current_byte_order();

                            // create a buffer for Template constructor
                            size_t s = (sizeof(Comon_str) + template_head.len * sizeof(uint16_t) * 2);

                            if (s > (current_base_index + flow_hdr.len)){
                                throw std::runtime_error("FlowSet buffer length is insufficient for the next template.");
                            }

                            memcpy(temp_buff, (buffer + flow_buf_index), s);

                            tmpls[template_head.id] = Template(temp_buff, s);

                            flow_buf_index += s;
                        }
                    }
                    if (flow_hdr.id == 0){
                        for(;flow_buf_index < (current_base_index + flow_hdr.len);){
                            //get template id and template count
                            Comon_str template_head = *(Comon_str*)(buffer + flow_buf_index);
                            template_head.to_current_byte_order();

                            // create a buffer for Template constructor
                            size_t s = (sizeof(Comon_str) + template_head.len * sizeof(uint16_t) * 2);

                            if (s > (current_base_index + flow_hdr.len)){
                                throw std::runtime_error("FlowSet buffer length is insufficient for the next template.");
                            }

                            memcpy(temp_buff, (buffer + flow_buf_index), s);

                            tmpls[template_head.id] = Template(temp_buff, s);

                            flow_buf_index += s;
                        }
                    }

                    // flow_buf_index += flow_hdr.len;
                }
            }
    };
};