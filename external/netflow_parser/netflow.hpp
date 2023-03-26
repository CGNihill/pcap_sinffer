#pragma once

#include <exception>
#include <stdexcept>
#include <cstdint>
#include <cstring>
#include <vector>
#include <map>
#include <netinet/in.h>
#include <array>

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

    class NF9_10_Pack{
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
            uint16_t id, s_len, len;
            
            constexpr void to_current_byte_order(){
            #if __BYTE_ORDER == __LITTLE_ENDIAN
            id = ntohs(id);
            s_len = ntohs(s_len);
            len = ntohs(len);
            #endif
            }
        };

        class Template{
        private:

            std::vector<Comon_str> fields;
            uint16_t id, count; 
            size_t s = 0;

        public:
            Template() = default;
            Template(u_char const * const flowset_buff, std::map<uint16_t, Template>& tmpl){ from_buffer(flowset_buff, tmpl); }

            void from_buffer(u_char const * const flowset_buff, std::map<uint16_t, Template>& tmpl){
                Comon_str flowset_header = *(Comon_str*)(flowset_buff);
                flowset_header.to_current_byte_order();

                size_t buffer_index = sizeof(Comon_str);

                // check if is data or option template
                Comon_str template_data;
                switch(flowset_header.id){
                    case 0:{
                        template_data = *(Comon_str*)(flowset_buff + buffer_index);
                        buffer_index += sizeof(Comon_str);
                        }
                        break;

                    case 1:
                        {
                            Option_header oph = *(Option_header*)(flowset_buff + buffer_index);
                            buffer_index += sizeof(Option_header);

                            template_data.id = oph.id;
                            template_data.len = (oph.len + oph.s_len)/sizeof(Comon_str);
                        }
                        break;

                    default:
                        throw std::logic_error("Error while check template type\n(0/1) for (DATA/OPTION) Template\nCurrent : ");
                        break;
                }
                
                template_data.to_current_byte_order();

                for(size_t i = 0; i < template_data.len; i++){

                    if (flowset_header.len < buffer_index + (template_data.len * sizeof(Comon_str))){
                        throw std::runtime_error("FlowSet buffer length is insufficient for the next template.");
                    }

                    fields.push_back(*(Comon_str*)(flowset_buff + buffer_index));
                    fields[fields.size() - 1].to_current_byte_order();
                    s += fields[fields.size() - 1].len;
                    buffer_index += sizeof(Comon_str);
                }

                tmpl[template_data.id] = *this;

                if (flowset_header.len == buffer_index + template_data.len){
                    return;
                }

                // if we have more templates / create new flowset

                buffer_index -= sizeof(Comon_str);

                size_t s = (flowset_header.len - buffer_index);
                u_char *new_buff = new u_char[s];

                flowset_header.to_current_byte_order();

                memcpy(new_buff, &flowset_header, sizeof(Comon_str));
                memcpy(new_buff + sizeof(Comon_str), flowset_buff + sizeof(Comon_str) + buffer_index, s);

                Template(new_buff, tmpl);
/*
                #if __BYTE_ORDER == __LITTLE_ENDIAN
                id = ntohs(*(uint16_t*)flowset_buff);
                count = ntohs(*(uint16_t*)(flowset_buff + sizeof(uint16_t)));
                #endif
                #if __BYTE_ORDER == __BIG_ENDIAN
                id = *(uint16_t*)flowset_buff;
                count = *(uint16_t*)(flowset_buff + sizeof(uint16_t));
                #endif

                if (len < (sizeof(uint16_t) * 2 + sizeof(Comon_str) * count)){
                    throw std::runtime_error("Template buffer length is insufficient.");
                }

                for(size_t i = 0; i < count; i++){
                    Comon_str field = *(Comon_str*)(flowset_buff + (sizeof(uint16_t) * 2 + sizeof(Comon_str) * i));

                    field.to_current_byte_order();

                    fields.push_back(field);
                }
                */
            }

            const std::vector<Comon_str>& get_template_fields() const { return fields; }

            size_t data_size() const { return s; }

            ~Template() = default;

        };

/*
        class Options_T{
        private:

            std::vector<Comon_str> fields;
            uint16_t id, scope_len, length; 

        public:
            Options_T() = default;
            Options_T(u_char const * const options_buff, const size_t len){ from_buffer(options_buff, len); }

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

            ~Options_T() = default;

        };
*/
        
        class Data{
        private:
            struct Flow{
                uint16_t type, size;
                u_char* buff;

                constexpr void to_current_byte_order(){
                #if __BYTE_ORDER == __LITTLE_ENDIAN
                    type = ntohs(type);
                    size = ntohs(size);
                #endif
                }
            };

            std::vector<std::vector<Flow>> flows;

            Template t;

        public:
            Data() = default;
            Data(u_char const * const flowset_buff, Template& tmpl){ from_buffer(flowset_buff, tmpl); }

            void from_buffer(u_char const * const flowset_buff, Template& tmpl){
                Comon_str flow_hdr = *(Comon_str*)(flowset_buff);
                flow_hdr.to_current_byte_order();

                size_t buff_index = sizeof(Comon_str);

                const std::vector<Comon_str> cur_field = tmpl.get_template_fields();

                while(1){
                    if((tmpl.data_size() + buff_index) > (flow_hdr.len - sizeof(uint32_t))){
                        throw std::runtime_error("error while reading data-flowset, insufficent flowset size");
                    }

                    std::vector<Flow> cur_flow;

                    for(size_t i = 0; i < cur_field.size(); i++){
                        Flow f;
                        f.type = cur_field[i].id;
                        f.size = cur_field[i].len;

                        f.buff = new u_char[f.size];
                        memcpy(f.buff, (flowset_buff + buff_index), f.size);

                        buff_index += f.size;
                        cur_flow.push_back(f);
                    }

                    flows.push_back(cur_flow);
                }

                t = tmpl;
            }
        };

        // map<version, map<templateID, Template>>
        static std::map<uint8_t, std::map<uint16_t, Template>> tmpls; // all templates

        // std::vector<std::pair<flowset id, Data flow>>
        std::vector<std::pair<uint16_t, Data>> dataflows; // all readed flows by template id
        std::vector<u_char*> no_tmpl; // data without a template

    public:
        NF9_10_Pack() = default;

        NF9_10_Pack(u_char const * const buffer, size_t length) { from_buffer(buffer, length); }

        void from_buffer(u_char const * const buffer, size_t length){
            head = *(header*)buffer;

            head.to_current_byte_order();

            // additional check netflow version
            switch (head.comon.version)
            {
            case 9:
            case 10:
                // good netflow version
                break;

            default:
                throw std::runtime_error("Unexpected netflow version");
                break;
            }

            size_t flow_buf_index = sizeof(header);

            // loop for differnt flowsets
            for(size_t i = 0; flow_buf_index < length; i++){
                Comon_str flow_hdr = *(Comon_str*)(buffer + flow_buf_index);

                flow_hdr.to_current_byte_order();

                if ((sizeof(header) + flow_buf_index + flow_hdr.len) > length){
                    throw std::runtime_error("Buffer length is insufficient for the next flowset.");
                }

                flow_buf_index += sizeof(Comon_str);
                uint16_t current_base_index = flow_buf_index;

                // loops for different Template, Option or Data in the same flowset
                u_char *temp_buff = nullptr; 

                // --- Templates / Options
                if (flow_hdr.id == 0 || flow_hdr.id == 1){
                    Template((buffer + flow_buf_index), tmpls[head.comon.version]);
                    tmpls[head.comon.version];
                    for(;flow_buf_index < (current_base_index + flow_hdr.len);){

                        //get template id and template count
                        Comon_str template_head = *(Comon_str*)(buffer + flow_buf_index);
                        template_head.to_current_byte_order();

                        // create a buffer for Template constructor

                        if (template_head.len > flow_hdr.len){
                            throw std::runtime_error("FlowSet buffer length is insufficient for the next template.");
                        }

                        temp_buff = new u_char[template_head.len];
                        memcpy(temp_buff, (buffer + flow_buf_index), template_head.len);

                        tmpls[head.comon.version][template_head.id] = Template(temp_buff, tmpls[head.comon.version]);

                        flow_buf_index += template_head.len;
                    }
                }
                // --- Data Flow
                else{
                    uint32_t padding = *(uint32_t*)(buffer + (flow_buf_index + flow_hdr.len - sizeof(uint32_t)));
                    if (padding != 0){
                        throw std::runtime_error("data-flowset does not match the patern (padding != 0)");
                    }

                    if (tmpls.contains(head.comon.version) && tmpls[head.comon.version].contains(flow_hdr.id)){
                        dataflows.push_back(std::make_pair(flow_hdr.id, Data((buffer + flow_buf_index), tmpls[head.comon.version][flow_hdr.id])));
                    }
                    else{
                        unreaded.push_back(new u_char[flow_hdr.len]);
                        memcpy(unreaded[unreaded.size() - 1], buffer + flow_buf_index, flow_hdr.len);
                    }
                }

                flow_buf_index += flow_hdr.len;
            }
        }

        ~NF9_10_Pack(){
            for (size_t i = 0; i < unreaded.size(); i++){
                delete unreaded[i];
                unreaded[i] = nullptr;   
            }
        }
        
    private:
        std::vector<u_char*> unreaded;
    };
};