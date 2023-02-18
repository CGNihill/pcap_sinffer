#pragma once

/*
    libpcap can work in multi-thread state ```check the docs```
    but is recomended to use only pc_sniffer::scan(int) in other thread ```i checked the source code of pcap_loop() and this function is thread-safe```
    + use threads for pc_sniffer::scan(int) only if the handler function code is thread-safe
*/

#include <functional>
#include <pcap.h>

class pc_sniffer
{
private:
    static const int snaplen = 1518, to_ms = 1000;   // pcap_open_live max_pack_length dellay
    static constexpr char const *expr = "ip or ip6"; // pcap_compile

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t *interfaces = nullptr;
    pcap_t *handler = nullptr;
    bpf_program fp;

    void list_show(pcap_if_t *dev);

public:
    pc_sniffer();

    ~pc_sniffer();

    // documentation for filter_expression : https://www.tcpdump.org/manpages/pcap-filter.7.html
    // if use default value will set filter "ip or ip6"
    void init_interface(const char *device, const char *filter_expression = nullptr);

    void scan(int count);

    void init_file(char const *path);

    // satic handler function called in pcap_loop from pcap_handler
    inline static std::function<void(u_char *user, uint32_t cap, uint32_t len, __time_t tv_sec, __suseconds_t tv_usec, const u_char *data)> h_func;
};
