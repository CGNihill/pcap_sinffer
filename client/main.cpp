#include <iostream>
#include <thread>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "../external/sniffer/sniffer.h"
#include "../external/protobuff/gen/pack.pb.h"

using namespace std;

void handler(u_char *user, uint32_t cap, uint32_t len, __time_t tv_sec, __suseconds_t tv_usec, const u_char *data);

int main()
{
    pc_sniffer pc;
    pc.h_func = handler;
    cout << "1) init from file\n2) init from interface\n-";
    short o;
    cin >> o;
    string I_F_name;
    if (o == 1){
        cout << "type file path and name\n-";
        cin >> I_F_name;

        // pc.init_file(I_F_name.c_str());
        pc.init_file("/home/Nihill/Documents/out/pcap_exaples/release/pcapfiles/netflow_many_packets_dump.pcap");
        
    }else if (o == 2){
        pc.show_interfaces();
        cout << '-';
        cin >> I_F_name;
        pc.init_interface(I_F_name.c_str());
        cout << "1) break loop\n";

        thread th([&](){pc.scan(-1);});

        while(1){
            cout << '-';
            cin >> o;
            if (o == 1){ pc.breakloop(); break; }
        }

        th.join();
    }
    return 0;
}

void handler(u_char *user, uint32_t cap, uint32_t len, __time_t tv_sec, __suseconds_t tv_usec, const u_char *data)
{
    if (cap != len)
        return;

    char *p = new char[len];
    // copy(data, data + len, p);
    for (uint32_t i = 0; i < len; i++){ p[i] = data[i]; }
/*
    for (int i = 0; i < len; i++){
        if (isprint(data[i])){
            cout << data[i];
        }else{ cout << '.'; }
    }

    cout << "\n\n\n\n\n";
*/

    uint16_t data_index = 0;
    pack pa;
    pa.set_time(tv_usec);
    pa.set_framesize(len);

    ether_header eth = *(ether_header*)(p + data_index);
    data_index += ETH_HLEN;

    pa.set_s_mac(ether_ntoa((ether_addr*)eth.ether_shost));
    pa.set_d_mac(ether_ntoa((ether_addr*)eth.ether_dhost));

    uint8_t ip_tos;
    switch (ntohs(eth.ether_type))
    {
    case ETHERTYPE_IP:
        {
            ip iph = *(ip*)(p + data_index);
            data_index += sizeof(iph);
            
            pa.set_ipv(iph.ip_v);

            char ipa[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &iph.ip_src, ipa, INET_ADDRSTRLEN);
            pa.set_s_ip(ipa);
            inet_ntop(AF_INET, &iph.ip_dst, ipa, INET_ADDRSTRLEN);
            pa.set_d_ip(ipa);

            ip_tos = iph.ip_tos;
        }
        break;

    case ETHERTYPE_IPV6:
        {
            ip6_hdr iph = *(ip6_hdr*)(p + data_index);
            data_index += sizeof(iph);

            pa.set_ipv(iph.ip6_ctlun.ip6_un2_vfc);

            char ipa[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &iph.ip6_src, ipa, INET6_ADDRSTRLEN);
            pa.set_s_ip(ipa);
            inet_ntop(AF_INET6, &iph.ip6_dst, ipa, INET6_ADDRSTRLEN);
            pa.set_d_ip(ipa);

            ip_tos = iph.ip6_ctlun.ip6_un1.ip6_un1_nxt;
        }
        break;
    
    default:
        {
            pa.set_ipv(0);
            pa.set_s_ip("UNDEFINED");
            pa.set_d_ip("UNDEFINED");
        }
        break;
    }

    switch (ip_tos)
    {
    case IPPROTO_TCP:
        {
            tcphdr prth = *(tcphdr*)(p + data_index);
            data_index += sizeof(prth);

            pa.set_t_proto("TCP");

            pa.set_s_port(prth.th_sport);
            pa.set_d_port(prth.th_dport);
        }
        break;
    case IPPROTO_UDP:
        {
            udphdr prth = *(udphdr*)(p + data_index);
            data_index += sizeof(prth);

            pa.set_t_proto("UDP");

            pa.set_s_port(prth.uh_sport);
            pa.set_d_port(prth.uh_dport);
        }
        break;
    
    default:
        {
            pa.set_t_proto("UNDEFINED");

            pa.set_s_port(0);
            pa.set_d_port(0);
        }
        break;
    }

    cout << pa.framesize() << endl;
    cout << pa.s_mac() << endl;
    cout << pa.d_mac() << endl;
    cout << pa.ipv() << endl;
    cout << pa.s_ip() << endl;
    cout << pa.d_ip() << endl;
    cout << pa.t_proto() << endl;
    cout << pa.s_port() << endl;
    cout << pa.d_port() << endl;
    cout << "\n\n";
    exit(-1);

    delete p;
}