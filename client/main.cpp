#include <iostream>
#include <thread>

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
    }
    return 0;
}
// /home/Nihill/Documents/out/pcap_exaples/release/pcapfiles/netflow_many_packets_dump.pcap
void handler(u_char *user, uint32_t cap, uint32_t len, __time_t tv_sec, __suseconds_t tv_usec, const u_char *data)
{
    if (cap != len)
        return;

    char *p = new char[len];
    copy(data, data + len, p);

    for (int i = 0; i < len; i++){
        if (isprint(data[i])){
            cout << data[i];
        }else{ cout << '.'; }
    }

    cout << "\n\n\n\n\n";

    delete p;
}