#include <iostream>
#include <functional>

#include "../external/sniffer/sniffer.h"
#include "../external/protobuff/gen/pack.pb.h"

using namespace std;

void handler(u_char *user, uint32_t cap, uint32_t len, __time_t tv_sec, __suseconds_t tv_usec, const u_char *data);

int main()
{
    pc_sniffer *pc = new pc_sniffer;
    pc->init_interface("wlo1");
    pc->h_func = handler;
    delete pc;
    cout << "deleted" << endl;
    int b;
    cin >> b;
    return 0;
}

void handler(u_char *user, uint32_t cap, uint32_t len, __time_t tv_sec, __suseconds_t tv_usec, const u_char *data)
{
    if (cap != len)
        return;

    char *p = new char[len];
    copy(data, data + len, p);

    delete p;
}