#include "sniffer.h"

#include <iostream>
#include <exception>
#include <pcap.h>
#include <functional>

void pc_sniffer::list_show(pcap_if_t *dev)
{
    std::cout << "---- " << dev->name << std::endl;
    if (dev->next)
        this->list_show(dev->next);
}

pc_sniffer::pc_sniffer()
{
    if (pcap_findalldevs(&interfaces, errbuf) != 0) // get a list of capture devices
    {
        throw std::runtime_error(errbuf);
    }
}

pc_sniffer::~pc_sniffer()
{
    if (interfaces != nullptr)
        pcap_freealldevs(interfaces); // free the list ponter form pcap_findalldevs
    if (handler != nullptr)
    {
        pcap_breakloop(handler);
        pcap_close(handler); // closes the files associated with p and deallocates resources
    }
}

void pc_sniffer::init_interface(const char *device, char const *filter_expression)
{
    bpf_u_int32 net, mask;
    if (pcap_lookupnet(device, &net, &mask, errbuf)) // find the IP network number and netmask for a device
    {
        throw std::runtime_error(errbuf);
    }

    if ((handler = pcap_open_live(device, snaplen, 0, to_ms, errbuf)) == NULL) // open a device for capturing
    {
        throw std::runtime_error(errbuf);
    }

    const char *ex = expr;
    if (filter_expression != nullptr)
        ex = filter_expression;

    if (pcap_compile(handler, &fp, ex, 0, net) < 0) // compile a filter expression
    {
        throw std::runtime_error(pcap_geterr(handler));
    }

    if (pcap_setfilter(handler, &fp) < 0)
    {
        throw std::runtime_error(pcap_geterr(handler));
    }
}

// handler function for pcap_loop & init_file
void got_(u_char *user, const struct pcap_pkthdr *h, const u_char *data)
{
    pc_sniffer::h_func(user, h->caplen, h->len, h->ts.tv_sec, h->ts.tv_usec, data);
}

void pc_sniffer::scan(int count)
{
    pcap_loop(handler, count, got_, NULL);
}

void pc_sniffer::init_file(char const *path)
{
    pcap_t *file_data = pcap_open_offline(path, errbuf);
    if (file_data == NULL)
    {
        throw std::runtime_error(errbuf);
    }
    pcap_pkthdr *header;
    const u_char *data;
    while (pcap_next_ex(file_data, &header, &data) > 0)
    {
        got_(NULL, header, data);
    }

    pcap_close(file_data);
}

void pc_sniffer::breakloop(){
    pcap_breakloop(handler);
}