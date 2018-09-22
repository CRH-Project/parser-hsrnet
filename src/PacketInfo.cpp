#include <stdexcept>
#include "PacketInfo.h"

static int _eth_type = 0;

static int getEthernetType(){return _eth_type;}

PacketInfo::PacketInfo(const u_char *pkt, const struct timeval &v)
    :time(v) 
{
    memset(this->options, 0, sizeof(this->options));
    auto eth_conf = getEthernetType();
    if(eth_conf == ETH_TCPDUMP)
    {
        memcpy(&eth, pkt, sizeof(Ethernet_t));
        pkt += sizeof(Ethernet_t);
    }
    else if (eth_conf == ETH_TSHARK)
    {
        memcpy(&eth.type, pkt + 14, sizeof eth.type);
        pkt += ETH_TSHARK_HEADER_LEN;
    }
    if(eth.type != IPV4_T)
        throw std::runtime_error("Invalid packet type! Expect IPV4!");

    memcpy(&ip, pkt, sizeof(Ipv4_t));
    pkt += sizeof(Ipv4_t);
    auto isT = _isTcp(), isU = _isUdp();

    if(isT)
    {
        memcpy(&trans.tcp, pkt, sizeof(Tcp_t));
        mode = TCP;

        pkt += sizeof(Tcp_t);
        int size = trans.tcp.doff * 4;
        int addi = size - 20;
        if(addi) memcpy(options, pkt, 
                std::min((uint64_t)addi, sizeof options));
        this->payload = ntohs(ip.tot_len) - ip.ihl * 4 - trans.tcp.doff * 4;
    }
    else if (isU)
    {
        memcpy(&trans.udp, pkt, sizeof(Udp_t));
        mode = UDP;

        this->payload = ntohs(ip.tot_len) - ip.ihl * 4 - sizeof(Udp_t);
    }
    else 
        throw std::runtime_error("Invalid packet type! Expect TCP or UDP!");


}

void setEthernetType(int type)
{
    _eth_type = type;
}
