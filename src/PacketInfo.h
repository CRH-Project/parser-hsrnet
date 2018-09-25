#ifndef _PACKETINFO_HH_
#define _PACKETINFO_HH_

#include "headers.h"

#define ETH_TCPDUMP 0
#define ETH_TSHARK  1

#define ETH_TSHARK_HEADER_LEN 16

typedef union Transport_t
{
    Tcp_t tcp;
    Udp_t udp;
} Transport;

class PacketInfo
{
    private:
        bool _isTcp(){return ip.protocol == 6;};
        bool _isUdp(){return ip.protocol == 17;}

    public:
        size_t pkt_number;
        struct timeval time;
        size_t payload;
        Ethernet_t eth;
        Ipv4_t ip;
        Transport_t trans;
        enum TransMode { TCP = 0, UDP = 1} mode;
        uint32_t options[10];
    public:
        PacketInfo() = default;
        PacketInfo(const u_char *pkt, const struct timeval &v);
        PacketInfo(PacketInfo &&) = default;
        PacketInfo(const PacketInfo &) = default;

        inline void setNumber(size_t num){this->pkt_number = num;}
        inline bool operator<(const PacketInfo &r) const
        {
            return pkt_number < r.pkt_number;
        }
        //PacketInfo(Ethernet_t *, Ipv4_t *, Transport_t *);

};


/* reserved for fast memory copy */
void *memcpy(void *dest, const void *src, size_t n);

/* value should choose between ETH_TCPDUMP and
 * ETH_TSHARK
 */
void setEthernetType(int TYPE);
#endif
