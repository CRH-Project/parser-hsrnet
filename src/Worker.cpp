#include <sys/socket.h>
#include <arpa/inet.h>

#include "Worker.h"
#include "utils.h"
#include "TcpAnal.h"

using Mode = PacketInfo::TransMode;

#define ISHTTP(port) ((port) == 80 || (port) == 8080)

#define _MOVE(EXP) std::move(EXP)
#define N2H16(i) ntohs(i)
#define N2H32(i) ntohl(i)
#define N2H8(i)  (i)

#define OUT_SRCIP(pkt) _MOVE(nip2a(pkt.ip.srcip))
#define OUT_DSTIP(pkt) _MOVE(nip2a(pkt.ip.dstip))
#define OUT_SRCPORT(pkt) (N2H16(pkt.trans.tcp.srcport))
#define OUT_DSTPORT(pkt) (N2H16(pkt.trans.udp.dstport))
#define OUT_PROTOCOL(pkt) _MOVE(getProtocol(pkt))
#define OUT_TCP_FIELD_LEN(pkt, field, len)              \
    (pkt.mode == Mode::TCP ?                            \
        std::to_string(N2H##len(pkt.trans.tcp.field))   \
        : "")                                           \

#define OUT_TCP_HDRLEN(pkt)             \
    (pkt.mode == Mode::TCP ?                            \
        std::to_string(4 * N2H8(pkt.trans.tcp.doff))    \
        : "")                                           \

#define OUT_MPTCP_OPT(pkt) _MOVE(getMPTCP(pkt))
#define OUT_PAYLOAD_LEN(pkt) (pkt.payload)


#define D delimeter

std::vector<std::string> Worker::header
{
    "number", "time", "srcip", "dstip", "protocol", 
    "srcport", "dstport", "ack-seq", "seq",
//    "is_syn", "is_ack", "is_fin", "is_rst", "mptcp_opt",
    "window_size", "header_len", "payload_len",
    "ack_which",
    "ack_rtt", "retransmission"//, "TSval", "TSecr"//,"lost_segment"
    //"fast_retransmission", "spurious_retransmission", "BIF"
};

inline static std::string nip2a(uint32_t nip)
{
    struct in_addr addr;
    addr.s_addr = nip;
    return std::string(inet_ntoa(addr));
}

inline static std::string getProtocol(const PacketInfo &pkt)
{
    auto dp = OUT_DSTPORT(pkt), sp = OUT_SRCPORT(pkt);
    if(pkt.mode == PacketInfo::TCP)
    {

        if(ISHTTP(dp) || ISHTTP(sp))
            return "HTTP";
        if(dp == 443 || sp == 443)
            return "SSL";
        if( dp == 22 || sp == 22)
            return "SSH";
        return "TCP";
    }
    else //UDP
    {
        if(dp == 53 || sp == 53)
            return "DNS";
        return "UDP";
    }
}

inline static std::string getMPTCP(const PacketInfo &pkt)
{
    if(pkt.mode != PacketInfo::TransMode::TCP)
        return "0";
    if(pkt.options[0] == 30)
        return "1";
    else return "0";
}


void Worker::Start()
{
    RttCaller rtt_caller;
    if(stopped)
        throw std::runtime_error("Try to use a stopped Worker!");

    while(buffer->isRunning())
    {
        ++pkt_cnt;
        auto newpkt = std::move(buffer->next());
        newpkt.setNumber(pkt_cnt);
        buffered_pkts.emplace(newpkt);

        std::string retrans;
        std::pair<size_t, double> ack_rtt;
        if(newpkt.mode == PacketInfo::TransMode::TCP)
        {
            ack_rtt = rtt_caller.insertAck(newpkt);
            retrans = rtt_caller.insertPacket(newpkt);
        }

        if(ack_rtt.first != 0ull)
        {
            rtt_buf[ack_rtt.first].ack_which = newpkt.pkt_number;
            rtt_buf[ack_rtt.first].rtt = ack_rtt.second;
        }
        rtt_buf[newpkt.pkt_number].retrans = retrans;

        if(buffered_pkts.size() < Worker::BUFFERED_SIZE)
            continue;

        auto pkt {std::move(*(buffered_pkts.begin()))};
        
        fout<<pkt.pkt_number<<D
            <<pkt.time.tv_sec<<D
            <<OUT_SRCIP(pkt)<<D<<OUT_DSTIP(pkt)<<D
            <<OUT_PROTOCOL(pkt)<<D
            <<OUT_SRCPORT(pkt)<<D<<OUT_DSTPORT(pkt)<<D
            <<OUT_TCP_FIELD_LEN(pkt, ackseq, 32)<<D
            <<OUT_TCP_FIELD_LEN(pkt, seq, 32)<<D
            <<OUT_TCP_FIELD_LEN(pkt, wndsize, 16)<<D
            <<OUT_TCP_HDRLEN(pkt)<<D
            <<OUT_PAYLOAD_LEN(pkt)<<D
            <<rtt_buf[pkt.pkt_number]<<D
            <<std::endl;

        buffered_pkts.erase(buffered_pkts.begin());
        rtt_buf.erase(rtt_buf.find(pkt.pkt_number));
        //rtt_caller.removePacket(pkt);
    }

    for(auto & pkt : buffered_pkts)
    {
        fout<<pkt.pkt_number<<D
            <<pkt.time.tv_sec<<D
            <<OUT_SRCIP(pkt)<<D<<OUT_DSTIP(pkt)<<D
            <<OUT_PROTOCOL(pkt)<<D
            <<OUT_SRCPORT(pkt)<<D<<OUT_DSTPORT(pkt)<<D
            <<OUT_TCP_FIELD_LEN(pkt, ackseq, 32)<<D
            <<OUT_TCP_FIELD_LEN(pkt, seq, 32)<<D
            <<OUT_TCP_FIELD_LEN(pkt, wndsize, 16)<<D
            <<OUT_TCP_HDRLEN(pkt)<<D
            <<OUT_PAYLOAD_LEN(pkt)<<D
            <<rtt_buf[pkt.pkt_number]<<D
            <<std::endl;
    }
}
