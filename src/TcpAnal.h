#ifndef _TCPANAL_HH_
#define _TCPANAL_HH_

#include <map>
#include <set>
#include "PacketInfo.h"

struct PktRange;
class Pipe;

struct Addr_pair;
using CS_pair = std::pair<Addr_pair, Addr_pair>;
class Session;

struct PktRange
{
    size_t start,end;
    struct timeval time;
    bool operator<(const PktRange &p) const
    {
        if(start == p.start) return end<p.end;
        return start<p.start;
    }
};

class Pipe
{
    private:
        size_t bif = 0;
        std::set<PktRange> acked, inflight, window;

    public:
        /* state infomation
         * high        --->             low
         * 0    0   0   0   0   0   0   0
         *          A   A   An  S   S   sn
         */
        static constexpr int NORMAL = 0;
        static constexpr int LOST_SEG = 3;
        static constexpr int RETRANS = 5;
        static constexpr int SEND_MASK = 7;

        static constexpr int ACK_NORMAL = 0;
        static constexpr int DUP_ACK = 24;
        static constexpr int ACK_MASK = 0x28;
    public:
        /**
         * METHOD: insertPacket
         *
         * @param   pr : the packet to insert
         * @returns a status code indicating the status
         *          including: normal, lost_seg, retrans
         */
        int insertPacket(const PktRange &pr);

        /**
         * METHOD: insertAck
         *
         * TODO: Deal with SACK!!
         *
         * @param   ack : the ack packet
         * @returns a status code indicating the status
         *          including: normal, dup_ack
         */
        int insertAck(const PktRange &ack);

        double getAckRTT(const PktRange &ack);
        size_t getBIF();


};

struct Addr_pair
{
    uint32_t ip;
    uint16_t port;
    bool operator<(const Addr_pair &ap) const
    {
        if(ip == ap.ip) return port < ap.port;
        return ip<ap.ip;
    }
    bool operator==(const Addr_pair &ap) const
    {
        return ip == ap.ip && port == ap.port;
    }
};

class Session
{
    private:
        CS_pair id;
        Pipe c2s;       // first SYN is c2s 

    public:
        void start();   // SYN
        void end();     // RST or FIN

        Pipe & getPipe();
    public:
        bool operator<(const Session &s) const
        {
            return id<s.id;
        }
};

struct RttElement
{
    static constexpr int NORMAL = 0;
    static constexpr int RETRANS = 1;
    static constexpr int ACKED = 2;
    CS_pair id;
    uint32_t seq;   //here is network endian
    int state;
    struct timeval timestamp;
    bool operator<(const RttElement &r) const
    {
        if(this->id == r.id)
            return this->seq < r.seq;
        return id < r.id;
    }
    RttElement(const PacketInfo &pkt, bool inverse = false);
};

class RttCaller
{
    private:
        std::set<RttElement> table;
    public:
        std::string insertPacket(const PacketInfo &pkt);
        std::string insertAck(const PacketInfo &pkt);
        std::pair<std::string, std::string>
            insertDual(const PacketInfo &pkt);
};



/* FUNCTION HELPERS */

CS_pair getPairFromPkt(const PacketInfo &pkt);
CS_pair getInversedPairFromPkt(const PacketInfo &pkt);
bool operator<(const CS_pair &l, const CS_pair &r);
#endif
