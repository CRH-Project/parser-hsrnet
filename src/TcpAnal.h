#ifndef _TCPANAL_HH_
#define _TCPANAL_HH_

#include <map>
#include <set>
#include "PacketInfo.h"

/* defined but not actually used */
struct PktRange;
class Pipe;
class Session;

/* used class */
struct Addr_pair;
using CS_pair = std::pair<Addr_pair, Addr_pair>;
struct RttElement;
struct RttElementTS;
class RttCaller;
class RttCallerTS;


/* helpers */
struct TCPOption;
class TCPOptionWalker;


/* definition and declarations */

struct PktRange
{
    size_t start,end;
    struct timeval time;
    bool operator<(const PktRange &p) const;
};


struct Addr_pair
{
    uint32_t ip;
    uint16_t port;
    bool operator<(const Addr_pair &ap) const;
    bool operator==(const Addr_pair &ap) const;
};


struct RttElement
{
    static constexpr int NORMAL = 0;
    static constexpr int RETRANS = 1;
    static constexpr int ACKED = 2;
    int number;
    CS_pair id;
    uint32_t seq;   //here is network endian
    uint32_t ack_seq;
    uint32_t tsv;
    struct timeval timestamp;

    bool operator<(const RttElement &r) const; // in TcpAnal.cpp
    RttElement(const PacketInfo &pkt, bool inverse = false); // in Rttcal.cpp
    inline void setNumber(int number){this->number = number;}
};

struct RttElementTS
{
    CS_pair id;
    struct timeval timestamp;
    int tsval;
    int tsecr;
    bool operator<(const RttElementTS &r) const;
    RttElementTS(const PacketInfo &pkt, bool inverse = false);
};

class RttCaller
{
    private:
        struct RetransCMP
        {
            bool operator()(const RttElement & l, const RttElement & r)
            {
                if(l.id == r.id)
                {
                    if(l.seq == r.seq)
                        return l.ack_seq < r.ack_seq;
                    return l.seq < r.seq;
                }
                return l.id < r.id;
            }
        };

    private:
        //std::multiset<RttElement> table;
        std::set<RttElement> table;
        std::set<RttElement, RetransCMP> rtable;
    public:
        std::string insertPacket(const PacketInfo &pkt, const RttElement *hint = nullptr);
        std::pair<size_t, double> insertAck(const PacketInfo &pkt, const RttElement *hint = nullptr);
        [[deprecated]]
        std::pair<std::string, std::string>
            insertDual(const PacketInfo &pkt);
        void removePacket(const PacketInfo &pkt, const RttElement *hint = nullptr);

};

class RttCallerTS
{
    private:
        std::set<RttElementTS> table;
    public:
        std::string insertPacket(const PacketInfo &pkt);
        std::string insertAck(const PacketInfo &pkt);
};


/* HELPER CLASS */
struct TCPOption
{
    enum Type 
    {
        END_OF_LIST = 0,
        NO_OPERATION = 1,
        MAX_SEG_SIZE = 2,
        SACK = 5,
        TIMESTAMP = 8
    };

    unsigned char type;
    unsigned char len;
    unsigned char data[];
};

#define TCPOPT_EOL 0
#define TCPOPT_NOP 1

class TCPOptionWalker{
    protected:
        char* current;
        char* ceiling;
    public:
        static const int TCP_OPTION_OFFSET = 20;

        void init(const uint32_t *tcpopt)
        {
            current = (char*)tcpopt;
            ceiling = (char*)tcpopt + 40;
        }

        TCPOptionWalker(const uint32_t *tcpopt)
        {
            init(tcpopt);
        }

        TCPOptionWalker() {}

        inline TCPOption* next()
        {
            if (current == 0)
                throw std::runtime_error("invalid TCP option");
            else if(current >= ceiling)
                return nullptr;
            else if (*current == TCPOPT_EOL || *current == TCPOPT_NOP)
                current++;
            else
                current += *(char*)(current + 1);
            return (TCPOption*)(current >= ceiling ? 0 : current);
        }
};


/* FUNCTION HELPERS */

CS_pair getPairFromPkt(const PacketInfo &pkt);
CS_pair getInversedPairFromPkt(const PacketInfo &pkt);
bool operator<(const CS_pair &l, const CS_pair &r);
int getTSval(TCPOption *popt);
int getTSecr(TCPOption *popt);
#endif
