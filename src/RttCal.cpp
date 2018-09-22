#ifndef _RTTCAL_HH_
#define _RTTCAL_HH_

#include <stdexcept>
#include "PacketInfo.h"
#include "TcpAnal.h"
#include "utils.h"

bool operator<(const CS_pair &l, const CS_pair &r)
{    
    if(l.first == r.first)
        return l.second<r.second;
    return l.first < r.first;
}

CS_pair getPairFromPkt(const PacketInfo &pkt)
{
    CS_pair pair;
    pair.first.ip = pkt.ip.srcip;
    pair.first.port = pkt.trans.tcp.srcport;

    pair.second.ip = pkt.ip.dstip;
    pair.second.port = pkt.trans.tcp.dstport;
    return pair;
}

CS_pair getInversedPairFromPkt(const PacketInfo &pkt)
{
    CS_pair pair;
    pair.first.ip = pkt.ip.dstip;
    pair.first.port = pkt.trans.tcp.dstport;

    pair.second.ip = pkt.ip.srcip;
    pair.second.port = pkt.trans.tcp.srcport;
    return pair;
}

int getTSval(TCPOption *popt)
{
    uint32_t *ptsval = (uint32_t *)(popt->data);
    return *ptsval;
}

int getTSecr(TCPOption *popt)
{
    uint32_t *ptsecr = (uint32_t *)((char *)(popt->data) + 4);
    return *ptsecr;
}

RttElement::RttElement(const PacketInfo &pkt, bool isAck)
{
    if(pkt.mode != PacketInfo::TransMode::TCP)
        throw std::runtime_error("expect TCP packet to calculate RTT");

    RttElementTS rts(pkt, isAck);

    if(!isAck)
    {
        this->id = getPairFromPkt(pkt);
        this->seq = pkt.trans.tcp.seq;
        this->ack_seq = pkt.trans.tcp.ackseq;
        this->tsv = rts.tsval;
        
    }
    else
    { 
        this->id = getInversedPairFromPkt(pkt);
        this->seq = pkt.trans.tcp.ackseq;
        this->ack_seq = pkt.trans.tcp.seq;
        this->tsv = rts.tsval;
    }

    //this->state = NORMAL;
    this->timestamp = pkt.time;
}

RttElementTS::RttElementTS(const PacketInfo &pkt, bool isAck)
{
    if(pkt.mode != PacketInfo::TransMode::TCP)
        throw std::runtime_error("expect TCP packet to calculate RTT");

    TCPOptionWalker wk(pkt.options);
    TCPOption *opt = wk.next();
    while(opt && opt->type != TCPOption::TIMESTAMP)
        opt = wk.next();
    if(opt == nullptr)
        throw std::runtime_error("Packet with no timestamp found!");
    if(!isAck)
    {
        this->tsecr = getTSecr(opt);
        this->tsval = getTSval(opt);
    }
    else
    {
        this->tsval = getTSecr(opt);
        this->tsecr = getTSval(opt);
    }
    this->timestamp = pkt.time;
}

std::string RttCaller::insertPacket(const PacketInfo &pkt)
{
    try
    {
        RttElement ele(pkt, false);
        auto range = table.equal_range(ele);
        for(auto it = range.first; it != range.second; ++it)
        {
            if(it->ack_seq == ele.ack_seq)
            {
                table.erase(it);
                return "This is a retransmission ";//having same tsval";
            }
        }
        /*
           if(table.find(ele) != table.end())
           {
           table.erase(ele);
           return "This is a retransmission";
           }
           */
        table.insert(ele);
        return "";
    }catch(std::runtime_error &e)
    {
        //fprintf(stderr,"%s\n",e.what());
        return e.what();
    }
}

std::string RttCaller::insertAck(const PacketInfo &pkt)
{
    try{
        RttElement ele(pkt, true);  //inverse
        if(!pkt.trans.tcp.ack)      // not ack return nothing
            return "";

        decltype(table.find(ele)) res = table.end();
        auto range = table.equal_range(ele);
        for(auto it = range.first; it != range.second; ++it)
        {
            if(pkt.trans.tcp.seq - pkt.payload == it->ack_seq)
            {
                res = it;
                break;
            }
        }
        if(res != table.end())
        {
            auto tsend = res->timestamp;
            auto trecv = ele.timestamp;
            auto rtt = trecv - tsend;
            double res = rtt.tv_sec + rtt.tv_usec / 1000000.0;
            table.erase(ele);
            return std::to_string(res);
        }

        return "";
    }catch(std::runtime_error &e)
    {
        //fprintf(stderr,"%s\n",e.what());
        return e.what();
    }
}

std::pair<std::string, std::string> RttCaller::insertDual(const PacketInfo &pkt)
{
    auto ack = insertAck(pkt);
    auto ppp = insertPacket(pkt);
    return {ppp, ack};
}

std::string RttCallerTS::insertPacket(const PacketInfo &pkt)
{
    try
    {
        table.emplace(pkt, false);
    }catch(std::runtime_error &e)
    {
        return e.what();
    }
    return "";
}

std::string RttCallerTS::insertAck(const PacketInfo &pkt)
{
    try
    {
        RttElementTS ele(pkt, true);
        auto result = table.find(ele);
        if(result == table.end()) return "";
        auto tsend = result->timestamp;
        auto trecv = ele.timestamp;
        auto rtt = trecv - tsend;
        double res = rtt.tv_sec + rtt.tv_usec / 1000000.0;
        table.erase(ele);
        return std::to_string(res);
    }catch(std::runtime_error &e)
    {
        return e.what();
    }
}



#endif
