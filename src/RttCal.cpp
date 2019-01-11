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

    //RttElementTS rts(pkt, isAck);
    TCPOptionWalker wk(pkt.options);
    TCPOption *opt = wk.next();
    while(opt && opt->type != TCPOption::TIMESTAMP)
        opt = wk.next();

#ifdef USE_TS
    if(opt == nullptr)
        throw std::runtime_error("Packet with no timestamp found!");
#endif

    if(!isAck)
    {
        this->id = getPairFromPkt(pkt);
        this->seq = ntohl(pkt.trans.tcp.seq) + pkt.payload;
        this->ack_seq = ntohl(pkt.trans.tcp.ackseq);
#ifdef USE_TS
        this->tsv = getTSval(opt);
#endif
        
    }
    else
    { 
        this->id = getInversedPairFromPkt(pkt);
        this->seq = ntohl(pkt.trans.tcp.ackseq);
        this->ack_seq = ntohl(pkt.trans.tcp.seq);
#ifdef USE_TS
        this->tsv = getTSecr(opt);
#endif
    }

    //this->state = NORMAL;
    this->timestamp = pkt.time;
    this->setNumber(pkt.pkt_number);
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

std::string RttCaller::insertPacket(const PacketInfo &pkt,
        const RttElement *hint)
{
    const RttElement *ele;
    std::string ret_status = "";
    try
    {
        if(hint)
            ele = hint;
        else 
            ele = new RttElement(pkt, false);
        auto retrans_status = this->rtable.insert(*ele);
        if(!retrans_status.second)
            ret_status += "Retransmission found with " 
                + std::to_string(retrans_status.first->number);
        auto range = table.equal_range(*ele);
        for(auto it = range.first; it != range.second; ++it)
        {
            if(it->ack_seq == ele->ack_seq)
            {
                //table.erase(it);
                if(!hint) delete ele;
                return "Duplicate (same TSVAL) packet with " +
                    std::to_string(it->number);
            }
        }
        table.insert(*ele);
        if(!hint) delete ele;
        return ret_status;
    }catch(std::runtime_error &e)
    {
        //fprintf(stderr,"%s\n",e.what());
        return e.what();
    }
}

std::pair<size_t, double> RttCaller::insertAck(const PacketInfo &pkt, 
        const RttElement *hint)
{
    const RttElement * ele;
    const std::pair<size_t, double> DEFAULT_RET{0,0};
    try{
        if(hint)
            ele = hint;
        else
            ele = new RttElement(pkt, true);  //inverse
        if(!pkt.trans.tcp.ack)      // not ack return nothing
            return DEFAULT_RET;

        decltype(table.find(*ele)) res = table.end();
        auto range = table.equal_range(*ele);
        for(auto it = range.first; it != range.second; ++it)
        {
            //if(pkt.trans.tcp.seq - pkt.payload == it->ack_seq)
            //{
                res = it;
                break;
            //}
        }
        if(res != table.end())
        {
            auto tsend = res->timestamp;
            auto trecv = ele->timestamp;
            auto rtt = trecv - tsend;
            double re = rtt.tv_sec + rtt.tv_usec / 1000000.0;
            table.erase(*ele);
            if(!hint) delete ele;
            return std::make_pair(res->number,re);
        }
        if(!hint) delete ele;
        return DEFAULT_RET;
    }catch(std::runtime_error &e)
    {
        //fprintf(stderr,"%s\n",e.what());
        //return e.what();
        return DEFAULT_RET;
    }
}

void RttCaller::removePacket(const PacketInfo &pkt, const RttElement *hint)
{
    const RttElement *ele;
    try{
        if(hint)
            ele = hint;
        else 
            ele = new RttElement(pkt, false);
        table.erase(*ele);
    }catch(...){}
}

/*
std::pair<std::string, std::string> RttCaller::insertDual(const PacketInfo &pkt)
{
    auto ack = insertAck(pkt);
    auto ppp = insertPacket(pkt);
    return {ppp, ack};
}
*/

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
