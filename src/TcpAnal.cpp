#include "TcpAnal.h"

int Pipe::insertPacket(const PktRange &pr)
{
    if(acked.count(pr))
        return RETRANS;

    auto res_i = inflight.insert(pr),
         res_w = window.insert(pr);
    if(res_w.second == false)       //already send
        return RETRANS;
    
    auto & iter_w = res_w.first;
    --iter_w;
    if(iter_w->end < pr.start)      //have a gap, lost seg
        return LOST_SEG;

    return NORMAL;
}


int Pipe::insertAck(const PktRange &pr)
{
    
}
