#include "TcpAnal.h"

/* =========== PktRange ============*/
bool PktRange::operator<(const PktRange & p) const
{
    if(start == p.start) return end<p.end;
    return start<p.start;
}


/*=========== Addr_pair ============*/
bool Addr_pair::operator<(const Addr_pair &ap) const
{
    if(ip == ap.ip) return port < ap.port;
    return ip<ap.ip;
}
bool Addr_pair::operator==(const Addr_pair &ap) const
{
    return ip == ap.ip && port == ap.port;
}


/*========== RttElement =============*/
bool RttElement::operator<(const RttElement & r) const
{
    if(this->id == r.id)
    {
        if(this->seq == r.seq)
            return this->tsv < r.tsv;
        return this->seq < r.seq;
    }
    return id < r.id;
}

/*========== RttElementTS =============*/
bool RttElementTS::operator<(const RttElementTS &r) const
{
    if(this->tsval == r.tsval)
        return this->tsecr < r.tsecr;
    return this->tsval < r.tsval;
}

/*========== TcpOptionWalker =========*/
