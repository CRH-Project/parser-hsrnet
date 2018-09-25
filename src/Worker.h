#ifndef _WORKER_HH_
#define _WORKER_HH_

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
#include <set>
#include <map>

#include "Buffer.hpp"
#include "PacketInfo.h"
/**
 * Class Worker
 *
 * Worker reads input packets from a buffer, 
 * writes it's output to a file without modifing input.
 *
 * It outputs:
 * 1.Some basic info
 *      number, time, srcip, dstip, protocol-type, 
 *      srcport, dstport, ack-seq, seq, is_syn, is_ack, is_fin,
 *      is_rst, mptcp_option, window_size, len, hdr_len,
 * 2.Analyzed info
 *      lost_segment, ack_rtt, retransmission, fast_retransmission,
 *      spurious_retransmission, BIF
 */

class Worker
{
    using Buffer_t = Buffer<PacketInfo>;
    using Buffer_ptr = std::shared_ptr<Buffer_t>;

    private:
        void _print_header()
        {
            for(auto &&str : Worker::header)
                fout<<str<<delimeter;
            fout<<std::endl;
        }

        static constexpr size_t BUFFERED_SIZE = 16384;
    public:
        
        Worker();
        Worker(Buffer_ptr p_, const std::string &filename)
            : buffer(p_), fout(std::ofstream(filename, std::ios::out)),
            pkt_cnt(0), stopped(false) 
        {
            if(!fout)
                throw std::runtime_error("Cannot open file for writing!");
            _print_header();
        }
        
        virtual void Start();

        virtual void Close()
        {
            fout.close();
            stopped = true;
        }

        virtual ~Worker() = default;
        
    private:
        Buffer_ptr buffer;
        std::ofstream fout;
        int pkt_cnt = 0;
        bool stopped = false;
        
    private:
        static std::vector<std::string> header;
        constexpr static char delimeter {','};

    private:
        struct ExtraInfo
        {
            size_t ack_which;
            double rtt;
            std::string retrans;
        };
        friend std::ostream & operator<<(std::ostream & o, const ExtraInfo &e)
        {
            if(e.ack_which!=0)
               o<<e.ack_which;
            o<<delimeter;
            if(e.rtt!=0)
                o<<e.rtt;
            o<<delimeter
                <<e.retrans;
            return o;
        }

    private:
        std::set<PacketInfo> buffered_pkts;
        std::map<size_t, ExtraInfo> rtt_buf;

};


class WorkerRttThp : public Worker
{
    public:

};




#endif
