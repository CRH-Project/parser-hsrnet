#ifndef _READER_HH_
#define _READER_HH_

class Reader;
class BufferProvider;
extern BufferProvider provider;

#include <memory>
#include <string>
#include <functional>
#include <pcap/pcap.h>
#include <stdexcept>
#include <map>
#include <vector>

#include "PacketInfo.h"
#include "Buffer.hpp"

void printErr(int, u_char*);

class BufferProvider
{
    private:
        using Buffer_t = Buffer<PacketInfo>;
        using BufferPtr = std::shared_ptr<Buffer_t>;

        std::map<std::string, BufferPtr> storage;

    public:
        void CreateNewBuffer(const std::string &name)
        {
            if(storage.count(name) == 0)
                storage.emplace(name, std::make_shared<Buffer_t>());
        }

        BufferPtr GetBufferByName(const std::string &name)
        {
            if(storage.count(name) == 0) return nullptr;
            return storage[name];
        }

};

extern BufferProvider provider;

#define REG_NEW_BUFFER(B_NAME) provider.CreateNewBuffer(B_NAME)

#define REG_PCAP_HANDLER_WITH_BUF(F_NAME, B_NAME)              \
    void handler##F_NAME(u_char *, const struct pcap_pkthdr *h,\
            const u_char *pkt)                                 \
    {                                                          \
        try                                                    \
        {                                                      \
            PacketInfo p(pkt,h->ts);                           \
        }catch(...)                                            \
        {                                                      \
            return;                                            \
        }                                                      \
        provider.GetBufferByName(B_NAME)->emplace(pkt, h->ts); \
    }                                                          \


#define REG_PCAP_HANDLER_WITH_BUF_AND_PRED(F_NAME, B_NAME, PRED) \
    void handler##F_NAME(u_char *, const struct pcap_pkthdr *h,  \
            const u_char *pkt)                                   \
    {                                                            \
        try                                                      \
        {                                                        \
            PacketInfo p(pkt, h->ts);                            \
            if(!PRED(p)) return;                                 \
        }catch(...)                                              \
        {                                                        \
            return;                                              \
        }                                                        \
        provider.GetBufferByName(B_NAME)->emplace(pkt, h->ts);   \
    }                                                            \


#define REG_PCAP_READER(B_NAME, PRED, ID)                      \
    REG_PCAP_HANDLER_WITH_BUF_AND_PRED(ID ,B_NAME,PRED)        \
    void reader_##ID(const char *filename)                     \
    {                                                          \
        FILE *file = fopen(filename, "r");                     \
        pcap_t *pcap = pcap_fopen_offline(file, NULL);         \
        u_char err[100];                                       \
        int errcode = pcap_loop(pcap, 0, handler##ID, err);    \
        if(errcode) printErr(errcode, err);                    \
        fclose(file);                                          \
        provider.GetBufferByName(B_NAME)->stop();              \
    }                                                          \

#define REG_PCAP_READER_NO_PRED(B_NAME, ID)                    \
    REG_PCAP_HANDLER_WITH_BUF(ID ,B_NAME)                      \
    void reader_##ID(const char *filename)                     \
    {                                                          \
        FILE *file = fopen(filename, "r");                     \
        pcap_t *pcap = pcap_fopen_offline(file, NULL);         \
        u_char err[100];                                       \
        int errcode = pcap_loop(pcap, 0, handler##ID, err);    \
        if(errcode) printErr(errcode, err);                    \
        fclose(file);                                          \
        provider.GetBufferByName(B_NAME)->stop();              \
    }                                                          \
                                                                
/**
 * Reader reads from pacp file, use the filter to filter out
 * unwanted packet and insert the wanted packet into a buffer
 */
using Pred = std::function<bool(PacketInfo *)>;
using PcapHandle = std::function<
                    void(u_char, const struct pcap_pkthdr*, u_char*)>;

/*
class Reader
{
    private:
        FILE *file;
        pcap_t *pcap;
        std::shared_ptr<Buffer<PacketInfo>> buf;
        const Pred &pred;

        void _init();
        Reader(const char *f_,
               const std::string &buf_name,
               const Pred &p_)
            : pred(p_) 
        {
            file = fopen(f_,"r");
            if(!file) 
                throw std::runtime_error("PCAP File Not Found!");
            pcap = pcap_fopen_offline(file, NULL);

            this->buf = provider.GetBufferByName(buf_name);
        }

        void handler(u_char *, const struct pcap_pkthdr *, const u_char *);

    public:
        void Start();

    public:
        class Builder
        {
            using RB = Reader::Builder&;
            public:
                std::shared_ptr<Reader> build(); // build the Reader

                RB setInput(const char *filename);
                RB setBuffer(std::shared_ptr<Buffer<PacketInfo>> buf);
                RB setFilter(std::shared_ptr<Pred> p);

            private:
                bool _check_prequsites();
        };

        friend class Reader::Builder;
};
*/


#endif
