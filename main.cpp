#include <iostream>
#include <cassert>
#include <stdio.h>
#include <map>
#include "src/Threadpool.hpp"
#include "src/SmallDeque.hpp"
#include "src/Buffer.hpp"
#include "src/Reader.h"
#include "src/Worker.h"
#include "src/TcpAnal.h"

using namespace std;
using TP = Aposta::FixedThreadPool;

void testBuffer()
{
    Buffer<int> buf;
    TP pool(2);
    auto writer = [&buf](){
        int i = 0;
        while(true){
            if(i%2)
                buf.emplace(i++); 
            else buf.push(i++);
            i%=2000;
        }
    };
    auto reader = [&buf](){
        std::this_thread::sleep_for(1s);
        while(true){
            auto num = buf.next();
            printf("%d ",num);
            if(num % 200 == 0)
            {
                printf("\n");
                std::this_thread::sleep_for(1s);
            }
        }
    };

    buf.setStopBound(1000);
    buf.setStartBound(500);

    pool.enqueue(writer);
    pool.enqueue(reader);

    //pool.barrier();

}

void testSmallDeque()
{
    struct A
    {
        int id;
        char c;
        A(int i, char cc):id(i),c(cc){}
        A() = default;
        A(A && _) = default;
        A(const A &) = default;
    };

    SmallDeque<A> deq(100);
    for(int i=0;i<10;i++) deq.emplace_back(i,i+'0');
    for(int i=0;i<10;i++) deq.push_back(A(i,i+'a'));
    auto s = deq.size();
    for(size_t i=0;i<s;i++)
    {
        A a {std::move(deq.front())};
        deq.pop_front();
        std::cout<<a.c<<" "<<a.id<<std::endl; 
    }

}

REG_PCAP_READER_NO_PRED("test", 1);
extern BufferProvider provider;
void testReader(const char *filename)
{
    REG_NEW_BUFFER("test");
    TP pool(2);
    auto buf = provider.GetBufferByName("test");
    assert(buf);
    int count = 0;
    auto reader = [&](){
            while(buf->isRunning()){buf->next();}};
    pool.enqueue(reader);
    pool.enqueue(reader_1,filename);
}

REG_PCAP_READER_NO_PRED("testRW", RW);
void testRW(const char *input)
{
    REG_NEW_BUFFER("testRW");
    TP pool(2);
    auto buf = provider.GetBufferByName("testRW");
    assert(buf);
    Worker worker(buf, "output.csv");
    auto future = pool.enqueue([&worker](){worker.Start();});
    pool.enqueue(reader_RW, input);
    future.get();
    worker.Close();
    
}

#define MAIN_BUFFER_NAME "mainBuf"
REG_PCAP_READER_NO_PRED(MAIN_BUFFER_NAME, MAIN);

std::map<std::string, int> ethMap {
    {"tcpdump", ETH_TCPDUMP},{"tshark", ETH_TSHARK}
};
int main(int argc, char *argv[])
{
    //testRW(argv[1]);
    if(argc!=3)
    {
        fprintf(stderr, "Usage: %s <pcap_file> <pcap_type = {tcpdump | tshark}>\n", argv[0]);
        fprintf(stderr, "Output file name will be <pcap_file>-anal.csv\n");
        exit(-1);
    }

    std::string type{argv[2]};
    if(ethMap.count(type) == 0)
    {
        fprintf(stderr, "The second parameter must choose between 'tcpdump' or 'tshark'; but got %s\n",
                type.c_str());
        fprintf(stderr, "Unrecoginzed parameter! The default value 'tcpdump' will be used!\n");
    }
    setEthernetType(ethMap[type]);
    
    std::string input{argv[1]};
    REG_NEW_BUFFER(MAIN_BUFFER_NAME);
    TP pool(2);
    auto buf = provider.GetBufferByName(MAIN_BUFFER_NAME);
    assert(buf);
    Worker worker(buf, input + "-anal.csv");

    auto future = pool.enqueue([&worker](){worker.Start();});
    pool.enqueue(reader_MAIN, input.c_str());
    future.get();
    worker.Close();
}
