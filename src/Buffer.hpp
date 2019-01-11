#ifndef _BUFFER_HPP_
#define _BUFFER_HPP_

#include <deque>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <iostream>

#include "SmallDeque.hpp"
template<typename T> class SmallDeque;

template<typename T>
using Collection = SmallDeque<T>;
//using Collection = std::deque<T>;     // it dosen't work!

template<typename T>
class Buffer
{
    private:
        static constexpr size_t DEFAULT_STOP_BOUND = 65536;
        static constexpr size_t DEFAULT_START_BOUND = 4096;
    public:
        Buffer() 
            : stop_bound(DEFAULT_STOP_BOUND),
            start_bound(DEFAULT_START_BOUND), data(stop_bound), stopped(false)
        {
        }

        Buffer(size_t stop_bnd) : stop_bound(stop_bnd), data(stop_bnd), stopped(false)
        {
            start_bound = 0;//stop_bound/2;
        }
    public:
        T next();
        template<typename ...ArgTypes>
        void emplace(ArgTypes ...args);
        void push(const T & t);

        void setStopBound(size_t s){this->stop_bound = s;}
        size_t getStopBound(){return this->stop_bound;}

        void setStartBound(size_t s){this->start_bound = s;}
        size_t getStartBound(){return this->start_bound;} 

        void stop(){this->stopped = true; read_cond.notify_one();}
        bool isRunning(){return !stopped || this->data.size() != 0;}
    private:

        size_t stop_bound = DEFAULT_STOP_BOUND;
        size_t start_bound = DEFAULT_START_BOUND;

        Collection<T> data;
        
        std::mutex write_mutex;
        std::condition_variable write_cond;

        std::mutex read_mutex;
        std::condition_variable read_cond;

        bool stopped = false;
};

template<typename T>
T Buffer<T>::next()
{
    if(!isRunning())
        throw std::runtime_error("Try to read from a stopped buffer!");
    std::unique_lock<std::mutex> read_lock(this->read_mutex);
    if(!stopped)
        read_cond.wait(read_lock,[this](){ return this->data.size() > 1;});
    T ret{std::move(this->data.front())};
    this->data.pop_front();
    if(this->data.size()<start_bound) 
        write_cond.notify_one();
    if(this->data.size() == 0) std::cout<<"reach 0!"<<std::endl;
    return ret;
}

template<typename T>
void Buffer<T>::push(const T & t)
{
    /**
     * race condition here!
     * However, it's the single reader/writer Buffer
     * So we don't really care about the actual size
     * of data queue, so we use data.size() here
     * directly instead of using somehow locking 
     */
    if(this->data.size() > stop_bound)
    {
        std::unique_lock<std::mutex> write_lock(this->write_mutex);
        std::cout<<"reach stop bound!"<<std::endl;
        this->write_cond.wait(write_lock,
                [this](){return this->data.size() < this->start_bound;});

        std::cout<<"reach start bound!"<<std::endl;
    }
    this->data.push_back(t);
    if(this->data.size() > this->start_bound) this->read_cond.notify_one();
}


template<typename T>
template<typename... ArgTypes>
void Buffer<T>::emplace(ArgTypes ...args)
{
    /**
     * race condition here!
     * just like in push();
     */
    if(this->data.size() > stop_bound)
    {
        std::unique_lock<std::mutex> write_lock(this->write_mutex);
        std::cout<<"reach stop bound!"<<std::endl;
        this->write_cond.wait(write_lock,
                [this](){return this->data.size() < this->start_bound;});

        std::cout<<"reach start bound!"<<std::endl;
    }
    this->data.emplace_back(args...);
    if(this->data.size() > this->start_bound) this->read_cond.notify_one();
}
#endif
