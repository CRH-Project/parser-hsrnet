#ifndef _SMALLDEQUE_HPP_
#define _SMALLDEQUE_HPP_

#include <stdlib.h>
#include <stdexcept>

namespace{  // anonymous namespace

template<typename T>
struct stab
{
    public:
        /**
         * default slab size in BYTES
         * total 64KB
         * try to fit into L2 cache
         */
        static constexpr size_t ALLOCATION_SIZE = 1<<16;
        static constexpr size_t OBJECT_COUNT = ALLOCATION_SIZE/sizeof(T);

    private:
        bool is_allocated;
        size_t start_index;
        T * raw_pointer;

    public:
        stab(size_t sp, bool allocate_later = true) noexcept
            :is_allocated(false),start_index(sp),raw_pointer(nullptr)
        {
            /* allocate the memory */
            if(allocate_later == false)
                allocate();
        }

        void allocate()
        {
            if(is_allocated) return;
            is_allocated = true;
            raw_pointer = new T[OBJECT_COUNT];
        }

        /**
         * Methods:
         * operator[]
         * startIndex()
         */

        size_t startIndex(){return start_index;}
        T & operator[](size_t index)
        {
            if(index >= OBJECT_COUNT || index < 0)
                throw std::overflow_error("Index overflow inside ::stab");
            return raw_pointer[index];
        }

};

};// anonymous namespace

template<typename T>
class SmallDeque
{
    public:
        /**
         * front
         * pop_front
         * emplace_back
         * push_back
         * size
         */

        SmallDeque(size_t cap) noexcept 
            :capacity(cap)
        {
            actual_size = cap * 2;
            raw_ptr = new T[actual_size];
            printf("SmallDeque constructed at %p\n",raw_ptr);
            write_pos = 0;
            read_pos = 0;
        }

        T front()
        {
            return raw_ptr[_get_position(read_pos)];
        }

        void pop_front()
        {
            ++read_pos;
        }

        void push_back(const T &t)
        {
            auto pos = _get_position(write_pos);
            //raw_ptr[pos] = t;
            new (raw_ptr+pos) T{t};
            ++write_pos;
        }

        template<typename... ArgTypes>
        void emplace_back(ArgTypes ...args)
        {
            auto ptr = raw_ptr + _get_position(write_pos);
            new (ptr) T{args...};
            ++write_pos;
        }

        size_t size() const
        {
            return write_pos - read_pos;
        }

        virtual ~SmallDeque()
        {
            delete[] raw_ptr;
        }


    private:
        size_t capacity;
        size_t actual_size;
        T *raw_ptr;

        size_t write_pos;
        size_t read_pos;

    private:
        size_t _get_position(size_t pos){return pos % actual_size;}

};





#endif
