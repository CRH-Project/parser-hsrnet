CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(Analysiser-src)

SET(INCLUDES headers.h Threadpool.hpp utils.h Buffer.hpp
    SmallDeque.hpp PacketInfo.h Reader.h Worker.h TcpAnal.h
	)
SET(C_SOURCES utils.c 
	)
SET(CXX_SOURCES utils.cpp Threadpool.cpp PacketInfo.cpp
    Reader.cpp Worker.cpp TcpAnal.cpp RttCal.cpp
	)

ADD_LIBRARY(c_src_lib STATIC ${C_SOURCES} ${INCLUDES})
ADD_LIBRARY(cxx_src_lib STATIC ${CXX_SOURCES} ${INCLUDES})
