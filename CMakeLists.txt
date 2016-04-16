cmake_minimum_required(VERSION 2.8)
project (petya_recovery)

set (hdrs
	base64.h
	decryptor.h
	types.h)

set (srcs
	base64.c
	main.cpp
	decryptor.cpp)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")


add_executable (petya_recovery ${hdrs} ${srcs})
