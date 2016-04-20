cmake_minimum_required(VERSION 2.8)
project (petya_recovery)

set (hdrs
	base64.h
	decryptor.h
	genetic.h
	types.h)

set (srcs
	base64.c
	genetic.cpp
	main.cpp
	decryptor.cpp)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
SET(BUILD_SHARED_LIBRARIES OFF)
SET(CMAKE_EXE_LINKER_FLAGS "-static")

option (OUT_32BIT "Build 32-bit executable" OFF)

IF (OUT_32BIT)
	# To build x86 executable on x86-64 linux, install also the following: gcc-multilib g++-multilib
	set(CMAKE_SYSTEM_NAME Linux)
	set(CMAKE_SYSTEM_PROCESSOR "i686")

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32" CACHE STRING "c++ flags")
	set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -m32" CACHE STRING "c flags")
ENDIF(OUT_32BIT)

add_executable (petya_recovery ${hdrs} ${srcs})
