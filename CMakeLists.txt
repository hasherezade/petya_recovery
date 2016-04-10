cmake_minimum_required(VERSION 2.8)
project (petya_recovery)

set (hdrs
	base64.h
)

set (srcs
	base64.c
	main.cpp
)

add_executable (petya_recovery ${hdrs} ${srcs})
