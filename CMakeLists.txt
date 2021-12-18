cmake_minimum_required(VERSION 3.20)
project(hw3)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

add_executable(hw3 src/main.cpp src/elf_parser.cpp include/elf_parser.h)
