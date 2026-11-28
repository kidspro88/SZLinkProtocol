cmake_minimum_required(VERSION 3.13)

project(udp_example CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(SZLink REQUIRED)

add_executable(udp_example udp_example.cpp)

target_link_libraries(udp_example PRIVATE SZLink::szlink)
