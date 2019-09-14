cmake_minimum_required(VERSION 3.14)
project(socks5_interface)

set(CMAKE_CXX_STANDARD 17)

add_executable(socks5_interface src/main.cpp include/socks5.hpp include/socks5_proxy.hpp
        include/socks5.hpp include/socks5_auth.hpp include/socks5_interface.hpp)