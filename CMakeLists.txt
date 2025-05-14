cmake_minimum_required(VERSION 3.20)

project(sock5-client LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(sock5-client STATIC client.c)