cmake_minimum_required(VERSION 3.20)

project(sock5_client LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(sock5_client STATIC client.c)
target_include_directories(sock5_client PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")