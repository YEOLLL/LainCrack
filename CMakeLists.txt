cmake_minimum_required(VERSION 3.21)
project(LainCrack)

link_libraries(crypto pthread)
set(CMAKE_C_STANDARD 23)

add_executable(LainCrack main.c crypto.c crypto.h)
