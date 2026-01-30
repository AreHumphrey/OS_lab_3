cmake_minimum_required(VERSION 3.10)
project(lab3 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(lab3 main.cpp)

if(WIN32)
    target_link_libraries(lab3 PRIVATE kernel32 user32)
else()
    target_link_libraries(lab3 PRIVATE pthread rt)
endif()
