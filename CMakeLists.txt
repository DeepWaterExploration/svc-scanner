cmake_minimum_required(VERSION 3.15)
project(svc-scanner LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS "on")

set(CPP_SOURCES src/main.cpp)

add_executable(svc-scanner ${CPP_SOURCES})

target_compile_features(svc-scanner PRIVATE cxx_std_17)
target_include_directories(svc-scanner PRIVATE include)
target_link_libraries(svc-scanner ws2_32 iphlpapi)
