cmake_minimum_required(VERSION 3.15)
project(svc-scanner LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS "on")

add_library(${PROJECT_NAME} INTERFACE)

target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_17)
target_include_directories(${PROJECT_NAME} INTERFACE include)

IF (WIN32)
  target_link_libraries(${PROJECT_NAME} INTERFACE ws2_32 iphlpapi)
ELSE()
ENDIF()
