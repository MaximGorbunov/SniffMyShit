cmake_minimum_required(VERSION 3.29)
project(SniffMyShit)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_CPPCHECK "cppcheck")

add_compile_options(
        "-O3" "-Werror" "-Wall" "-Wpedantic" "-Wextra" "-Wshadow" "-fexceptions" "-Wnon-virtual-dtor" "-Wno-unused-parameter"
)

#debug
if (DEFINED ENV{ADDRESS_SANITIZER})
    add_compile_options("-fsanitize=address;-fsanitize=undefined;")
    add_link_options("-fsanitize=address;-fsanitize=undefined;")
ENDIF()

if (DEFINED ENV{THREAD_SANITIZER} AND NOT APPLE)
    add_compile_options("-fsanitize=thread;-fsanitize=undefined;-Wno-error=tsan")
    add_link_options("-fsanitize=thread;-fsanitize=undefined;-Wno-error=tsan")
ENDIF()

set(SOURCES
        src/main/main.cpp
        src/main/options.cpp
        src/main/reassembly/IpReassembly.cpp
        src/main/reassembly/TcpReassembly.cpp
        src/main/reassembly/HttpReassembly.cpp
        src/main/reassembly/parser/http1Parser.cpp
        src/main/filter/httpFilter.cpp
)


add_executable(SniffMyShit ${SOURCES})

find_package(PcapPlusPlus REQUIRED)
target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)