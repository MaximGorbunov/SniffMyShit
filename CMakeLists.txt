cmake_minimum_required(VERSION 3.27)
project(SniffMyShit)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_CPPCHECK "cppcheck")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


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
if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR NOT CMAKE_BUILD_TYPE)
    include(FetchContent)
    FetchContent_Declare(
        cpptrace
        GIT_REPOSITORY  https://github.com/jeremy-rifkin/cpptrace
        GIT_TAG        v1.0.4
    )
    FetchContent_MakeAvailable(cpptrace)
    target_link_libraries("${PROJECT_NAME}" PUBLIC cpptrace::cpptrace)
endif()


target_compile_options("${PROJECT_NAME}" PRIVATE
        "-O3" "-Werror" "-Wall" "-Wpedantic" "-Wextra" "-Wshadow" "-fexceptions" "-Wnon-virtual-dtor" "-Wno-unused-parameter"
)
target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)
