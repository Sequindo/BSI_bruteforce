cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)

project(BSI_bruteforce)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_library(Cryptopp_LIB libcryptopp.a)
find_path(Cryptopp_INCLUDE cryptopp)
message("Lib: ${Cryptopp_LIB}")
message("Include: ${Cryptopp_INCLUDE}")

add_executable(BSI_bruteforce main.cpp)
target_include_directories(BSI_bruteforce PRIVATE ${Cryptopp_INCLUDE})
target_link_libraries(BSI_bruteforce Threads::Threads)
target_link_libraries(BSI_bruteforce ${Cryptopp_LIB})