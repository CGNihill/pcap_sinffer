cmake_minimum_required(VERSION 3.0.0)
project(sniff)

set(CXX_STANDARD_REQUIRED 20)

find_package(Protobuf REQUIRED)

add_library(pcsniff ../external/sniffer/sniffer.h ../external/sniffer/sniffer.cpp)
add_library(proto_pack ../external/protobuff/gen/pack.pb.h ../external/protobuff/gen/pack.pb.cc)

add_executable(sniff main.cpp)

target_link_libraries(pcsniff pcap)
target_link_libraries(proto_pack ${Protobuf_LIBRARIES})

target_link_libraries(sniff proto_pack pcsniff)