#include "scanner.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstring>
#include <iostream>
#include <vector>

Scanner::Scanner(const std::string& target) : target_(target) {}

std::vector<std::vector<char>> Scanner::fragment_packet(const std::vector<char>& packet, int fragment_size) {
    std::vector<std::vector<char>> fragments;
    for (size_t i = 0; i < packet.size(); i += fragment_size) {
        std::vector<char> fragment(packet.begin() + i, packet.begin() + std::min(i + fragment_size, packet.size()));
        fragments.push_back(fragment);
    }
    return fragments;
}


void Scanner::send_decoy_packets(int src_port, int dst_port) {
    // std::string original_ip = local_ip_;
    // std::vector<std::string> decoy_ips = {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"};
    
    // for (const auto& decoy_ip : decoy_ips) {
    //     local_ip_ = decoy_ip;
    //     send_packet(src_port, dst_port);
    // }
    
    // local_ip_ = original_ip;
    // send_packet(src_port, dst_port); // Send the real packet
}
