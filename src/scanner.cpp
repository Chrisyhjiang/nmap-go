#include "scanner.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstring>
#include <iostream>
#include <vector>

std::string Scanner::local_ip_ = "";

Scanner::Scanner(const std::string& target) : target_(target) {
    if (local_ip_.empty()) {
        initialize_local_ip();
    }
}

void Scanner::initialize_local_ip() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return;
    }

    const char* kGoogleDnsIp = "8.8.8.8";
    uint16_t kDnsPort = 53;
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons(kDnsPort);

    int err = connect(sock, (const struct sockaddr*) &serv, sizeof(serv));
    if (err < 0) {
        std::cerr << "Error connecting to socket" << std::endl;
        close(sock);
        return;
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);
    if (err < 0) {
        std::cerr << "Error getting socket name" << std::endl;
        close(sock);
        return;
    }

    char buffer[INET_ADDRSTRLEN];
    const char* p = inet_ntop(AF_INET, &name.sin_addr, buffer, sizeof(buffer));
    if (p == nullptr) {
        std::cerr << "Error getting IP address" << std::endl;
        close(sock);
        return;
    }

    local_ip_ = buffer;
    std::cout << "Cached Local IP Address: " << local_ip_ << std::endl;
    close(sock);
}

std::vector<std::vector<char>> Scanner::fragment_packet(const std::vector<char>& packet, int fragment_size) {
    std::vector<std::vector<char>> fragments;
    for (size_t i = 0; i < packet.size(); i += fragment_size) {
        std::vector<char> fragment(packet.begin() + i, packet.begin() + std::min(i + fragment_size, packet.size()));
        fragments.push_back(fragment);
    }
    return fragments;
}

void Scanner::prepare_packet(std::vector<char>& packet, int src_port, int dst_port) {
    struct ip *ip_header = (struct ip *)packet.data();
    struct tcphdr *tcp_header = (struct tcphdr *)(packet.data() + sizeof(struct ip));

    // Prepare IP header
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ip_header->ip_id = htons(54321);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 255;
    ip_header->ip_p = IPPROTO_TCP;
    ip_header->ip_sum = 0;
    ip_header->ip_src.s_addr = inet_addr(local_ip_.c_str());
    ip_header->ip_dst.s_addr = inet_addr(target_.c_str());

    // Prepare TCP header
    tcp_header->th_sport = htons(src_port);
    tcp_header->th_dport = htons(dst_port);
    tcp_header->th_seq = htonl(1000);
    tcp_header->th_ack = 0;
    tcp_header->th_off = 5;
    tcp_header->th_flags = TH_SYN;
    tcp_header->th_win = htons(65535);
    tcp_header->th_sum = 0;
    tcp_header->th_urp = 0;
}

void Scanner::send_decoy_packets(int src_port, int dst_port) {
    std::string original_ip = local_ip_;
    std::vector<std::string> decoy_ips = {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"};
    
    for (const auto& decoy_ip : decoy_ips) {
        local_ip_ = decoy_ip;
        send_packet(src_port, dst_port);
    }
    
    local_ip_ = original_ip;
    send_packet(src_port, dst_port); // Send the real packet
}
