#include "scanner.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>  // For ip header
#include <netinet/tcp.h> // For tcp header
#include <cstring>
#include <iostream>
#include <vector>

// Static member definition
std::string Scanner::local_ip_ = "";

Scanner::Scanner(const std::string& target) : target_(target) {
    if (local_ip_.empty()) {
        initialize_local_ip();
    }
}

// Initialize local IP
void Scanner::initialize_local_ip() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Error creating socket to get local IP" << std::endl;
        return;
    }

    // Use a dummy destination address to get the local IP
    struct sockaddr_in dest;
    std::memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr("8.8.8.8"); // Google DNS
    dest.sin_port = htons(53); // DNS port

    if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == -1) {
        std::cerr << "Error connecting to dummy address" << std::endl;
        close(sock);
        return;
    }

    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(sock, (struct sockaddr*)&local_addr, &addr_len) == -1) {
        std::cerr << "Failed to get local address" << std::endl;
        close(sock);
        return;
    }

    char local_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, INET_ADDRSTRLEN);
    local_ip_ = local_ip;

    std::cout << "Cached Local IP Address: " << local_ip_ << std::endl;
    close(sock);
}

// Fragment packet
std::vector<std::vector<char>> Scanner::fragment_packet(const std::vector<char>& packet, int fragment_size) {
    std::vector<std::vector<char>> fragments;
    for (size_t i = 0; i < packet.size(); i += fragment_size) {
        std::vector<char> fragment(packet.begin() + i, packet.begin() + std::min(i + fragment_size, packet.size()));
        fragments.push_back(fragment);
    }
    return fragments;
}

// Send decoy packets
void Scanner::send_decoy_packets(const std::string& real_src_ip, int src_port, int dst_port) {
    std::vector<std::string> decoy_ips = {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"};
    for (const auto& decoy_ip : decoy_ips) {
        send_packet(decoy_ip, src_port, dst_port);
    }
    send_packet(real_src_ip, src_port, dst_port);
}

// Send packet
void Scanner::send_packet(const std::string& src_ip, int src_port, int dst_port) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dst_port);
    inet_pton(AF_INET, target_.c_str(), &dest.sin_addr);

    std::vector<char> packet(4096);
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
    ip_header->ip_src.s_addr = inet_addr(src_ip.c_str());
    ip_header->ip_dst = dest.sin_addr;

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

    // Fragment the packet
    std::vector<std::vector<char>> fragments = fragment_packet(packet, 8);

    // Send fragments
    for (const auto& fragment : fragments) {
        if (sendto(sock, fragment.data(), fragment.size(), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            std::cerr << "Error sending packet" << std::endl;
        }
    }

    close(sock);
}
