#include "syn_scanner.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>  // For ip header
#include <netinet/tcp.h> // For tcp header
#include <cstring>
#include <iostream>
#include <vector>

// Ensure SynScanner includes the correct constructor and scan method implementation
SynScanner::SynScanner(const std::string& target) : Scanner(target) {}

std::vector<int> SynScanner::scan(int start_port, int end_port) {
    std::vector<int> open_ports;
    for (int port = start_port; port <= end_port; ++port) {
        if (is_port_open(port)) {
            open_ports.push_back(port);
        }
    }
    return open_ports;
}

bool SynScanner::is_port_open(int port) {
    // Implementation for checking if port is open
    return false; // Replace with actual logic
}

// Correct the send_packet function to match the header
void SynScanner::send_packet(int src_port, int dst_port) {
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
    ip_header->ip_src.s_addr = inet_addr(Scanner::local_ip_.c_str()); // Use cached local IP
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
    std::vector<std::vector<char>> fragments = fragment_packet(packet, 8); // specify the fragment size

    // Send fragments
    for (const auto& fragment : fragments) {
        if (sendto(sock, fragment.data(), fragment.size(), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            std::cerr << "Error sending packet" << std::endl;
        }
    }

    close(sock);
}
