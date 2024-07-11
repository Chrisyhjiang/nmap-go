#include "scanner.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>  // For ip header
#include <netinet/tcp.h> // For tcp header
#include <cstring>
#include <thread>
#include <mutex>
#include <iostream>
#include <random>
#include <vector>
#include <algorithm>

// Constructor definition
Scanner::Scanner(const std::string& target) : target_(target) {}

// Load OS database
void Scanner::load_os_database() {
    // This is a simplified version. In a real implementation, you'd load from a file.
    os_database = {
        {"Apple macOS 12.X", "Apple macOS 12 (Monterey) (Darwin 21.1.0 - 21.6.0)", 64, 65535, "MSS,NOP,WS,NOP,NOP,TS"},
        {"Linux 5.X", "Linux 5.0 - 5.15", 64, 29200, "MSS,SACK,TS,NOP,WS"},
        {"Windows 10", "Microsoft Windows 10 1809 - 21H2", 128, 65535, "MSS,NOP,WS,NOP,NOP,TS"}
    };
}

// Get target fingerprint
Scanner::OSFingerprint Scanner::get_target_fingerprint() {
    OSFingerprint fingerprint;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return fingerprint;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(80);
    inet_pton(AF_INET, target_.c_str(), &dest.sin_addr);

    char packet[4096];
    struct ip *ip_header = (struct ip *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ip));

    // Prepare IP header
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    ip_header->ip_id = htons(54321);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_TCP;
    ip_header->ip_sum = 0;
    ip_header->ip_src.s_addr = inet_addr("192.168.1.1");
    ip_header->ip_dst = dest.sin_addr;

    // Prepare TCP header
    tcp_header->th_sport = htons(12345);
    tcp_header->th_dport = htons(80);
    tcp_header->th_seq = htonl(1000);
    tcp_header->th_ack = 0;
    tcp_header->th_off = 5;
    tcp_header->th_flags = TH_SYN;
    tcp_header->th_win = htons(65535);
    tcp_header->th_sum = 0;
    tcp_header->th_urp = 0;

    // Send packet and receive response
    if (sendto(sock, packet, ip_header->ip_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        std::cerr << "Error sending packet" << std::endl;
        close(sock);
        return fingerprint;
    }

    char buffer[4096];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    int received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &fromlen);

    if (received > 0) {
        struct ip *ip_reply = (struct ip *)buffer;
        struct tcphdr *tcp_reply = (struct tcphdr *)(buffer + sizeof(struct ip));

        fingerprint.ttl = ip_reply->ip_ttl;
        fingerprint.window_size = ntohs(tcp_reply->th_win);
        // Parse TCP options (simplified)
        fingerprint.tcp_options = "MSS,NOP,WS,NOP,NOP,TS";
    }

    close(sock);
    return fingerprint;
}

// Match fingerprint
std::string Scanner::match_fingerprint(const OSFingerprint& target) {
    for (const auto& db_entry : os_database) {
        if (db_entry.ttl == target.ttl &&
            db_entry.window_size == target.window_size &&
            db_entry.tcp_options == target.tcp_options) {
            return db_entry.os_name + "\nOS details: " + db_entry.os_details;
        }
    }
    return "Unknown OS";
}

// Detect OS
std::string Scanner::detect_os() {
    load_os_database();
    OSFingerprint target_fp = get_target_fingerprint();
    return "Running: " + match_fingerprint(target_fp);
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
    std::vector<std::vector<char>> fragments = fragment_packet(packet, 8); // specify the fragment size

    // Send fragments
    for (const auto& fragment : fragments) {
        if (sendto(sock, fragment.data(), fragment.size(), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            std::cerr << "Error sending packet" << std::endl;
        }
    }

    close(sock);
}
