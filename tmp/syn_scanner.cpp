#include "syn_scanner.h"
#include <iostream>
#include <vector>
#include <thread>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

SynScanner::SynScanner(const std::string& target) : target_(target) {}

uint16_t SynScanner::checksum(void* addr, int len) {
    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)addr;
    while (len > 1) {
        sum += *ptr++;
        if (sum & 0x80000000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t*)ptr;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

void SynScanner::send_syn_packet(int sock, const std::string& target_ip, int src_port, int dst_port) {
    char packet[4096];
    struct ip *ip_header = (struct ip *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ip));

    memset(packet, 0, 4096);

    // IP Header
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ip_header->ip_id = htons(54321);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_TCP;
    ip_header->ip_sum = 0;
    ip_header->ip_src.s_addr = inet_addr("192.168.1.1");
    ip_header->ip_dst.s_addr = inet_addr(target_ip.c_str());

    // TCP Header
    tcp_header->th_sport = htons(src_port);
    tcp_header->th_dport = htons(dst_port);
    tcp_header->th_seq = htonl(1000);
    tcp_header->th_ack = 0;
    tcp_header->th_off = 5;
    tcp_header->th_flags = TH_SYN;
    tcp_header->th_win = htons(65535);
    tcp_header->th_sum = 0;
    tcp_header->th_urp = 0;

    tcp_header->th_sum = checksum((uint16_t *)tcp_header, sizeof(struct tcphdr));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dst_port);
    dest.sin_addr.s_addr = inet_addr(target_ip.c_str());

    if (sendto(sock, packet, ip_header->ip_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        std::cerr << "sendto failed" << std::endl;
    }
}

bool SynScanner::receive_response(int sock, int src_port, int dst_port) {
    char buffer[4096];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    int received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &fromlen);
    if (received > 0) {
        struct ip *ip_reply = (struct ip *)buffer;
        struct tcphdr *tcp_reply = (struct tcphdr *)(buffer + sizeof(struct ip));

        if (tcp_reply->th_sport == htons(dst_port) && tcp_reply->th_dport == htons(src_port)) {
            if (tcp_reply->th_flags & TH_SYN && tcp_reply->th_flags & TH_ACK) {
                return true;
            }
        }
    }
    return false;
}

bool SynScanner::is_port_open(int port) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return false;
    }

    int src_port = 12345;  // Arbitrary source port
    send_syn_packet(sock, target_, src_port, port);
    bool is_open = receive_response(sock, src_port, port);
    close(sock);
    return is_open;
}

std::vector<int> SynScanner::scan(int start_port, int end_port) {
    std::vector<std::thread*> portTests;
    std::vector<int> buffer;

    int numOfTasks = 500;

    for (int port = start_port; port <= end_port; port++) {
        portTests.push_back(new std::thread([&buffer, this, port]() {
            if (this->is_port_open(port)) {
                std::lock_guard<std::mutex> lock(bufferLock);
                buffer.push_back(port);
            }
        }));

        if (portTests.size() >= numOfTasks || port == end_port) {
            for (auto& thread : portTests) {
                thread->join();
            }
            for (auto& thread : portTests) {
                delete thread;
            }
            portTests.clear();
        }
    }

    std::sort(buffer.begin(), buffer.end());
    return buffer;
}
