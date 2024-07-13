#include "syn_scanner.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <algorithm>
#include <thread>
#include <mutex>
#include <chrono>
#include <sys/event.h>
#include <fcntl.h>

SynScanner::SynScanner(const std::string& target, std::shared_ptr<Packet> packet) 
    : Scanner(target), packet_(packet) {}

std::vector<int> SynScanner::scan(int start_port, int end_port) {
    std::vector<int> open_ports;
    std::vector<std::thread> threads;
    int num_threads = 12; // Adjust the number of threads based on your needs
    int ports_per_thread = (end_port - start_port + 1) / num_threads;

    for (int i = 0; i < num_threads; ++i) {
        int thread_start_port = start_port + i * ports_per_thread;
        int thread_end_port = (i == num_threads - 1) ? end_port : thread_start_port + ports_per_thread - 1;
        threads.emplace_back(&SynScanner::scan_range, this, thread_start_port, thread_end_port, std::ref(open_ports));
    }

    for (auto& thread : threads) {
        thread.join();
    }

    std::sort(open_ports.begin(), open_ports.end());
    return open_ports;
}

void SynScanner::scan_range(int start_port, int end_port, std::vector<int>& open_ports) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return;
    }

    int kq = kqueue();
    if (kq == -1) {
        std::cerr << "Error creating kqueue instance" << std::endl;
        close(sock);
        return;
    }

    struct kevent ev;
    EV_SET(&ev, sock, EVFILT_READ, EV_ADD, 0, 0, nullptr);
    if (kevent(kq, &ev, 1, nullptr, 0, nullptr) == -1) {
        std::cerr << "Error adding socket to kqueue" << std::endl;
        close(kq);
        close(sock);
        return;
    }

    std::vector<int> ports_to_scan;
    for (int port = start_port; port <= end_port; ++port) {
        ports_to_scan.push_back(port);
    }

    int max_in_flight = 1000; // Adjust based on your needs
    int timeout_ms = 1000; // Initial timeout
    auto start_time = std::chrono::steady_clock::now();

    while (!ports_to_scan.empty()) {
        int in_flight = 0;
        for (auto it = ports_to_scan.begin(); it != ports_to_scan.end() && in_flight < max_in_flight;) {
            send_packet(sock, *it);
            ++in_flight;
            it = ports_to_scan.erase(it);
        }

        struct kevent events[max_in_flight];
        timespec timeout = {timeout_ms / 1000, (timeout_ms % 1000) * 1000000};
        int nfds = kevent(kq, nullptr, 0, events, max_in_flight, &timeout);

        for (int n = 0; n < nfds; ++n) {
            if (events[n].ident == sock) {
                int port = process_response(sock);
                if (port > 0) {
                    std::lock_guard<std::mutex> lock(bufferLock);
                    open_ports.push_back(port);
                }
            }
        }

        // Dynamic timing adjustment
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time).count();
        if (elapsed > 0) {
            int scan_rate = in_flight * 1000 / elapsed;
            if (scan_rate > 1000) {
                max_in_flight = std::min(max_in_flight * 2, 5000);
                timeout_ms = std::max(timeout_ms / 2, 100);
            } else if (scan_rate < 100) {
                max_in_flight = std::max(max_in_flight / 2, 100);
                timeout_ms = std::min(timeout_ms * 2, 5000);
            }
        }
        start_time = current_time;
    }

    close(kq);
    close(sock);
}

void SynScanner::send_packet(int sock, int port) {
    std::vector<char> packet(4096);
    packet_->prepare_packet(packet, 12345, port);

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target_.c_str(), &dest.sin_addr);
    sendto(sock, packet.data(), packet.size(), 0, (struct sockaddr *)&dest, sizeof(dest));
}

int SynScanner::process_response(int sock) {
    char buffer[4096];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &fromlen);
    if (len > 0) {
        struct ip *ip_header = (struct ip *)buffer;
        struct tcphdr *tcp_header = (struct tcphdr *)(buffer + (ip_header->ip_hl << 2));
        if (tcp_header->th_flags & TH_SYN && tcp_header->th_flags & TH_ACK) {
            return ntohs(tcp_header->th_sport);
        }
    }
    return -1;
}

bool SynScanner::is_port_open(int port) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return false;
    }

    send_packet(sock, port);

    char buffer[4096];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int retval = select(sock + 1, &readfds, NULL, NULL, &timeout);
    if (retval == -1) {
        std::cerr << "Error on select" << std::endl;
        close(sock);
        return false;
    } else if (retval) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &fromlen);
        if (len > 0) {
            struct ip *ip_header = (struct ip *)buffer;
            struct tcphdr *tcp_header = (struct tcphdr *)(buffer + (ip_header->ip_hl << 2));
            if (tcp_header->th_flags & TH_SYN && tcp_header->th_flags & TH_ACK) {
                close(sock);
                return true;
            }
        }
    }

    close(sock);
    return false;
}
