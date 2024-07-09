#include "syn_scanner.h"
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>  // For ip header
#include <netinet/tcp.h> // For tcp header
#include <sys/socket.h>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>

std::mutex bufferLock;

SynScanner::SynScanner(const std::string& target) : target_ip(target) {}

void SynScanner::load_os_database() {
    // This is a simplified version. In a real implementation, you'd load from a file.
    os_database = {
        {"Apple macOS 12.X", "Apple macOS 12 (Monterey) (Darwin 21.1.0 - 21.6.0)", 64, 65535, "MSS,NOP,WS,NOP,NOP,TS"},
        {"Linux 5.X", "Linux 5.0 - 5.15", 64, 29200, "MSS,SACK,TS,NOP,WS"},
        {"Windows 10", "Microsoft Windows 10 1809 - 21H2", 128, 65535, "MSS,NOP,WS,NOP,NOP,TS"}
    };
}

SynScanner::OSFingerprint SynScanner::get_target_fingerprint() {
    OSFingerprint fingerprint;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return fingerprint;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(80);
    inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);

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

std::string SynScanner::match_fingerprint(const OSFingerprint& target) {
    for (const auto& db_entry : os_database) {
        if (db_entry.ttl == target.ttl &&
            db_entry.window_size == target.window_size &&
            db_entry.tcp_options == target.tcp_options) {
            return db_entry.os_name + "\nOS details: " + db_entry.os_details;
        }
    }
    return "Unknown OS";
}

std::string SynScanner::detect_os() {
    load_os_database();
    OSFingerprint target_fp = get_target_fingerprint();
    return "Running: " + match_fingerprint(target_fp);
}

bool TestPortConnection(std::string ip, int port) {
    struct sockaddr_in address;
    int myNetworkSocket = -1;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip.c_str());
    address.sin_port = htons(port);

    myNetworkSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (myNetworkSocket == -1) {
        std::cerr << "Socket creation failed on port " << port << std::endl;
        return false;
    }

    fcntl(myNetworkSocket, F_SETFL, O_NONBLOCK);
    connect(myNetworkSocket, (struct sockaddr *)&address, sizeof(address)); 

    fd_set fileDescriptorSet;
    struct timeval timeout;

    FD_ZERO(&fileDescriptorSet);
    FD_SET(myNetworkSocket, &fileDescriptorSet);
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    int connectionResponse = select(myNetworkSocket + 1, NULL, &fileDescriptorSet, NULL, &timeout);
    if (connectionResponse == 1) {
        int socketError;
        socklen_t len = sizeof socketError;
        getsockopt(myNetworkSocket, SOL_SOCKET, SO_ERROR, &socketError, &len);

        if (socketError == 0) {
            close(myNetworkSocket);
            return true;
        } else {
            close(myNetworkSocket);
            return false;
        }
    }
    close(myNetworkSocket);
    return false;
}

void ThreadTask(std::vector<int>* bufferArg, std::string hostNameArg, int port) {
    if (TestPortConnection(hostNameArg, port)) {
        std::lock_guard<std::mutex> lock(bufferLock);
        bufferArg->push_back(port);
    }
}

std::vector<int> SynScanner::syn_scan(int start_port, int end_port) {
    std::vector<std::thread*> portTests;
    std::vector<int> buffer;

    int numOfTasks = 500;  // Increase the number of concurrent threads

    for (int port = start_port; port <= end_port; port++) {
        portTests.push_back(new std::thread(ThreadTask, &buffer, target_ip, port));

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
