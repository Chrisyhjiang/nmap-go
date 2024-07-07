#include "scanner.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <mutex>
#include <iostream>
#include <netinet/in.h>

// Manual definitions of required structures
struct iphdr {
    unsigned int ihl:4;
    unsigned int version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t res2:2;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

Scanner::Scanner(const std::string& target) : target_(target) {}

std::vector<int> Scanner::scan(int start_port, int end_port) {
    std::vector<int> open_ports;
    std::mutex mutex;

    auto scan_range = [&](int start, int end) {
        for (int port = start; int(port) <= end; ++port) {
            if (is_port_open(port)) {
                std::lock_guard<std::mutex> lock(mutex);
                open_ports.push_back(port);
            }
        }
    };

    const int num_threads = 4;
    std::vector<std::thread> threads;
    int ports_per_thread = (end_port - start_port + 1) / num_threads;

    for (int i = 0; i < num_threads; ++i) {
        int thread_start = start_port + i * ports_per_thread;
        int thread_end = (i == num_threads - 1) ? end_port : thread_start + ports_per_thread - 1;
        threads.emplace_back(scan_range, thread_start, thread_end);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    return open_ports;
}

bool Scanner::is_port_open(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, target_.c_str(), &server_addr.sin_addr);

    int result = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    close(sock);

    return result == 0;
}

bool Scanner::is_port_open_syn(int port) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Failed to create socket");
        return false;
    }

    char packet[4096];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(target_.c_str());

    memset(packet, 0, 4096);

    // IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = INADDR_ANY;
    iph->daddr = sin.sin_addr .s_addr;

    // IP checksum
    iph->check = checksum((unsigned short *)packet, sizeof(struct iphdr));

    // TCP Header
    tcph->source = htons(1234);  // Source port
    tcph->dest = htons(port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // TCP checksum calculation
    tcph->check = tcp_checksum(iph, tcph);

    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        close(sock);
        return false;
    }

    // Debugging: print packet size and destination
    std::cout << "Sending packet to " << target_ << " on port " << port << " with size " << ntohs(iph->tot_len) << std::endl;

    if (sendto(sock, packet, ntohs(iph->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto failed");
        close(sock);
        return false;
    }

    struct sockaddr_in source_addr;
    int saddr_size = sizeof(source_addr);
    char buffer[4096];
    int data_size = recvfrom(sock, buffer, 4096, 0, (struct sockaddr *)&source_addr, (socklen_t*)&saddr_size);

    if (data_size < 0) {
        perror("recvfrom failed");
        close(sock);
        return false;
    }

    struct iphdr *iph_reply = (struct iphdr *)buffer;
    struct tcphdr *tcph_reply = (struct tcphdr *)(buffer + iph_reply->ihl * 4);

    close(sock);

    return (tcph_reply->syn == 1 && tcph_reply->ack == 1);
}


unsigned short Scanner::checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return answer;
}

unsigned short Scanner::tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    struct pseudo_header {
        unsigned int source_address;
        unsigned int dest_address;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
    } psh;

    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = new char[psize];

    memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    unsigned short checksum = this->checksum((unsigned short*)pseudogram, psize);

    delete[] pseudogram;
    return checksum;
}

std::vector<int> Scanner::syn_scan(int start_port, int end_port) {
    std::vector<int> open_ports;
    std::mutex mutex;

    auto scan_range = [&](int start, int end) {
        for (int port = start; port <= end; ++port) {
            if (is_port_open_syn(port)) {
                std::lock_guard<std::mutex> lock(mutex);
                open_ports.push_back(port);
            }
        }
    };

    const int num_threads = 4;
    std::vector<std::thread> threads;
    int ports_per_thread = (end_port - start_port + 1) / num_threads;

    for (int i = 0; i < num_threads; ++i) {
        int thread_start = start_port + i * ports_per_thread;
        int thread_end = (i == num_threads - 1) ? end_port : thread_start + ports_per_thread - 1;
        threads.emplace_back(scan_range, thread_start, thread_end);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    return open_ports;
}
