#include "scanner.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <mutex>
#include <iostream>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <fcntl.h>
#include <chrono>
#include <vector>
#include <algorithm>
#include <random>
#include <atomic>
#include <unordered_map>

using namespace std;

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

Scanner::Scanner(const std::string& target) : target_(target), gen(rd()), dis(1024, 65535) {
    initialize_socket();
}

Scanner::~Scanner() {
    if (raw_socket_ >= 0) {
        close(raw_socket_);
    }
}

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

std::string Scanner::get_local_ip() {
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }

            // Skip loopback interface
            if (strcmp(ifa->ifa_name, "lo") != 0) {
                freeifaddrs(ifaddr);
                return std::string(host);
            }
        }
    }

    freeifaddrs(ifaddr);
    return "";
}

void Scanner::initialize_socket() {
    raw_socket_ = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket_ < 0) {
        throw std::runtime_error("Failed to create raw socket");
    }
    int one = 1;
    if (setsockopt(raw_socket_, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        throw std::runtime_error("Failed to set IP_HDRINCL");
    }
    // Set socket to non-blocking mode
    int flags = fcntl(raw_socket_, F_GETFL, 0);
    fcntl(raw_socket_, F_SETFL, flags | O_NONBLOCK);
}

void Scanner::send_syn_packet(int port) {
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    inet_pton(AF_INET, target_.c_str(), &sin.sin_addr);

    memset(packet, 0, sizeof(packet));

    // IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(dis(gen));
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(get_local_ip().c_str());
    iph->daddr = sin.sin_addr.s_addr;

    // TCP Header
    tcph->source = htons(dis(gen));
    tcph->dest = htons(port);
    tcph->seq = htonl(dis(gen));
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(64240);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // Calculate checksums
    iph->check = checksum((unsigned short *)packet, iph->tot_len);
    tcph->check = tcp_checksum(iph, tcph);

    sendto(raw_socket_, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
}

std::vector<int> Scanner::receive_syn_ack(const std::vector<int>& ports, int timeout_ms) {
    std::vector<int> open_ports;
    char buffer[4096];
    struct sockaddr_in source_addr;
    int saddr_size = sizeof(source_addr);
    fd_set readfds;
    struct timeval tv;
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start).count() < timeout_ms) {
        FD_ZERO(&readfds);
        FD_SET(raw_socket_, &readfds);
        tv.tv_sec = 0;
        tv.tv_usec = 10000; // 10ms

        int result = select(raw_socket_ + 1, &readfds, NULL, NULL, &tv);
        if (result > 0) {
            int data_size = recvfrom(raw_socket_, buffer, 4096, 0, (struct sockaddr *)&source_addr, (socklen_t*)&saddr_size);
            if (data_size > 0) {
                struct iphdr *iph_reply = (struct iphdr *)buffer;
                struct tcphdr *tcph_reply = (struct tcphdr *)(buffer + iph_reply->ihl * 4);
                if (tcph_reply->syn == 1 && tcph_reply->ack == 1) {
                    int port = ntohs(tcph_reply->source);
                    if (std::find(ports.begin(), ports.end(), port) != ports.end()) {
                        open_ports.push_back(port);
                    }
                }
            }
        }
    }
    return open_ports;
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
    std::vector<int> ports_to_scan;
    for (int port = start_port; port <= end_port; ++port) {
        ports_to_scan.push_back(port);
    }

    const int BATCH_SIZE = 1000;
    const int MAX_RETRIES = 3;
    const int INITIAL_TIMEOUT_MS = 100;

    std::mutex mutex;
    std::atomic<int> active_threads(0);
    const int MAX_THREADS = std::thread::hardware_concurrency();

    auto scan_batch = [&](const std::vector<int>& batch) {
        std::vector<int> batch_open_ports;
        std::unordered_map<int, int> retries;
        std::unordered_map<int, std::chrono::steady_clock::time_point> last_sent;

        for (int port : batch) {
            send_syn_packet(port);
            last_sent[port] = std::chrono::steady_clock::now();
        }

        int timeout_ms = INITIAL_TIMEOUT_MS;
        while (!batch.empty()) {
            auto response_ports = receive_syn_ack(batch, timeout_ms);
            for (int port : response_ports) {
                batch_open_ports.push_back(port);
                retries.erase(port);
                last_sent.erase(port);
            }

            auto now = std::chrono::steady_clock::now();
            for (auto it = last_sent.begin(); it != last_sent.end();) {
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second).count() > timeout_ms) {
                    if (retries[it->first] < MAX_RETRIES) {
                        send_syn_packet(it->first);
                        it->second = now;
                        retries[it->first]++;
                        timeout_ms = std::min(timeout_ms * 2, 1000); // Exponential backoff, max 1 second
                        ++it;
                    } else {
                        it = last_sent.erase(it);
                    }
                } else {
                    ++it;
                }
            }
        }

        std::lock_guard<std::mutex> lock(mutex);
        open_ports.insert(open_ports.end(), batch_open_ports.begin(), batch_open_ports.end());
        --active_threads;
    };

    for (int i = 0; i < ports_to_scan.size(); i += BATCH_SIZE) {
        int batch_end = std::min(i + BATCH_SIZE, (int)ports_to_scan.size());
        std::vector<int> batch(ports_to_scan.begin() + i, ports_to_scan.begin() + batch_end);

        while (active_threads >= MAX_THREADS) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        ++active_threads;
        std::thread(scan_batch, batch).detach();
    }

    while (active_threads > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return open_ports;
}
