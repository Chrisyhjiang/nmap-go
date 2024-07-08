#include "../include/syn_scanner.h"
#include <iostream>
#include <pthread.h>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <ifaddrs.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <iomanip>  // Include this for std::setprecision

using namespace Tins;

#define RATE_LIMIT 100

SynScanner::SynScanner(const std::string& target) 
    : target_(target), rd(), gen(rd()), dis(1024, 65535), iface(NetworkInterface::default_interface()), sniffer(NetworkInterface::default_interface().name()) {
}

SynScanner::~SynScanner() {}

std::string SynScanner::get_local_ip() {
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

            if (strcmp(ifa->ifa_name, "lo") != 0) {
                freeifaddrs(ifaddr);
                return std::string(host);
            }
        }
    }

    freeifaddrs(ifaddr);
    return "";
}

void SynScanner::send_syn_packets(const std::vector<int>& ports) {
    PacketSender sender;
    NetworkInterface::Info info = iface.addresses();
    IP ip = IP(target_, info.ip_addr) / TCP();
    TCP& tcp = ip.rfind_pdu<TCP>();
    tcp.set_flag(TCP::SYN, 1);
    tcp.sport(46156);

    unsigned rate_limit_counter = 1;
    open_hosts.clear();
    for (const auto& port : ports) {
        if (rate_limit_counter % RATE_LIMIT == 0)
            sleep(1);

        ip.dst_addr(target_);
        tcp.dport(port);
        sender.send(ip);

        rate_limit_counter = (rate_limit_counter + 1) % RATE_LIMIT;
    }

    tcp.set_flag(TCP::RST, 1);
    tcp.sport(*target_ports.begin());
    ip.src_addr(target_);

    EthernetII eth = EthernetII(info.hw_addr, info.hw_addr) / ip;
    sender.send(eth, iface);
}

void SynScanner::launch_sniffer() {
    sniffer.sniff_loop(make_sniffer_handler(this, &SynScanner::callback));
}

bool SynScanner::callback(PDU& pdu) {
    const IP& ip = pdu.rfind_pdu<IP>();
    const TCP& tcp = pdu.rfind_pdu<TCP>();

    if (target_ports.count(tcp.sport()) == 1) {
        std::string ip_address = ip.src_addr().to_string();

        if (tcp.get_flag(TCP::RST)) {
            if (tcp.get_flag(TCP::SYN))
                return false;
        } else if (tcp.flags() == (TCP::SYN | TCP::ACK)) {
            std::cout << ip_address << " (" << tcp.sport() << " open\n";
            open_hosts.insert(ip_address);
        }
    }
    return true;
}

void SynScanner::run() {
    start_clock();

    pthread_t thread;
    pthread_create(&thread, 0, &SynScanner::thread_proc, this);
    send_syn_packets(std::vector<int>(target_ports.begin(), target_ports.end()));

    void* dummy;
    pthread_join(thread, &dummy);

    std::cout << "\nTotal open hosts: " << open_hosts.size() << " host(s)" << std::endl;

    end_clock();
}

void* SynScanner::thread_proc(void* arg) {
    SynScanner* scanner = (SynScanner*)arg;
    scanner->launch_sniffer();

    return NULL;
}

void SynScanner::start_clock() {
    clock_gettime(CLOCK_MONOTONIC, &start_time);
}

void SynScanner::end_clock() {
    clock_gettime(CLOCK_MONOTONIC, &finish_time);
    program_duration = (finish_time.tv_sec - start_time.tv_sec);
    program_duration += (finish_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

    int hours_duration = program_duration / 3600;
    int mins_duration = (int)(program_duration / 60) % 60;
    double secs_duration = fmod(program_duration, 60);

    std::cout << "Scan duration: " << hours_duration << " hour(s) " << mins_duration << " min(s) " << std::setprecision(5) << secs_duration << " sec(s)\n";
}

std::vector<int> SynScanner::syn_scan(int start_port, int end_port) {
    for (int port = start_port; port <= end_port; ++port) {
        target_ports.insert(port);
    }

    run();

    std::vector<int> open_ports;
    for (const auto& host : open_hosts) {
        open_ports.push_back(std::stoi(host));
    }

    return open_ports;
}
