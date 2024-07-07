#pragma once
#include <string>
#include <vector>

// Forward declarations
struct iphdr;
struct tcphdr;

class Scanner {
public:
    Scanner(const std::string& target);
    std::vector<int> scan(int start_port, int end_port);
    std::vector<int> syn_scan(int start_port, int end_port);
    std::vector<int> udp_scan(int start_port, int end_port);  // Placeholder for UDP scan

private:
    std::string target_;
    bool is_port_open(int port);
    bool is_port_open_syn(int port);
    bool is_port_open_udp(int port);  // Placeholder for UDP port check
    unsigned short checksum(unsigned short *ptr, int nbytes);
    unsigned short tcp_checksum(struct iphdr *iph, struct tcphdr *tcph);
};
