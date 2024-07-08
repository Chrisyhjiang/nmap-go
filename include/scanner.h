#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>
#include <random>

class Scanner {
public:
    Scanner(const std::string& target);
    ~Scanner();
    std::vector<int> scan(int start_port, int end_port);
    std::vector<int> syn_scan(int start_port, int end_port);

private:
    std::string target_;
    int raw_socket_;
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<> dis;

    void initialize_socket();
    bool is_port_open(int port);
    std::string get_local_ip();
    void send_syn_packet(int port);
    std::vector<int> receive_syn_ack(const std::vector<int>& ports, int timeout_ms);
    unsigned short checksum(unsigned short *ptr, int nbytes);
    unsigned short tcp_checksum(struct iphdr *iph, struct tcphdr *tcph);
};

#endif // SCANNER_H
