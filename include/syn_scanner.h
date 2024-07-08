#ifndef SYN_SCANNER_H
#define SYN_SCANNER_H

#include <string>
#include <vector>
#include <random>
#include <tins/tins.h>

class SynScanner {
public:
    SynScanner(const std::string& target);
    ~SynScanner();
    std::vector<int> syn_scan(int start_port, int end_port);
    void run();

private:
    std::string target_;
    std::random_device rd; // Should be declared before `gen`
    std::mt19937 gen;
    std::uniform_int_distribution<> dis;
    Tins::NetworkInterface iface; // Should be declared before `sniffer`
    Tins::Sniffer sniffer;
    std::set<uint16_t> target_ports;
    std::set<std::string> open_hosts;

    std::string get_local_ip();
    void send_syn_packets(const std::vector<int>& ports);
    bool callback(Tins::PDU& pdu);
    void launch_sniffer();
    static void* thread_proc(void* arg);
    void start_clock();
    void end_clock();
    double program_duration;
    struct timespec start_time, finish_time;
};

#endif // SYN_SCANNER_H
