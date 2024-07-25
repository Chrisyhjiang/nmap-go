#ifndef SCANNER_H
#define SCANNER_H

#include <tins/tins.h>
#include <set>
#include <mutex>
#include <atomic>
#include <vector>
#include <thread>
#include <chrono>

using namespace Tins;

enum class PortStatus {
    Open,
    Closed,
    Filtered, 
    OPEN_OR_FILTERED
};

class Scanner {
protected:
    NetworkInterface iface;
    IPv4Address target_ip;
    PacketSender sender;
    std::mutex mtx;
    std::atomic<uint16_t> scanned_ports{0};
    std::atomic<bool> should_stop{false};
    uint16_t total_ports;

    virtual bool is_local_ip(const IPv4Address& ip);
    virtual PortStatus scan_port(uint16_t port) = 0; // Pure virtual function

public:
    Scanner(const IPv4Address& ip, uint16_t total_ports);
    virtual ~Scanner() {}  // Virtual destructor
    virtual void scan_ports(uint16_t start_port, uint16_t end_port, std::set<uint16_t>& open_ports) = 0; // Pure virtual function
    void stop();
    void print_progress();
};

#endif // SCANNER_H
