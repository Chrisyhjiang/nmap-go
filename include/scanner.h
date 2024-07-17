#ifndef SCANNER_H
#define SCANNER_H

#include <tins/tins.h>
#include <set>
#include <mutex>
#include <atomic>
#include <vector>
#include <thread>
#include <chrono>
#include <condition_variable>
#include <queue>

using namespace Tins;

enum class PortStatus {
    Open,
    Closed,
    Filtered
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
    uint16_t get_scanned_ports() const { return scanned_ports.load(); }
    uint16_t get_total_ports() const { return total_ports; }
};

extern std::mutex cout_mutex; // Add this line

#endif // SCANNER_H
