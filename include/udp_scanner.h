#ifndef UDP_SCANNER_H
#define UDP_SCANNER_H

#include "scanner.h"
#include <unordered_map>
#include <condition_variable>
#include <queue>

class UDPScanner : public Scanner {
private:
    const int TIMEOUT = 100; // Timeout in milliseconds
    const int MAX_RETRIES = 3;
    const int MAX_THREADS = 100; // Maximum number of concurrent threads
    const int MAX_CONCURRENT_SNIFFERS = 10; // Maximum number of concurrent sniffers

    std::unordered_map<uint16_t, std::vector<uint8_t>> payload_database;
    std::condition_variable cv;
    bool finished = false;

    int active_sniffers = 0;
    std::mutex sniffer_mtx;
    std::condition_variable sniffer_cv;

    std::queue<uint16_t> port_queue; // Add the missing port_queue

    PortStatus scan_port(uint16_t port) override;

    void worker_thread(std::set<uint16_t>& open_ports);

public:
    UDPScanner(const IPv4Address& ip, uint16_t total_ports);
    void scan_ports(uint16_t start_port, uint16_t end_port, std::set<uint16_t>& open_ports) override;
};

#endif // UDP_SCANNER_H
