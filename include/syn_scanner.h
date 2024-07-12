#ifndef SYN_SCANNER_H
#define SYN_SCANNER_H

#include "scanner.h"
#include <vector>
#include <mutex>
#include <chrono>

class SynScanner : public Scanner {
public:
    SynScanner(const std::string& target);
    ~SynScanner() = default;

    std::vector<int> scan(int start_port, int end_port) override;
    bool is_port_open(int port) override;
    void send_packet(int sock, int port) override;

private:
    void scan_range(int start_port, int end_port, std::vector<int>& open_ports);
    int process_response(int sock);

    std::mutex bufferLock;
};

#endif // SYN_SCANNER_H
