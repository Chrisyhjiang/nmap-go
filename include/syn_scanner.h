#ifndef SYN_SCANNER_H
#define SYN_SCANNER_H

#include "scanner.h"
#include <vector>
#include <mutex>

class SynScanner : public Scanner {
public:
    SynScanner(const std::string& target);
    ~SynScanner() = default;

    std::vector<int> scan(int start_port, int end_port) override;
    bool is_port_open(int port) override;
    void send_packet(int src_port, int dst_port);  // Add this line

private:
    std::mutex bufferLock;
};

#endif // SYN_SCANNER_H
