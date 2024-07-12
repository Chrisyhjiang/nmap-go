#ifndef SYN_SCANNER_H
#define SYN_SCANNER_H

#include <string>
#include <vector>
#include <mutex>

class SynScanner {
public:
    SynScanner(const std::string& target);
    std::vector<int> scan(int start_port, int end_port);
    bool is_port_open(int port);

private:
    std::string target_;
    std::mutex bufferLock;

    uint16_t checksum(void* addr, int len);
    void send_syn_packet(int sock, const std::string& target_ip, int src_port, int dst_port);
    bool receive_response(int sock, int src_port, int dst_port);
};

#endif // SYN_SCANNER_H
