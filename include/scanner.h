#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>
#include "os_detector.h"

class Scanner {
public:
    Scanner(const std::string& target);
    virtual ~Scanner() = default;
    virtual std::vector<int> scan(int start_port, int end_port) = 0;
    virtual bool is_port_open(int port) = 0;

    std::string detect_os();
    void send_decoy_packets(const std::string& real_src_ip, int src_port, int dst_port);

protected:
    std::string target_;
    OSDetector os_detector;  // OS detector instance

private:
    std::vector<std::vector<char>> fragment_packet(const std::vector<char>& packet, int fragment_size);
    void send_packet(const std::string& src_ip, int src_port, int dst_port);
};

#endif // SCANNER_H
