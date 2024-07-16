#ifndef SYN_SCANNER_H
#define SYN_SCANNER_H

#include "scanner.h"

class SynScanner : public Scanner {
public:
    SynScanner(const IPv4Address& ip, uint16_t total_ports);
    PortStatus scan_port(uint16_t port) override;
    void scan_ports(uint16_t start_port, uint16_t end_port, std::set<uint16_t>& open_ports) override;
};

#endif // SYN_SCANNER_H
