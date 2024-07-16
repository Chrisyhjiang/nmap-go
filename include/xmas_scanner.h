#ifndef XMAS_SCANNER_H
#define XMAS_SCANNER_H

#include "scanner.h"

class XMASScanner : public Scanner {
public:
    XMASScanner(const IPv4Address& ip, uint16_t total_ports);
    PortStatus scan_port(uint16_t port) override;
    void scan_ports(uint16_t start_port, uint16_t end_port, std::set<uint16_t>& open_ports) override;
};

#endif // XMAS_SCANNER_H
