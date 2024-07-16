#ifndef UDP_SCANNER_H
#define UDP_SCANNER_H

#include "scanner.h"

class UDPScanner : public Scanner {
private:
    static const int TIMEOUT = 500; // Timeout in milliseconds

protected:
    PortStatus scan_port(uint16_t port) override;

public:
    UDPScanner(const IPv4Address& ip, uint16_t total_ports);
    void scan_ports(uint16_t start_port, uint16_t end_port, std::set<uint16_t>& open_ports) override;
};

#endif // UDP_SCANNER_H