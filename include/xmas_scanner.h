#ifndef XMAS_SCANNER_H
#define XMAS_SCANNER_H

#include "scanner.h"
#include <tins/tins.h>
#include <set>
#include <atomic>
#include <mutex>

class XmasScanner : public Scanner {
class XmasScanner : public Scanner {
public:
    XmasScanner(const Tins::IPv4Address& ip, uint16_t total_ports);
    PortStatus scan_port(uint16_t port) override;
    void scan_ports(uint16_t start_port, uint16_t end_port, std::set<uint16_t>& open_ports) override;
};

#endif // XMAS_SCANNER_H