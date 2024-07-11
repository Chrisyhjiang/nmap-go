#pragma once
#include "scanner.h"

class TCPConnectScanner : public Scanner {
public:
    TCPConnectScanner(const std::string& target);
    std::vector<int> scan(int start_port, int end_port) override;

protected:
    bool is_port_open(int port) override;
};
