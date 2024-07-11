#pragma once
#include "scanner.h"

class SynScanner : public Scanner {
public:
    SynScanner(const std::string& target);

    std::vector<int> scan(int start_port, int end_port) override;

protected:
    bool is_port_open(int port) override;
};
