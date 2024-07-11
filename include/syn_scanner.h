#ifndef SYN_SCANNER_H
#define SYN_SCANNER_H

#include "scanner.h"
#include <string>
#include <vector>

class SynScanner : public Scanner {
public:
    SynScanner(const std::string& target);
    std::vector<int> scan(int start_port, int end_port) override;

private:
    bool is_port_open(int port) override;
};

#endif // SYN_SCANNER_H
