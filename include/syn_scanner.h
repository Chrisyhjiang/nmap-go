#ifndef SYN_SCANNER_H
#define SYN_SCANNER_H

#include <string>
#include <vector>

class SynScanner {
public:
    SynScanner(const std::string& target);
    std::vector<int> syn_scan(int start_port, int end_port);
    std::string estimate_os(const std::vector<int>& open_ports); // OS estimation method
private:
    std::string target_ip;
};

#endif // SYN_SCANNER_H
