#pragma once
#include <string>
#include <vector>

class Scanner {
public:
    Scanner(const std::string& target);
    std::vector<int> scan(int start_port, int end_port);

private:
    std::string target_;
    bool is_port_open(int port);
};
