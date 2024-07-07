#include "output.h"
#include "services.h"
#include <iostream>
#include <iomanip>
#include <unordered_map>

namespace Output {
    void print_results(const std::string& target, const std::vector<int>& open_ports) {
        std::cout << "Open ports for " << target << ":\n";
        std::cout << std::left << std::setw(10) << "PORT" << std::setw(10) << "STATE" << std::setw(20) << "SERVICE" << "\n";
        for (int port : open_ports) {
            std::string service = "unknown";
            auto it = port_to_service.find(port);
            if (it != port_to_service.end()) {
                service = it->second;
            }
            std::cout << std::left << std::setw(10) << (std::to_string(port) + "/tcp") << std::setw(10) << "open" << std::setw(20) << service << "\n";
        }
    }
}
