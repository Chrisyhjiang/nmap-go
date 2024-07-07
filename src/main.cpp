#include "scanner.h"
#include "output.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <ip_address> <scan_type>" << std::endl;
        std::cout << "scan_type: tcp, syn, udp" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    std::string scan_type = argv[2];
    Scanner scanner(target);
    std::vector<int> open_ports;

    if (scan_type == "tcp") {
        open_ports = scanner.scan(1, 65535);  // Scan all ports
    } else if (scan_type == "syn") {
        open_ports = scanner.syn_scan(1, 65535);  // Perform SYN scan on all ports
    } else if (scan_type == "udp") {
        // open_ports = scanner.udp_scan(1, 65535);  // Placeholder for UDP scan implementation
    } else {
        std::cout << "Unknown scan type: " << scan_type << std::endl;
        return 1;
    }

    Output::print_results(target, open_ports);

    return 0;
}
