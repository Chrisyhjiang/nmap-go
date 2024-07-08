#include "../include/scanner.h"
#include "../include/output.h"
#include "../include/syn_scanner.h"
#include <iostream>
#include <vector>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <ip_address> <scan_type>" << std::endl;
        std::cout << "scan_type: tcp, syn, udp" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    std::string scan_type = argv[2];
    std::vector<int> open_ports;

    if (scan_type == "tcp") {
        Scanner scanner(target);
        open_ports = scanner.scan(1, 65535);  // Scan all ports
    } else if (scan_type == "syn") {
        SynScanner syn_scanner(target);
        open_ports = syn_scanner.syn_scan(1, 65535);  // Perform SYN scan on all ports
    } else if (scan_type == "udp") {
        // Placeholder for UDP scan implementation
        std::cout << "UDP scan is not implemented yet." << std::endl;
        return 1;
    } else {
        std::cout << "Unknown scan type: " << scan_type << std::endl;
        return 1;
    }

    Output::print_results(target, open_ports);

    return 0;
}
