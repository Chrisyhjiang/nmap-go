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
        std::cout << "UDP scan is not implemented yet." << std::endl;
        return 1;
    } else {
        std::cout << "Unknown scan type: " << scan_type << std::endl;
        return 1;
    }

    std::cout << "Starting my_nmap\n";
    std::cout << "Nmap scan report for " << target << "\n";
    if (!open_ports.empty()) {
        std::cout << "Host is up.\n";
        std::cout << "Not shown: " << (65535 - open_ports.size()) << " closed ports\n";
        for (const int& port : open_ports) {
            std::cout << port << "/tcp open\n";
        }
    } else {
        std::cout << "All scanned ports are closed.\n";
    }

    return 0;
}
