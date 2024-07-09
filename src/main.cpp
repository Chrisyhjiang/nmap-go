#include "../include/scanner.h"
#include "../include/output.h"
#include "../include/syn_scanner.h"
#include "../include/ports.h"
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <unordered_map>

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 4) {
        std::cout << "Usage: " << argv[0] << " <ip_address> <scan_type> [--os]" << std::endl;
        std::cout << "scan_type: tcp, syn, udp" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    std::string scan_type = argv[2];
    bool estimate_os_flag = (argc == 4 && std::string(argv[3]) == "--os");

    std::vector<int> open_ports;

    auto start_time = std::chrono::high_resolution_clock::now();

    if (scan_type == "tcp") {
        Scanner scanner(target);
        open_ports = scanner.scan(1, 65535);  // Scan all ports
    } else if (scan_type == "syn") {
        SynScanner syn_scanner(target);
        open_ports = syn_scanner.syn_scan(1, 65535);  // Perform SYN scan on all ports

        if (estimate_os_flag) {
            std::string os_estimation = syn_scanner.detect_os();
            std::cout << os_estimation << std::endl;
        }
    } else if (scan_type == "udp") {
        std::cout << "UDP scan is not implemented yet." << std::endl;
        return 1;
    } else {
        std::cout << "Unknown scan type: " << scan_type << std::endl;
        return 1;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end_time - start_time;
    double latency = elapsed.count() / open_ports.size(); // Simulated average latency

    std::cout << "Starting my_nmap\n";
    std::cout << "Nmap scan report for " << target << "\n";
    std::cout << "Host is up (" << std::fixed << std::setprecision(6) << latency << "s latency).\n";
    std::cout << "Not shown: " << (65535 - open_ports.size()) << " closed tcp ports (conn-refused)\n";

    if (!open_ports.empty()) {
        std::cout << "PORT     STATE SERVICE\n";
        for (const int& port : open_ports) {
            std::string service = (commonPorts.find(port) != commonPorts.end()) ? commonPorts[port] : "unknown";
            std::cout << port << "/tcp open  " << service << "\n";
        }
    } else {
        std::cout << "All scanned ports are closed.\n";
    }

    std::cout << "\nNmap done: 1 IP address (1 host up) scanned in " << elapsed.count() << " seconds\n";

    return 0;
}
