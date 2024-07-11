#include "../include/tcp_connect_scanner.h"
#include "../include/syn_scanner.h"
#include <iostream>
#include <vector>
#include <string>

using namespace std;

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cout << "Usage: " << argv[0] << " <ip_address> <scan_type>" << std::endl;
        cout << "scan_type: tcp, syn" << std::endl;
        return 1;
    }

    string target = argv[1];
    string scan_type = argv[2];
    vector<int> open_ports;

    if (scan_type == "tcp") {
        TCPConnectScanner scanner(target);
        open_ports = scanner.scan(1, 65535);  // Scan all ports
    } else if (scan_type == "syn") {
        SynScanner syn_scanner(target);
        open_ports = syn_scanner.scan(1, 65535);  // Perform SYN scan on all ports
    } else {
        cout << "Unknown scan type: " << scan_type << std::endl;
        return 1;
    }

    cout << "Starting my_nmap\n";
    cout << "Nmap scan report for " << target << "\n";
    if (!open_ports.empty()) {
        cout << "Host is up.\n";
        cout << "Not shown: " << (65535 - open_ports.size()) << " closed ports\n";
        for (const int& port : open_ports) {
            cout << port << "/tcp open\n";
        }
    } else {
        cout << "All scanned ports are closed.\n";
    }
    return 0;
}
