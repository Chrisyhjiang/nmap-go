#include "../include/tcp_connect_scanner.h"
#include "../include/syn_scanner.h"
#include <iostream>
#include <vector>
#include <string>
#include <memory>

using namespace std;

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage: " << argv[0] << " <ip_address> <scan_type> [--os-detect]" << std::endl;
        cout << "scan_type: tcp, syn" << std::endl;
        return 1;
    }

    string target = argv[1];
    string scan_type = argv[2];
    bool os_detect = false;

    if (argc == 4 && string(argv[3]) == "--os") {
        os_detect = true;
    }

    unique_ptr<Scanner> scanner;

    if (scan_type == "tcp") {
        scanner = make_unique<TCPConnectScanner>(target);
    } else if (scan_type == "syn") {
        scanner = make_unique<SynScanner>(target);
    } else {
        cout << "Unknown scan type: " << scan_type << std::endl;
        return 1;
    }

    if (os_detect) {
        string os_info = scanner->detect_os();
        cout << "OS Detection: " << os_info << std::endl;
    }

    vector<int> open_ports = scanner->scan(1, 65535);  // Scan all ports

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
