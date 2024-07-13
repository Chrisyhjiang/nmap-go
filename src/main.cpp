#include "syn_scanner.h"
#include "tcp_connect_scanner.h"
#include "packets/syn_packet.h"
#include "output.h"  // Include output header for printing results
#include <iostream>
#include <string>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstring>

std::string initialize_local_ip() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return "";
    }

    const char* kGoogleDnsIp = "8.8.8.8";
    uint16_t kDnsPort = 53;
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons(kDnsPort);

    int err = connect(sock, (const struct sockaddr*) &serv, sizeof(serv));
    if (err < 0) {
        std::cerr << "Error connecting to socket" << std::endl;
        close(sock);
        return "";
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);
    if (err < 0) {
        std::cerr << "Error getting socket name" << std::endl;
        close(sock);
        return "";
    }

    char buffer[INET_ADDRSTRLEN];
    const char* p = inet_ntop(AF_INET, &name.sin_addr, buffer, sizeof(buffer));
    if (p == nullptr) {
        std::cerr << "Error getting IP address" << std::endl;
        close(sock);
        return "";
    }

    close(sock);
    return buffer;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <target> <scan_type>" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    std::string scan_type = argv[2];
    std::string local_ip = initialize_local_ip();
    
    if (local_ip.empty()) {
        std::cerr << "Failed to initialize local IP address" << std::endl;
        return 1;
    }

    std::shared_ptr<Packet> syn_packet = std::make_shared<SYN_Packet>(local_ip, target);

    std::cout << "Starting scan using my_nmap..." << std::endl;
    std::vector<int> open_ports;
    if (scan_type == "syn") {
        std::cout << "Performing SYN scan on target: " << target << std::endl;
        SynScanner syn_scanner(target, syn_packet);
        open_ports = syn_scanner.scan(1, 1024);
    } else if (scan_type == "tcp") {
        std::cout << "Performing TCP connect scan on target: " << target << std::endl;
        TCPConnectScanner tcp_scanner(target, syn_packet);
        open_ports = tcp_scanner.scan(1, 1024);
    } else {
        std::cerr << "Unknown scan type: " << scan_type << std::endl;
        return 1;
    }
    Output::print_results(target, open_ports);
    std::cout << "Scan completed." << std::endl;
    return 0;
}
