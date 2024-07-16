#include "tcp_connect_scanner.h"
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

TCPConnectScanner::TCPConnectScanner(const IPv4Address& ip, uint16_t total_ports) : Scanner(ip, total_ports) {}

PortStatus TCPConnectScanner::scan_port(uint16_t port) {
    int sockfd;
    struct sockaddr_in target;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return PortStatus::Filtered;
    }

    target.sin_family = AF_INET;
    target.sin_addr.s_addr = inet_addr(target_ip.to_string().c_str());
    target.sin_port = htons(port);

    int result = connect(sockfd, (struct sockaddr *)&target, sizeof(target));
    close(sockfd);

    if (result == 0) {
        return PortStatus::Open;
    } else {
        if (errno == ECONNREFUSED) {
            return PortStatus::Closed;
        } else {
            return PortStatus::Filtered;
        }
    }
}

void TCPConnectScanner::scan_ports(uint16_t start_port, uint16_t end_port, std::set<uint16_t>& open_ports) {
    for (uint16_t port = start_port; port <= end_port && !should_stop; ++port) {
        PortStatus status = scan_port(port);
        if (status == PortStatus::Open) {
            std::lock_guard<std::mutex> lock(mtx);
            if (open_ports.insert(port).second) {
                std::cout << "Port " << port << " is open" << std::endl;
            }
        }
        ++scanned_ports;
        if (scanned_ports >= total_ports) {
            should_stop = true;
            break;
        }
    }
}
