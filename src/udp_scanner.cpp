#include "udp_scanner.h"
#include <iostream>
#include <chrono>

UDPScanner::UDPScanner(const IPv4Address& ip, uint16_t total_ports)
    : Scanner(ip, total_ports) {}

PortStatus UDPScanner::scan_port(uint16_t port) {
    try {
        if (is_local_ip(target_ip)) {
            iface = NetworkInterface::default_interface();
        }

        UDP udp = UDP(port, 12345);
        IP ip = IP(target_ip, iface.ipv4_address()) / udp / RawPDU("UDP Scan");
        
        sender.send(ip);

        Sniffer sniffer(iface.name());
        sniffer.set_timeout(TIMEOUT);
        
        PDU* response = sniffer.next_packet();
        if (response) {
            const IP* ip_layer = response->find_pdu<IP>();
            const ICMP* icmp_layer = response->find_pdu<ICMP>();
            
            if (ip_layer && icmp_layer && 
                ip_layer->src_addr() == target_ip &&
                icmp_layer->type() == ICMP::DEST_UNREACHABLE &&
                icmp_layer->code() == ICMP::DEST_UNREACHABLE) {
                return PortStatus::Closed;
            }
        }
        
        return PortStatus::Open; // Assume open if no response
    } catch (std::exception& e) {
        std::cerr << "Error scanning port " << port << ": " << e.what() << std::endl;
        return PortStatus::Filtered;
    }
}

void UDPScanner::scan_ports(uint16_t start_port, uint16_t end_port, std::set<uint16_t>& open_ports) {
    for (uint16_t port = start_port; port <= end_port && !should_stop; ++port) {
        PortStatus status = scan_port(port);
        if (status == PortStatus::Open) {
            std::lock_guard<std::mutex> lock(mtx);
            open_ports.insert(port);
        }
        ++scanned_ports;
    }
}