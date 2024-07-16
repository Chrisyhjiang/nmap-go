#include "syn_scanner.h"
#include <iostream>
#include <tins/tins.h>

using namespace Tins;

SynScanner::SynScanner(const IPv4Address& ip, uint16_t total_ports) : Scanner(ip, total_ports) {}

PortStatus SynScanner::scan_port(uint16_t port) {
    try {
        IP ip = IP(target_ip, iface.addresses().ip_addr) / TCP(port, 12345);
        TCP& tcp = ip.rfind_pdu<TCP>();
        tcp.set_flag(TCP::SYN, 1);
        tcp.set_flag(TCP::ACK, 0);

        SnifferConfiguration config;
        config.set_timeout(2); // Set a moderate timeout
        config.set_promisc_mode(true);
        config.set_filter("tcp and src host " + target_ip.to_string() + " and dst port 12345");
        Sniffer sniffer(iface.name(), config);

        sender.send(ip);

        PortStatus status = PortStatus::Filtered;

        sniffer.sniff_loop([&](PDU& pdu) {
            if (should_stop) return false;
            const IP* ip = pdu.find_pdu<IP>();
            const TCP* tcp = pdu.find_pdu<TCP>();
            if (ip && tcp && ip->src_addr() == target_ip && tcp->sport() == port && tcp->dport() == 12345) {
                if (tcp->get_flag(TCP::SYN) && tcp->get_flag(TCP::ACK)) {
                    status = PortStatus::Open;
                } else if (tcp->get_flag(TCP::RST)) {
                    status = PortStatus::Closed;
                }
                return false;
            }
            return true;
        });

        return status;
    } catch (const std::exception& e) {
        std::cerr << "Error scanning port " << port << ": " << e.what() << std::endl;
        return PortStatus::Filtered;
    }
}

void SynScanner::scan_ports(uint16_t start_port, uint16_t end_port, std::set<uint16_t>& open_ports) {
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
