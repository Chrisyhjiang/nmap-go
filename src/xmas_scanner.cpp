#include "xmas_scanner.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <future>
#include <atomic>
#include <tins/tins.h>

using namespace Tins;

XmasScanner::XmasScanner(const IPv4Address& ip, uint16_t total_ports)
    : Scanner(ip, total_ports) {}

void XmasScanner::scan_ports(uint16_t start_port, uint16_t end_port, std::set<uint16_t>& open_ports) {
    std::vector<uint16_t> ports_to_scan = {0, 1, 3306, 5000, 5001, 5002, 5003, 7000, 33060, 60869};

    for (uint16_t port : ports_to_scan) {
        if (should_stop) {
            break;
        }
        PortStatus status = scan_port(port);
        if (status == PortStatus::Open || status == PortStatus::OPEN_OR_FILTERED) {
            open_ports.insert(port);
        }
        ++scanned_ports;
    }
}

PortStatus XmasScanner::scan_port(uint16_t port) {
    try {
        // Craft the XMAS packet
        IP ip = IP(target_ip, iface.addresses().ip_addr) / TCP(port, 12345);
        TCP& tcp = ip.rfind_pdu<TCP>();
        tcp.flags(TCP::FIN | TCP::PSH | TCP::URG);

        // Set up the sniffer
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter("tcp and src host " + target_ip.to_string() + " and dst port 12345");
        Sniffer sniffer(iface.name(), config);

        // Send the packet
        sender.send(ip);

        // Use promise and future to handle the result
        std::promise<PortStatus> promise;
        std::future<PortStatus> future = promise.get_future();

        // Flag to indicate the sniffer thread should stop
        std::atomic<bool> stop_sniffer{false};

        // Start sniffing in a separate thread
        std::thread sniffer_thread([&sniffer, &promise, &stop_sniffer, this]() {
            PortStatus status = PortStatus::OPEN_OR_FILTERED;
            try {
                auto start_time = std::chrono::steady_clock::now();
                auto timeout_duration = std::chrono::milliseconds(2000);

                while (!stop_sniffer && (std::chrono::steady_clock::now() - start_time < timeout_duration)) {
                    const PDU* pdu = sniffer.next_packet();
                    if (pdu) {
                        const IP* ip = pdu->find_pdu<IP>();
                        const TCP* tcp = pdu->find_pdu<TCP>();
                        if (ip && tcp && ip->src_addr() == target_ip && tcp->dport() == 12345) {
                            if (tcp->get_flag(TCP::RST)) {
                                status = PortStatus::Closed;
                                break;
                            }
                        }
                    }
                }
                promise.set_value(status);
            } catch (const std::exception& e) {
                promise.set_value(PortStatus::Filtered); // Ensure promise is set in case of error
            }
        });

        // Wait for the result or timeout
        std::future_status status = future.wait_for(std::chrono::milliseconds(2000));
        if (status == std::future_status::timeout) {
            promise.set_value(PortStatus::OPEN_OR_FILTERED);
        }

        // Signal the sniffer thread to stop and join it
        stop_sniffer = true;
        sniffer_thread.join();

        PortStatus final_status = future.get();

        return final_status;
    } catch (const std::exception& e) {
        return PortStatus::Filtered;
    }
}
