#include "udp_scanner.h"
#include <iostream>
#include <chrono>
#include <thread>

extern std::mutex cout_mutex; // Declare the mutex here

UDPScanner::UDPScanner(const IPv4Address& ip, uint16_t total_ports)
    : Scanner(ip, total_ports) {}

PortStatus UDPScanner::scan_port(uint16_t port) {
    try {
        std::vector<uint8_t> payload = payload_database.count(port) ? payload_database[port] : std::vector<uint8_t>();

        UDP udp = UDP(port, 12345);
        IP ip = IP(target_ip, iface.ipv4_address()) / udp;

        if (!payload.empty()) {
            ip /= RawPDU(payload.data(), payload.size());
        }

        bool port_open = false;

        for (int i = 0; i < MAX_RETRIES; ++i) {
            sender.send(ip);

            {
                std::unique_lock<std::mutex> lock(sniffer_mtx);
                sniffer_cv.wait(lock, [this]() { return active_sniffers < MAX_CONCURRENT_SNIFFERS; });
                ++active_sniffers;
            }

            SnifferConfiguration config;
            config.set_promisc_mode(true);
            std::string filter = "icmp or (udp and src host " + target_ip.to_string() + " and dst port 12345)";
            config.set_filter(filter);

            Sniffer sniffer(iface.name(), config);

            auto start = std::chrono::steady_clock::now();

            int fd = sniffer.get_fd();
            fd_set readfds;
            struct timeval timeout;
            timeout.tv_sec = TIMEOUT / 1000;
            timeout.tv_usec = (TIMEOUT % 1000) * 1000;

            while (true) {
                FD_ZERO(&readfds);
                FD_SET(fd, &readfds);

                int ret = select(fd + 1, &readfds, NULL, NULL, &timeout);

                if (ret > 0 && FD_ISSET(fd, &readfds)) {
                    PDU* response = sniffer.next_packet();
                    if (response) {
                        const IP* ip_layer = response->find_pdu<IP>();
                        const ICMP* icmp_layer = response->find_pdu<ICMP>();

                        if (icmp_layer && icmp_layer->type() == ICMP::DEST_UNREACHABLE &&
                            icmp_layer->code() == 3) {
                            {
                                std::lock_guard<std::mutex> lock(sniffer_mtx);
                                --active_sniffers;
                                sniffer_cv.notify_one();
                            }
                            return PortStatus::Closed;
                        }

                        if (ip_layer && ip_layer->src_addr() == target_ip) {
                            const UDP* udp_layer = response->find_pdu<UDP>();
                            if (udp_layer && udp_layer->sport() == port) {
                                port_open = true;
                                break;
                            }
                        }
                    }
                } else {
                    auto elapsed = std::chrono::steady_clock::now() - start;
                    if (elapsed > std::chrono::milliseconds(TIMEOUT)) {
                        break;
                    }
                }
            }

            {
                std::lock_guard<std::mutex> lock(sniffer_mtx);
                --active_sniffers;
                sniffer_cv.notify_one();
            }

            if (port_open) {
                break;
            }
        }

        return port_open ? PortStatus::Open : PortStatus::Filtered;
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
