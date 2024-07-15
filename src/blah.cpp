#include <tins/tins.h>
#include <iostream>
#include <chrono>
#include <set>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>
#include <algorithm>

using namespace Tins;

enum class PortStatus {
    Open,
    Closed,
    Filtered
};

class SynScanner {
private:
    NetworkInterface iface;
    IPv4Address target_ip;
    PacketSender sender;
    std::mutex mtx;
    std::atomic<uint16_t> scanned_ports{0};
    std::atomic<bool> should_stop{false};
    uint16_t total_ports;

    bool is_local_ip(const IPv4Address& ip) {
        std::set<IPv4Address> local_ips;
        for (const auto& iface : NetworkInterface::all()) {
            local_ips.insert(iface.addresses().ip_addr);
        }
        return local_ips.find(ip) != local_ips.end();
    }

    PortStatus scan_port(uint16_t port) {
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

public:
    SynScanner(const IPv4Address& ip, uint16_t total_ports) : target_ip(ip), total_ports(total_ports) {
        try {
            if (is_local_ip(target_ip)) {
                iface = NetworkInterface("lo0");
            } else {
                iface = NetworkInterface::default_interface();
            }
            sender = PacketSender(iface.name());
            std::cout << "Using interface: " << iface.name() << " with IP: " << iface.addresses().ip_addr << std::endl;
        } catch (std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            throw;
        }
    }

    void scan_ports(uint16_t start_port, uint16_t end_port, std::set<uint16_t>& open_ports) {
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

    void stop() {
        should_stop = true;
    }

    void print_progress() {
        int bar_width = 70;
        while (scanned_ports < total_ports) {
            double progress = (double)scanned_ports / total_ports;
            std::cout << "[";
            int pos = bar_width * progress;
            for (int i = 0; i < bar_width; ++i) {
                if (i < pos) std::cout << "=";
                else if (i == pos) std::cout << ">";
                else std::cout << " ";
            }
            std::cout << "] " << int(progress * 100.0) << " %\r";
            std::cout.flush();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        std::cout << "[";
        for (int i = 0; i < bar_width; ++i) {
            std::cout << "=";
        }
        std::cout << "] 100 %\n"; // Ensure the progress bar shows 100% completion
    }
};

int main() {
    try {
        IPv4Address target_ip("10.0.0.78");
        uint16_t total_ports = 65535;  // Total number of ports
        SynScanner scanner(target_ip, total_ports);

        std::set<uint16_t> open_ports;
        const int num_threads = 64;  // Increased number of threads
        std::vector<std::thread> threads;

        auto start_time = std::chrono::high_resolution_clock::now();

        // Start the progress bar thread
        std::thread progress_thread(&SynScanner::print_progress, &scanner);

        uint16_t ports_per_thread = total_ports / num_threads;
        for (int i = 0; i < num_threads; ++i) {
            uint16_t start_port = i * ports_per_thread;
            uint16_t end_port = (i == num_threads - 1) ? 65535 : start_port + ports_per_thread - 1;
            threads.emplace_back(&SynScanner::scan_ports, &scanner, start_port, end_port, std::ref(open_ports));
        }

        for (auto& thread : threads) {
            thread.join();
        }

        scanner.stop();  // Stop the progress bar
        progress_thread.join();  // Ensure the progress thread is completed

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

        std::cout << "Scan completed in " << duration.count() << " seconds." << std::endl;
        std::cout << "Open ports: ";
        for (uint16_t port : open_ports) {
            std::cout << port << " ";
        }
        std::cout << std::endl;

    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
