#include <iostream>
#include <set>
#include <chrono>
#include <thread>
#include <atomic>
#include <tins/tins.h>

using namespace Tins;

class UDPScanner {
private:
    const int TIMEOUT = 2000; // Timeout in milliseconds
    const int MAX_RETRIES = 2;
    
    NetworkInterface iface;
    IPv4Address target_ip;
    PacketSender sender;
    std::atomic<bool> should_stop{false};

    bool scan_port(uint16_t port) {
        try {
            UDP udp = UDP(port, 12345);
            IP ip = IP(target_ip, iface.ipv4_address()) / udp / RawPDU("UDP Scan");
            
            for (int i = 0; i < MAX_RETRIES; ++i) {
                sender.send(ip);

                SnifferConfiguration config;
                config.set_timeout(TIMEOUT / 1000); // Convert to seconds
                config.set_promisc_mode(true);
                config.set_filter("icmp or udp and src host " + target_ip.to_string() + " and dst port 12345");

                Sniffer sniffer(iface.name(), config);

                auto start = std::chrono::steady_clock::now();

                while (true) {
                    PDU* response = sniffer.next_packet();
                    if (response) {
                        const IP* ip_layer = response->find_pdu<IP>();
                        const ICMP* icmp_layer = response->find_pdu<ICMP>();

                        if (icmp_layer && icmp_layer->type() == ICMP::DEST_UNREACHABLE && 
                            icmp_layer->code() == 3) { // Port Unreachable code is 3
                            std::cout << "Received ICMP port unreachable message." << std::endl;
                            return false; // Port is closed
                        }

                        if (ip_layer && ip_layer->src_addr() == target_ip) {
                            const UDP* udp_layer = response->find_pdu<UDP>();
                            if (udp_layer && udp_layer->sport() == port) {
                                std::cout << "Received UDP response from port " << port << "." << std::endl;
                                return true; // Port is open
                            }
                        }
                    }

                    auto elapsed = std::chrono::steady_clock::now() - start;
                    if (elapsed > std::chrono::milliseconds(TIMEOUT)) {
                        break;
                    }
                }
            }
            
            return true; // Assume open if no response after retries
        } catch (std::exception& e) {
            std::cerr << "Error scanning port " << port << ": " << e.what() << std::endl;
            return false;
        }
    }

public:
    UDPScanner(const IPv4Address& ip) : target_ip(ip), iface(NetworkInterface::default_interface()) {}

    void scan_port_5353(std::set<uint16_t>& open_ports) {
        uint16_t port = 5353;
        if (scan_port(port)) {
            open_ports.insert(port);
        }
    }

    void stop() {
        should_stop = true;
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <target_ip>" << std::endl;
        return 1;
    }

    try {
        IPv4Address target_ip(argv[1]);
        UDPScanner scanner(target_ip);
        std::set<uint16_t> open_ports;

        auto start_time = std::chrono::high_resolution_clock::now();

        std::thread scan_thread(&UDPScanner::scan_port_5353, &scanner, std::ref(open_ports));

        // Monitor progress and allow user to stop the scan
        while (scan_thread.joinable()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (std::cin.get() == 'q') {
                scanner.stop();
                break;
            }
        }

        scan_thread.join();

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

        std::cout << "\nScan completed in " << duration.count() << " seconds." << std::endl;
        std::cout << "Open ports:" << std::endl;
        for (uint16_t port : open_ports) {
            std::cout << port << std::endl;
        }

    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
