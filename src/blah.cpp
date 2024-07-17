#include <iostream>
#include <set>
#include <chrono>
#include <sys/select.h>
#include <tins/tins.h>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <vector>
#include <atomic>
#include <condition_variable>
#include <queue>

using namespace Tins;
using namespace std::chrono;
using namespace std;

class UDPScanner {
private:
    const int TIMEOUT = 100; // Timeout in milliseconds
    const int MAX_RETRIES = 3;
    const int MAX_THREADS = 100; // Maximum number of concurrent threads
    const int MAX_CONCURRENT_SNIFFERS = 10; // Maximum number of concurrent sniffers

    NetworkInterface iface;
    IPv4Address target_ip;
    PacketSender sender;

    std::unordered_map<uint16_t, std::vector<uint8_t>> payload_database = {
        {53, {0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}, // DNS query
        {161, {0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00}}, // SNMP GET
        {5353, {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01}}, // mDNS query
        {123, {0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}, // NTP query
        {137, {0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01}}, // NetBIOS Name Service query
        {500, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84}}, // IKE query
        {520, {0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}}, // RIP query
        {1645, {0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}, // RADIUS Access-Request
        {1812, {0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}, // RADIUS Access-Request (alternative port)
        {1900, {0x4d, 0x2d, 0x53, 0x45, 0x41, 0x52, 0x43, 0x48, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x32, 0x33, 0x39, 0x2e, 0x32, 0x35, 0x35, 0x2e, 0x32, 0x35, 0x35, 0x2e, 0x32, 0x35, 0x30, 0x3a, 0x31, 0x39, 0x30, 0x30, 0x0d, 0x0a, 0x4d, 0x61, 0x6e, 0x3a, 0x20, 0x22, 0x73, 0x73, 0x64, 0x70, 0x3a, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x22, 0x0d, 0x0a, 0x4d, 0x58, 0x3a, 0x20, 0x31, 0x0d, 0x0a, 0x53, 0x54, 0x3a, 0x20, 0x75, 0x72, 0x6e, 0x3a, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x73, 0x2d, 0x75, 0x70, 0x6e, 0x70, 0x2d, 0x6f, 0x72, 0x67, 0x3a, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x3a, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x47, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x3a, 0x31, 0x0d, 0x0a, 0x0d, 0x0a}}, // UPnP discovery
        {4500, {0x00, 0x00, 0x00, 0x00}}, // IPsec NAT Traversal
        {5060, {0x4f, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x53, 0x20, 0x73, 0x69, 0x70, 0x3a, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x20, 0x53, 0x49, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x56, 0x69, 0x61, 0x3a, 0x20, 0x53, 0x49, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x2f, 0x55, 0x44, 0x50, 0x20, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x3b, 0x62, 0x72, 0x61, 0x6e, 0x63, 0x68, 0x3d, 0x7a, 0x39, 0x68, 0x47, 0x34, 0x62, 0x4b, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x0d, 0x0a, 0x46, 0x72, 0x6f, 0x6d, 0x3a, 0x20, 0x73, 0x69, 0x70, 0x70, 0x40, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x0d, 0x0a, 0x54, 0x6f, 0x3a, 0x20, 0x73, 0x69, 0x70, 0x70, 0x40, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x0d, 0x0a, 0x43, 0x61, 0x6c, 0x6c, 0x2d, 0x49, 0x44, 0x3a, 0x20, 0x31, 0x0d, 0x0a, 0x43, 0x53, 0x65, 0x71, 0x3a, 0x20, 0x31, 0x20, 0x4f, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x53, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x63, 0x74, 0x3a, 0x20, 0x73, 0x69, 0x70, 0x3a, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x0d, 0x0a, 0x4d, 0x61, 0x78, 0x2d, 0x46, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x73, 0x3a, 0x20, 0x37, 0x30, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x30, 0x0d, 0x0a, 0x0d, 0x0a}}, // SIP OPTIONS request
        {69, {0x00, 0x01, 0x66, 0x69, 0x6c, 0x65, 0x00, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00}}, // TFTP Read Request
        {37, {0x00, 0x00, 0x00, 0x00}}, // Time Protocol
        {7, {0x50, 0x49, 0x4e, 0x47}}, // Echo Protocol
        {67, {0x01, 0x01, 0x06, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}}, // DHCP Discover
        {19, {0x00, 0x00, 0x00, 0x00}}, // Character Generator Protocol (CHARGEN)
        {2000, {0x00, 0x01, 0x02, 0x03}}, // Cisco Skinny Client Control Protocol (SCCP)
        {5355, {0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}} // Link-Local Multicast Name Resolution (LLMNR)
    };
    std::mutex mtx;
    std::atomic<int> scanned_ports{0};
    int total_ports;

    std::queue<uint16_t> port_queue;
    std::condition_variable cv;
    bool finished = false;

    int active_sniffers = 0;
    std::mutex sniffer_mtx;
    std::condition_variable sniffer_cv;

    bool scan_port(uint16_t port) {
        try {
            vector<uint8_t> payload = payload_database.count(port) ? payload_database[port] : vector<uint8_t>();

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

                auto start = steady_clock::now();

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
                                return false;
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
                        auto elapsed = steady_clock::now() - start;
                        if (elapsed > milliseconds(TIMEOUT)) {
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

            {
                std::lock_guard<std::mutex> lock(mtx);
                scanned_ports++;
            }

            return port_open;
        } catch (std::exception& e) {
            std::cerr << "Error scanning port " << port << ": " << e.what() << std::endl;
            return false;
        }
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

    void worker_thread(std::set<uint16_t>& open_ports) {
        while (true) {
            uint16_t port;
            {
                std::unique_lock<std::mutex> lock(mtx);
                cv.wait(lock, [this]() { return !port_queue.empty() || finished; });
                if (port_queue.empty() && finished) {
                    return;
                }
                if (!port_queue.empty()) {
                    port = port_queue.front();
                    port_queue.pop();
                } else {
                    continue;
                }
            }
            if (scan_port(port)) {
                std::lock_guard<std::mutex> lock(mtx);
                open_ports.insert(port);
            }
        }
    }

public:
    UDPScanner(const IPv4Address& ip) : target_ip(ip) {
        if (target_ip == IPv4Address("127.0.0.1")) {
            iface = NetworkInterface("lo0");
        } else {
            iface = NetworkInterface::default_interface();
        }
    }

    void scan_ports() {
        total_ports = 1000;  // Update to scan the first 1000 ports
        std::set<uint16_t> open_ports;

        std::vector<std::thread> threads;
        for (int i = 0; i < MAX_THREADS; ++i) {
            threads.emplace_back(&UDPScanner::worker_thread, this, std::ref(open_ports));
        }

        std::thread progress_thread(&UDPScanner::print_progress, this);

        for (uint16_t port = 1; port <= 1000; ++port) {  // Change the loop limit to 1000
            {
                std::lock_guard<std::mutex> lock(mtx);
                port_queue.push(port);
            }
            cv.notify_one();
        }

        {
            std::lock_guard<std::mutex> lock(mtx);
            finished = true;
        }
        cv.notify_all();

        for (auto& thread : threads) {
            thread.join(); // Wait for all worker threads to finish
        }

        progress_thread.join();

        std::cout << "\nOpen ports:" << std::endl;
        for (uint16_t open_port : open_ports) {
            std::cout << open_port << std::endl;
        }
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

        auto start_time = high_resolution_clock::now();

        scanner.scan_ports();

        auto end_time = high_resolution_clock::now();
        auto duration = duration_cast<seconds>(end_time - start_time);

        std::cout << "\nScan completed in " << duration.count() << " seconds." << std::endl;

    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
