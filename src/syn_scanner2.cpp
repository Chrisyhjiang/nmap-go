#include <tins/tins.h>
#include <iostream>
#include <chrono>
#include <thread>
#include <random>

using namespace Tins;

bool callback(const PDU &pdu) {
    const IP &ip = pdu.rfind_pdu<IP>();
    const TCP &tcp = pdu.rfind_pdu<TCP>();

    if (tcp.flags() == (TCP::SYN | TCP::ACK)) {
        std::cout << "Port " << tcp.sport() << " is open on " << ip.src_addr() << std::endl;
        return false;
    }
    return true;
}

// Function to generate a random port number
uint16_t random_port() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1024, 65535);
    return dis(gen);
}

void send_syn_packets(const std::string &target_ip, const NetworkInterface &iface, uint16_t start_port, uint16_t end_port) {
    PacketSender sender;

    for (uint16_t port = start_port; port <= end_port; ++port) {
        try {
            IP ip = IP(target_ip, iface.ipv4_address()) / TCP(port, random_port());
            ip.ttl(64);
            TCP &tcp = ip.rfind_pdu<TCP>();
            tcp.set_flag(TCP::SYN, 1);
            tcp.mss(1460);

            sender.send(ip, iface);
            std::cout << "Sent SYN packet to " << target_ip << " on port " << port << std::endl;

            std::this_thread::sleep_for(std::chrono::milliseconds(1)); // small delay to avoid flooding

        } catch (std::exception &ex) {
            std::cerr << "Error: " << ex.what() << std::endl;
        }
    }
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <IP address>" << std::endl;
        return 1;
    }

    try {
        NetworkInterface iface = NetworkInterface::default_interface();
        IPv4Address target(argv[1]);
        
        IP ip = IP(target, iface.ipv4_address()) / TCP(3306, random_port());
        ip.ttl(64);
        TCP& tcp = ip.rfind_pdu<TCP>();
        tcp.set_flag(TCP::SYN, 1);
        tcp.mss(1460);

        PacketSender sender;
        sender.send(ip, iface);

        SnifferConfiguration config;
        config.set_timeout(2);
        config.set_promisc_mode(true);
        Sniffer sniffer(iface.name(), config);
        
        sniffer.sniff_loop(callback);

        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        std::cout << "Scan completed." << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
