#include "scanner.h"
#include <iostream>
#include <thread>
#include <chrono>

Scanner::Scanner(const IPv4Address& ip, uint16_t total_ports) : target_ip(ip), total_ports(total_ports) {
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

bool Scanner::is_local_ip(const IPv4Address& ip) {
    std::set<IPv4Address> local_ips;
    for (const auto& iface : NetworkInterface::all()) {
        local_ips.insert(iface.addresses().ip_addr);
    }
    return local_ips.find(ip) != local_ips.end();
}

void Scanner::stop() {
    should_stop = true;
}

void Scanner::print_progress() {
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
