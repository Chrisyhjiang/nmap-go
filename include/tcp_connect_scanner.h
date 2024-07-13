#ifndef TCP_CONNECT_SCANNER_H
#define TCP_CONNECT_SCANNER_H

#include "scanner.h"
#include "packets/packet.h"
#include <vector>
#include <memory>

class TCPConnectScanner : public Scanner {
public:
    TCPConnectScanner(const std::string& target, std::shared_ptr<Packet> packet);
    std::vector<int> scan(int start_port, int end_port) override;

protected:
    bool is_port_open(int port) override;
    void send_packet(int sock, int port) override; // Use the correct signature

private:
    std::shared_ptr<Packet> packet_;
};

#endif // TCP_CONNECT_SCANNER_H
