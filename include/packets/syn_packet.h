#ifndef SYN_PACKET_H
#define SYN_PACKET_H

#include "packet.h"
#include <string>
#include <vector>

class SYN_Packet : public Packet {
public:
    SYN_Packet(const std::string& src_ip, const std::string& dst_ip);
    void prepare_packet(std::vector<char>& packet, int src_port, int dst_port) override;
};

#endif // SYN_PACKET_H
