#ifndef PACKET_H
#define PACKET_H

#include <string>
#include <vector>

class Packet {
public:
    Packet(const std::string& src_ip, const std::string& dst_ip);
    virtual ~Packet() = default;
    virtual void prepare_packet(std::vector<char>& packet, int src_port, int dst_port) = 0;

protected:
    std::string src_ip_;
    std::string dst_ip_;
};

#endif // PACKET_H
