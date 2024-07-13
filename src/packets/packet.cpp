#include "../../include/packets/packet.h"

Packet::Packet(const std::string& src_ip, const std::string& dst_ip)
    : src_ip_(src_ip), dst_ip_(dst_ip) {}
