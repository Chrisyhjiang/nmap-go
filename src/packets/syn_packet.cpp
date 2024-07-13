#include "../../include/packets/syn_packet.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cstring>

SYN_Packet::SYN_Packet(const std::string& src_ip, const std::string& dst_ip)
    : Packet(src_ip, dst_ip) {}

void SYN_Packet::prepare_packet(std::vector<char>& packet, int src_port, int dst_port) {
    struct ip *ip_header = (struct ip *)packet.data();
    struct tcphdr *tcp_header = (struct tcphdr *)(packet.data() + sizeof(struct ip));

    // Prepare IP header
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ip_header->ip_id = htons(54321);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 255;
    ip_header->ip_p = IPPROTO_TCP;
    ip_header->ip_sum = 0;
    ip_header->ip_src.s_addr = inet_addr(src_ip_.c_str());
    ip_header->ip_dst.s_addr = inet_addr(dst_ip_.c_str());

    // Prepare TCP header
    tcp_header->th_sport = htons(src_port);
    tcp_header->th_dport = htons(dst_port);
    tcp_header->th_seq = htonl(1000);
    tcp_header->th_ack = 0;
    tcp_header->th_off = 5;
    tcp_header->th_flags = TH_SYN;
    tcp_header->th_win = htons(65535);
    tcp_header->th_sum = 0;
    tcp_header->th_urp = 0;
}
