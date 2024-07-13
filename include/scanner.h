#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>
#include <future>

class Scanner {
public:
    Scanner(const std::string& target);
    virtual ~Scanner() = default;
    virtual std::vector<int> scan(int start_port, int end_port) = 0;
    virtual bool is_port_open(int port) = 0;

    virtual void send_packet(int sock, int port) = 0; // Use the correct signature
    void send_decoy_packets(int src_port, int dst_port);

protected:
    std::string target_;
    static std::string local_ip_;

    void initialize_local_ip();

    std::vector<std::vector<char>> fragment_packet(const std::vector<char>& packet, int fragment_size);

    void prepare_packet(std::vector<char>& packet, int src_port, int dst_port);
};

#endif // SCANNER_H
