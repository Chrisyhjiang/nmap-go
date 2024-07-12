#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>

class Scanner {
public:
    Scanner(const std::string& target);
    virtual ~Scanner() = default;
    virtual std::vector<int> scan(int start_port, int end_port) = 0;
    virtual bool is_port_open(int port) = 0;

    void send_decoy_packets(const std::string& real_src_ip, int src_port, int dst_port);

protected:
    std::string target_;
    static std::string local_ip_;  // Add this line

    std::vector<std::vector<char>> fragment_packet(const std::vector<char>& packet, int fragment_size);
    void send_packet(const std::string& src_ip, int src_port, int dst_port);
    void cache_local_ip();  // Add this line

private:
    void initialize_local_ip();  // Add this line
};

#endif // SCANNER_H
