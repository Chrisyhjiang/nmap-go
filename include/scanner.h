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

    std::string detect_os();
    void send_decoy_packets(const std::string& real_src_ip, int src_port, int dst_port);

protected:
    std::string target_;
    
private:
    struct OSFingerprint {
        std::string os_name;
        std::string os_details;
        int ttl;
        int window_size;
        std::string tcp_options;
    };

    std::vector<OSFingerprint> os_database;

    void load_os_database();
    OSFingerprint get_target_fingerprint();
    std::string match_fingerprint(const OSFingerprint& target);
    std::vector<std::vector<char>> fragment_packet(const std::vector<char>& packet, int fragment_size);
    void send_packet(const std::string& src_ip, int src_port, int dst_port);
};

#endif // SCANNER_H
