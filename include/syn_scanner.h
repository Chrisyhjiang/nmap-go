#ifndef SYN_SCANNER_H
#define SYN_SCANNER_H

#include <string>
#include <vector>

class SynScanner {
public:
    SynScanner(const std::string& target);
    std::vector<int> syn_scan(int start_port, int end_port);
    std::string detect_os();

private:
    std::string target_ip;

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
};

#endif // SYN_SCANNER_H
