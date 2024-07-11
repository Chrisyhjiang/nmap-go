#ifndef OS_DETECTOR_H
#define OS_DETECTOR_H

#include <string>
#include <vector>
#include <map>

struct tcp_options {
    uint16_t mss;
    uint8_t wscale;
    uint8_t sackok;
    uint8_t sack;
    uint8_t timestamp;
    uint32_t timestamp_val;
    uint32_t timestamp_ecr;
};

struct OSFingerprint {
    std::string os_name;
    std::string os_class;
    std::string cpe;
    std::map<std::string, std::vector<std::string>> tests;
};

class NmapOSDB {
private:
    std::vector<OSFingerprint> fingerprints;
    void parse_line(const std::string& line, OSFingerprint& current_fp);

public:
    void load_database(const std::string& filename);
    const std::vector<OSFingerprint>& get_fingerprints() const;
};

class OSDetector {
private:
    NmapOSDB os_database;
    std::string target_ip;

    OSFingerprint probe_target();
    double calculate_similarity(const OSFingerprint& fp1, const OSFingerprint& fp2);
    const char* parse_tcp_options(const uint8_t* optp, int len, struct tcp_options* tcp_opts);

public:
    OSDetector(const std::string& ip);
    void load_database(const std::string& filename);
    std::string detect_os();
};

#endif // OS_DETECTOR_H
