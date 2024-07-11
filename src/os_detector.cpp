#include "os_detector.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

// Implementation of NmapOSDB class
void NmapOSDB::load_database(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }

    std::string line;
    OSFingerprint current_fp;

    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') {
            continue; // Skip empty lines and comments
        }

        if (line.substr(0, 11) == "Fingerprint" && !current_fp.os_name.empty()) {
            fingerprints.push_back(current_fp);
            current_fp = OSFingerprint();
        }

        parse_line(line, current_fp);
    }

    if (!current_fp.os_name.empty()) {
        fingerprints.push_back(current_fp);
    }

    file.close();
}

void NmapOSDB::parse_line(const std::string& line, OSFingerprint& current_fp) {
    if (line.substr(0, 11) == "Fingerprint") {
        current_fp.os_name = line.substr(12);
    } else if (line.substr(0, 5) == "Class") {
        current_fp.os_class = line.substr(6);
    } else if (line.substr(0, 3) == "CPE") {
        current_fp.cpe = line.substr(4);
    } else {
        size_t pos = line.find('(');
        if (pos != std::string::npos) {
            std::string test_name = line.substr(0, pos);
            std::string test_values = line.substr(pos + 1);
            test_values.pop_back(); // Remove trailing ')'

            size_t start = 0, end;
            while ((end = test_values.find('%', start)) != std::string::npos) {
                std::string test_value = test_values.substr(start, end - start);
                current_fp.tests[test_name].push_back(test_value);
                start = end + 1;
            }
            current_fp.tests[test_name].push_back(test_values.substr(start));
        }
    }
}

const std::vector<OSFingerprint>& NmapOSDB::get_fingerprints() const {
    return fingerprints;
}

// Implementation of OSDetector class
OSDetector::OSDetector(const std::string& ip) : target_ip(ip) {}

void OSDetector::load_database(const std::string& filename) {
    os_database.load_database(filename);
}

OSFingerprint OSDetector::probe_target() {
    std::cout << "Starting probe_target function." << std::endl;
    OSFingerprint fp;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    std::cout << "Socket created successfully." << std::endl;

    char packet[4096];
    struct ip *ip_header = (struct ip *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ip));

    memset(packet, 0, 4096);

    // IP Header
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    ip_header->ip_id = htons(54321);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_TCP;
    ip_header->ip_sum = 0;
    ip_header->ip_src.s_addr = inet_addr("192.168.1.1");
    ip_header->ip_dst.s_addr = inet_addr(target_ip.c_str());

    // TCP Header
    tcp_header->th_sport = htons(12345);
    tcp_header->th_dport = htons(80);
    tcp_header->th_seq = htonl(1000);
    tcp_header->th_ack = 0;
    tcp_header->th_off = 5;
    tcp_header->th_flags = TH_SYN;
    tcp_header->th_win = htons(65535);
    tcp_header->th_sum = 0;
    tcp_header->th_urp = 0;

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(80);
    dest.sin_addr.s_addr = inet_addr(target_ip.c_str());

    if (sendto(sock, packet, ip_header->ip_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    std::cout << "Packet sent successfully." << std::endl;

    char buffer[4096];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    // Set a timeout for recvfrom
    struct timeval timeout;
    timeout.tv_sec = 5;  // 5 seconds timeout
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    int received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &fromlen);
    if (received < 0) {
        perror("recvfrom failed or timed out");
    } else {
        std::cout << "Finished receiving, received " << received << " bytes." << std::endl;
    }

    if (received > 0) {
        struct ip *ip_reply = (struct ip *)buffer;
        struct tcphdr *tcp_reply = (struct tcphdr *)(buffer + sizeof(struct ip));

        std::cout << "TTL: " << (int)ip_reply->ip_ttl << ", Window Size: " << ntohs(tcp_reply->th_win) << std::endl;

        fp.tests["T1(TTL)"].push_back(std::to_string(ip_reply->ip_ttl));
        fp.tests["T1(W)"].push_back(std::to_string(ntohs(tcp_reply->th_win)));

        // Parse TCP options
        int tcp_header_length = tcp_reply->th_off * 4;
        if (tcp_header_length > 20) {
            tcp_options tcp_opts;
            const char* options_string = parse_tcp_options((uint8_t *)(buffer + sizeof(struct ip) + 20), tcp_header_length - 20, &tcp_opts);
            std::cout << "TCP Options: " << options_string << std::endl;
            fp.tests["T1(O)"].push_back(options_string);
            free((void*)options_string); // Remember to free the allocated memory
        }
    } else {
        std::cerr << "recvfrom timed out or failed" << std::endl;
    }

    close(sock);
    std::cout << "Socket closed." << std::endl;
    return fp;
}

double OSDetector::calculate_similarity(const OSFingerprint& fp1, const OSFingerprint& fp2) {
    double similarity = 0.0;
    int total_tests = 0;

    std::cout << "Comparing fingerprints:" << std::endl;
    for (const auto& test : fp1.tests) {
        std::cout << "Test: " << test.first << std::endl;
        if (fp2.tests.find(test.first) != fp2.tests.end()) {
            std::cout << "  Target: ";
            for (const auto& val : test.second) {
                std::cout << val << " ";
            }
            std::cout << std::endl;

            std::cout << "  Database: ";
            for (const auto& db_val : fp2.tests.at(test.first)) {
                std::cout << db_val << " ";
            }
            std::cout << std::endl;

            for (const auto& val : test.second) {
                if (std::find(fp2.tests.at(test.first).begin(), fp2.tests.at(test.first).end(), val) != fp2.tests.at(test.first).end()) {
                    similarity += 1.0;
                    std::cout << "  Match found!" << std::endl;
                } else {
                    std::cout << "  No match." << std::endl;
                }
            }
            total_tests++;
        } else {
            std::cout << "  Test not found in database fingerprint." << std::endl;
        }
    }

    std::cout << "Total tests: " << total_tests << ", Matches: " << similarity << std::endl;
    return total_tests > 0 ? similarity / total_tests : 0.0;
}

#include <fstream>

std::string OSDetector::detect_os() {
    std::ofstream log_file("log.txt", std::ios_base::app);  // Append mode
    if (!log_file.is_open()) {
        std::cerr << "Error opening log file" << std::endl;
        return "Unknown OS";
    }

    log_file << "Starting OS detection." << std::endl;
    OSFingerprint target_fp = probe_target();
    log_file << "Finished probing target." << std::endl;
    
    double best_match = 0.0;
    std::string detected_os = "Unknown OS";

    for (const auto& db_fp : os_database.get_fingerprints()) {
        double similarity = calculate_similarity(target_fp, db_fp);
        log_file << "Comparing with " << db_fp.os_name << ", similarity: " << similarity << std::endl;
        if (similarity > best_match) {
            best_match = similarity;
            detected_os = db_fp.os_name;
        }
    }

    log_file << "Detected OS: " << detected_os << " (Confidence: " << best_match * 100 << "%)" << std::endl;
    return detected_os + " (Confidence: " + std::to_string(best_match * 100) + "%)";
}

const char *OSDetector::parse_tcp_options(const uint8_t *optp, int len, struct tcp_options *tcp_opts) {
    const uint8_t *p;
    int opcode, opsize;
    static char result[256];
    char *dst = result;
    unsigned int i;
    uint32_t tmp32;

    if (len < 0 || len > 40)
        return "ERROR: Invalid TCP options length";

    tcp_opts->mss = 0;
    tcp_opts->wscale = 0;
    tcp_opts->sackok = 0;
    tcp_opts->sack = 0;
    tcp_opts->timestamp = 0;
    tcp_opts->timestamp_val = 0;
    tcp_opts->timestamp_ecr = 0;

    p = optp;
    i = 0;
    while (i < (unsigned int) len) {
        opcode = *p++;
        i++;
        if (opcode == TCPOPT_EOL)
            break;
        if (opcode == TCPOPT_NOP) {
            *dst++ = 'N';
            continue;
        }
        if (i >= (unsigned int) len)
            break;
        opsize = *p++;
        i++;
        if (opsize < 2 || i + opsize > (unsigned int) len + 2)
            break;

        switch (opcode) {
        case TCPOPT_MAXSEG:
            if (opsize == 4) {
                tcp_opts->mss = ntohs(*(uint16_t *) p);
                *dst++ = 'M';
                dst += snprintf(dst, sizeof(result) - (dst - result), "%d", tcp_opts->mss);
            }
            break;
        case TCPOPT_WINDOW:
            if (opsize == 3) {
                tcp_opts->wscale = *p;
                *dst++ = 'W';
                dst += snprintf(dst, sizeof(result) - (dst - result), "%d", tcp_opts->wscale);
            }
            break;
        case TCPOPT_SACK_PERMITTED:
            if (opsize == 2) {
                tcp_opts->sackok = 1;
                *dst++ = 'S';
            }
            break;
        case TCPOPT_TIMESTAMP:
            if (opsize == 10) {
                tcp_opts->timestamp = 1;
                memcpy(&tmp32, p, 4);
                tcp_opts->timestamp_val = ntohl(tmp32);
                memcpy(&tmp32, p + 4, 4);
                tcp_opts->timestamp_ecr = ntohl(tmp32);
                *dst++ = 'T';
                if (tcp_opts->timestamp_ecr)
                    dst += snprintf(dst, sizeof(result) - (dst - result), "%u:%u", tcp_opts->timestamp_val, tcp_opts->timestamp_ecr);
                else
                    dst += snprintf(dst, sizeof(result) - (dst - result), "%u", tcp_opts->timestamp_val);
            }
            break;
        case TCPOPT_SACK:
            tcp_opts->sack = 1;
            *dst++ = 'L';
            break;
        default:
            *dst++ = '?';
            break;
        }
        i += opsize - 2;
        p += opsize - 2;
    }

    *dst = '\0';
    return result;
}
