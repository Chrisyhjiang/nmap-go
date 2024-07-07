#include "scanner.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <mutex>

Scanner::Scanner(const std::string& target) : target_(target) {}

std::vector<int> Scanner::scan(int start_port, int end_port) {
    std::vector<int> open_ports;
    std::mutex mutex;

    auto scan_range = [&](int start, int end) {
        for (int port = start; port <= end; ++port) {
            if (is_port_open(port)) {
                std::lock_guard<std::mutex> lock(mutex);
                open_ports.push_back(port);
            }
        }
    };

    const int num_threads = 4;
    std::vector<std::thread> threads;
    int ports_per_thread = (end_port - start_port + 1) / num_threads;

    for (int i = 0; i < num_threads; ++i) {
        int thread_start = start_port + i * ports_per_thread;
        int thread_end = (i == num_threads - 1) ? end_port : thread_start + ports_per_thread - 1;
        threads.emplace_back(scan_range, thread_start, thread_end);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    return open_ports;
}

bool Scanner::is_port_open(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, target_.c_str(), &server_addr.sin_addr);

    int result = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    close(sock);

    return result == 0;
}
