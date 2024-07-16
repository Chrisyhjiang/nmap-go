#include "output.h"
#include "services.h"
#include "tcp_connect_scanner.h"
#include "syn_scanner.h"
#include <iostream>
#include <vector>
#include <string>
#include <thread>

using namespace std;

void start_progress_bar(Scanner& scanner) {
    std::thread progress_thread(&Scanner::print_progress, &scanner);
    progress_thread.detach();
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cout << "Usage: " << argv[0] << " <ip_address> <scan_type>" << std::endl;
        cout << "scan_type: tcp, syn" << std::endl;
        return 1;
    }

    string target = argv[1];
    string scan_type = argv[2];
    std::set<uint16_t> open_ports;

    Scanner* scanner = nullptr;

    if (scan_type == "tcp") {
        scanner = new TCPConnectScanner(target, 65535);
    } else if (scan_type == "syn") {
        scanner = new SynScanner(target, 65535);
    } else {
        cout << "Unknown scan type: " << scan_type << std::endl;
        return 1;
    }

    if (scanner) {
        const int num_threads = 64;
        vector<thread> threads;
        uint16_t ports_per_thread = 65535 / num_threads;

        // Start the progress bar thread
        start_progress_bar(*scanner);

        auto start_time = chrono::high_resolution_clock::now();

        for (int i = 0; i < num_threads; ++i) {
            uint16_t start_port = i * ports_per_thread;
            uint16_t end_port = (i == num_threads - 1) ? 65535 : start_port + ports_per_thread - 1;
            threads.emplace_back(&Scanner::scan_ports, scanner, start_port, end_port, std::ref(open_ports));
        }

        for (auto& thread : threads) {
            thread.join();
        }

        scanner->stop();

        auto end_time = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::seconds>(end_time - start_time);

        cout << "Scan completed in " << duration.count() << " seconds." << std::endl;
        Output::print_results(target, vector<int>(open_ports.begin(), open_ports.end()));

        delete scanner;
    }

    return 0;
}
