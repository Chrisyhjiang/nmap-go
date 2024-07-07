#include "scanner.h"
#include "output.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <ip_address>" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    Scanner scanner(target);
    std::vector<int> open_ports = scanner.scan(1, 65535); // Scan all ports

    Output::print_results(target, open_ports);

    return 0;
}
