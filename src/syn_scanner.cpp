#include "syn_scanner.h"
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>

std::mutex bufferLock;

SynScanner::SynScanner(const std::string& target) : target_ip(target) {}

bool TestPortConnection(std::string ip, int port) {
    struct sockaddr_in address;
    int myNetworkSocket = -1;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip.c_str());
    address.sin_port = htons(port);

    myNetworkSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (myNetworkSocket == -1) {
        std::cerr << "Socket creation failed on port " << port << std::endl;
        return false;
    }

    fcntl(myNetworkSocket, F_SETFL, O_NONBLOCK);
    connect(myNetworkSocket, (struct sockaddr *)&address, sizeof(address)); 

    fd_set fileDescriptorSet;
    struct timeval timeout;

    FD_ZERO(&fileDescriptorSet);
    FD_SET(myNetworkSocket, &fileDescriptorSet);
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    int connectionResponse = select(myNetworkSocket + 1, NULL, &fileDescriptorSet, NULL, &timeout);
    if (connectionResponse == 1) {
        int socketError;
        socklen_t len = sizeof socketError;
        getsockopt(myNetworkSocket, SOL_SOCKET, SO_ERROR, &socketError, &len);

        if (socketError == 0) {
            close(myNetworkSocket);
            return true;
        } else {
            close(myNetworkSocket);
            return false;
        }
    }
    close(myNetworkSocket);
    return false;
}

void ThreadTask(std::vector<int>* bufferArg, std::string hostNameArg, int port) {
    if (TestPortConnection(hostNameArg, port)) {
        std::lock_guard<std::mutex> lock(bufferLock);
        bufferArg->push_back(port);
    }
}

std::vector<int> SynScanner::syn_scan(int start_port, int end_port) {
    std::vector<std::thread*> portTests;
    std::vector<int> buffer;

    int numOfTasks = 500;  // Increase the number of concurrent threads

    for (int port = start_port; port <= end_port; port++) {
        portTests.push_back(new std::thread(ThreadTask, &buffer, target_ip, port));

        if (portTests.size() >= numOfTasks || port == end_port) {
            for (auto& thread : portTests) {
                thread->join();
            }
            for (auto& thread : portTests) {
                delete thread;
            }
            portTests.clear();
        }
    }

    std::sort(buffer.begin(), buffer.end());
    return buffer;
}
