#include <arpa/inet.h>
#include <cstdlib>
#include <inttypes.h>
#include <iomanip>
#include <iostream>
#include <math.h>
#include <netdb.h>
#include <pthread.h>
#include <set>
#include <stdarg.h>
#include <string>
#include <unistd.h>
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>

/* https://github.com/mfontanini/libtins */
#include <tins/address_range.h>
#include <tins/ethernetII.h>
#include <tins/ip.h>
#include <tins/ip_address.h>
#include <tins/network_interface.h>
#include <tins/packet_sender.h>
#include <tins/sniffer.h>
#include <tins/tcp.h>
#include <tins/utils.h>

using namespace Tins;

#define RATE_LIMIT 100

void start_scan(int argc, char* argv[]);
int parse_cidr(const char* cidr, struct in_addr* addr, struct in_addr* mask);
const char* dotted_quad(const struct in_addr* addr);
AddressRange<IPv4Address> parse_target(char* target);
std::string ip_to_host(const char* ip);

class Scanner {
public:
    Scanner(const NetworkInterface& interface,
        const AddressRange<IPv4Address>& target_addresses,
        uint16_t start_port, uint16_t end_port);

    void run();

private:
    void send_syn_packets(const NetworkInterface& iface);
    bool callback(PDU& pdu);
    void launch_sniffer();
    static void* thread_proc(void* arg);
    void start_clock();
    void end_clock();
    void initialize_ports();

    NetworkInterface iface;
    AddressRange<IPv4Address> target_addresses;
    uint16_t start_port;
    uint16_t end_port;
    Sniffer sniffer;

    std::set<std::string> open_hosts;
    double program_duration;
    struct timespec start_time, finish_time;

    std::mutex mtx;
    std::condition_variable cv;
    std::queue<uint16_t> port_queue;
};

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <IP/CIDR>\n";
        std::cout << "Example:\n";
        std::cout << "\t" << argv[0] << " 166.104.0.0/16\n";
        std::cout << "\t" << argv[0] << " 35.186.153.3\n";
        std::cout << "\t" << argv[0] << " 166.104.177.24\n";

        return 1;
    }

    try {
        start_scan(argc, argv);
    } catch (std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }
}

/**
  Constructor for the Scanner class
 */
Scanner::Scanner(const NetworkInterface& interface,
    const AddressRange<IPv4Address>& target_addresses,
    uint16_t start_port, uint16_t end_port)
    : iface(interface)
    , target_addresses(target_addresses)
    , start_port(start_port)
    , end_port(end_port)
    , sniffer(interface.name())
{
    initialize_ports();
}

/**
  Initialize port queue
 */
void Scanner::initialize_ports()
{
    for (uint16_t port = start_port; port <= end_port; ++port) {
        port_queue.push(port);
    }
}

/**
  The function for sniffer thread
 */
void* Scanner::thread_proc(void* arg)
{
    Scanner* scanner = (Scanner*)arg;
    scanner->launch_sniffer();

    return NULL;
}

/**
  Launch the sniffer process
 */
void Scanner::launch_sniffer()
{
    sniffer.sniff_loop(make_sniffer_handler(this, &Scanner::callback));
}

/**
  Sniffer's callback to handle replies from target hosts
 */
bool Scanner::callback(PDU& pdu)
{
    const IP& ip = pdu.rfind_pdu<IP>();
    const TCP& tcp = pdu.rfind_pdu<TCP>();

    // Log detailed packet information
    std::cout << "Captured packet from " << ip.src_addr() << " to " << ip.dst_addr()
              << " on port " << tcp.dport() << " with flags: " << static_cast<int>(tcp.flags()) << std::endl;

    if (target_addresses.contains(ip.src_addr()) && tcp.dport() == 3306) {
        std::string ip_address = ip.src_addr().to_string();

        if (tcp.flags() == (TCP::SYN | TCP::ACK)) {
            std::cout << ip_address << " (" << ip_to_host(ip_address.c_str()) << ")\t\tPort: " << tcp.sport() << " open\n";
            open_hosts.insert(ip_address);
        } else if (tcp.get_flag(TCP::RST)) {
            std::cout << ip_address << " (" << ip_to_host(ip_address.c_str()) << ")\t\tPort: " << tcp.sport() << " closed (RST received)\n";
        } else {
            std::cout << "Received unexpected packet from " << ip.src_addr() << " on port " << tcp.sport() << " with flags: " << static_cast<int>(tcp.flags()) << std::endl;
        }
    }
    return true;
}

/**
  Start the scan process
 */
void Scanner::run()
{
    start_clock();

    pthread_t sniffer_thread;
    pthread_create(&sniffer_thread, 0, &Scanner::thread_proc, this);

    std::vector<std::thread> workers;
    int num_threads = 1;  // Increase the number of threads
    for (int i = 0; i < num_threads; ++i) {
        workers.emplace_back([this] {
            this->send_syn_packets(this->iface);
        });
    }

    for (auto& worker : workers) {
        worker.join();
    }

    void* dummy;
    pthread_join(sniffer_thread, &dummy);

    std::cout << "\nTotal open hosts: " << open_hosts.size() << " host(s)" << std::endl;

    end_clock();
}

void Scanner::send_syn_packets(const NetworkInterface& iface)
{
    PacketSender sender;
    NetworkInterface::Info info = iface.addresses();
    IP ip = IP(*target_addresses.begin(), info.ip_addr) / TCP();
    TCP& tcp = ip.rfind_pdu<TCP>();
    tcp.set_flag(TCP::SYN, 1);
    tcp.sport(46156);

    open_hosts.clear();

    while (true) {
        uint16_t port;
        {
            std::unique_lock<std::mutex> lock(mtx);
            if (port_queue.empty()) {
                break;
            }
            port = port_queue.front();
            port_queue.pop();
        }

        for (const auto& addr : target_addresses) {
            ip.dst_addr(addr);
            tcp.dport(port);  // Ensure the destination port is set correctly
            sender.send(ip);
            std::cout << "Sent SYN packet to " << addr << " on port " << port << std::endl;

            // Simulate a small delay
            usleep(1000);  // 1 millisecond
        }

        // Log after finishing scanning the port
        std::cout << "Finished scanning port " << port << std::endl;
    }

    tcp.set_flag(TCP::RST, 1);
    tcp.sport(start_port);
    ip.src_addr(*target_addresses.begin());

    EthernetII eth = EthernetII(info.hw_addr, info.hw_addr) / ip;
    sender.send(eth, iface);
}


/**
  To mark the beginning of the scan, will initialize start_time variable
 */
void Scanner::start_clock()
{
    clock_gettime(CLOCK_MONOTONIC, &start_time);
}

/**
  To mark the end of the scan, will output the scan duration
 */
void Scanner::end_clock()
{
    clock_gettime(CLOCK_MONOTONIC, &finish_time);
    program_duration = (finish_time.tv_sec - start_time.tv_sec);
    program_duration += (finish_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

    int hours_duration = program_duration / 3600;
    int mins_duration = (int)(program_duration / 60) % 60;
    double secs_duration = fmod(program_duration, 60);

    std::cout << "Scan duration: " << hours_duration << " hour(s) " << mins_duration << " min(s) " << std::setprecision(5) << secs_duration << " sec(s)\n";
}

/**
  This is where the Scanner class will be used
 */
void start_scan(int argc, char* argv[])
{
    NetworkInterface iface = NetworkInterface::default_interface();
    std::cout << "Running on interface: " << iface.name() << "\n";
    std::cout << "SYN scan [" << argv[1] << "]:[3306]\n";

    AddressRange<IPv4Address> target_addresses = parse_target(argv[1]);

    Scanner scanner(iface, target_addresses, 3306, 3306);
    scanner.run();
}

/**
  Format the IPv4 address in dotted quad notation, using a static buffer
 */
const char* dotted_quad(const struct in_addr* addr)
{
    static char buf[INET_ADDRSTRLEN];

    return inet_ntop(AF_INET, addr, buf, sizeof buf);
}

/**
  Parse CIDR notation address.
  Return the number of bits in the netmask if the string is valid
  Return -1 if the string is invalid.
 */
int parse_cidr(const char* cidr, struct in_addr* addr, struct in_addr* mask)
{
    int bits = inet_net_pton(AF_INET, cidr, addr, sizeof addr);

    mask->s_addr = htonl(~(bits == 32 ? 0 : ~0U >> bits));
    return bits;
}

/**
  Parse target IP into AddressRange<IPv4Address> type
 */
AddressRange<IPv4Address> parse_target(char* target)
{
    struct in_addr parsed_in_addr, mask_in_addr, wildcard_in_addr, network_in_addr, broadcast_in_addr, min_in_addr, max_in_addr;

    int bits = parse_cidr(target, &parsed_in_addr, &mask_in_addr);
    if (bits == -1) {
        std::cerr << "Invalid network address" << std::endl;
        exit(1);
    }

    wildcard_in_addr = mask_in_addr;
    wildcard_in_addr.s_addr = ~wildcard_in_addr.s_addr;

    network_in_addr = parsed_in_addr;
    network_in_addr.s_addr &= mask_in_addr.s_addr;

    broadcast_in_addr = parsed_in_addr;
    broadcast_in_addr.s_addr |= wildcard_in_addr.s_addr;

    min_in_addr = network_in_addr;
    max_in_addr = broadcast_in_addr;

    if (network_in_addr.s_addr != broadcast_in_addr.s_addr) {
        min_in_addr.s_addr = htonl(ntohl(min_in_addr.s_addr) + 1);
        max_in_addr.s_addr = htonl(ntohl(max_in_addr.s_addr) - 1);
    }

    int num_hosts = (int64_t)ntohl(broadcast_in_addr.s_addr) - ntohl(network_in_addr.s_addr) + 1;
    std::string min_ip(dotted_quad(&min_in_addr));
    std::string max_ip(dotted_quad(&max_in_addr));
    AddressRange<IPv4Address> range(min_ip, max_ip);

    std::cout << num_hosts << " host(s): " << min_ip << " -> " << max_ip << "\n\n";

    return range;
}

/**
 Get hostname of an IP address
 */
std::string ip_to_host(const char* ip)
{
    struct sockaddr_in dest;
    char buffer[NI_MAXHOST];

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ip);
    dest.sin_port = 0;

    if (getnameinfo((struct sockaddr*)&dest, sizeof(dest), buffer, NI_MAXHOST, NULL, 0, NI_NAMEREQD) != 0)
        strcpy(buffer, " ");

    return std::string(buffer);
}
