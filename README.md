# MyNmap - Custom Port Scanner

MyNmap is a custom-built port scanner written in C++. It implements various scanning techniques, such as TCP Connect and SYN scan (half-open scan). The scanner also includes additional features such as OS fingerprinting and firewall evasion techniques.

## Features

- **TCP Connect Scan**: Establishes a full connection with the target.
- **SYN Scan**: Performs a half-open scan by sending SYN packets and analyzing the response.
- **OS Fingerprinting**: Identifies the target operating system based on network responses.
- **Firewall Evasion**: Implements techniques such as packet fragmentation and decoy packets to bypass firewalls.

## Project Structure

├── 📁 include
│ ├── 📄 scanner.h
│ └── 📄 syn_scanner.h
├── 📁 src
│ ├── 📄 main.cpp
│ ├── 📄 scanner.cpp
│ └── 📄 syn_scanner.cpp
├── 📁 bin
│ └── 📄 my_nmap
└── 📄 README.md

## Dependencies

- C++11 or later
- POSIX compliant OS (Linux, macOS, etc.)
- GCC or Clang compiler

## Installation

1. **Clone the repository**

   ```sh
   git clone https://github.com/Chrisyhjiang/nmap-cpp.git
   cd nmap-cpp
   ```

2. **Build the project**
   ```sh
   make
   ```

## Usage

Run the executable `my_nmap` with the target IP address and scan type:

```sh
./bin/my_nmap <ip_address> <scan_type>
```

## Additional Features

1. OS detection
2. Firewall evasion techniques
