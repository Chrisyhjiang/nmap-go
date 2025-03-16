# nmap-go

A lightweight, concurrent port scanner written in Go, inspired by the popular Nmap security tool. This project implements various scanning techniques including TCP Connect, SYN (half-open), and UDP scanning with a focus on performance and accuracy.

## Features

- **Multiple Scanning Techniques**:

  - TCP Connect Scan: Full TCP handshake, reliable but more detectable
  - SYN Scan: Half-open scanning, less detectable (requires root/sudo)
  - UDP Scan: Basic UDP port scanning

- **Concurrent Scanning**:

  - Utilizes Go's goroutines for parallel port scanning
  - Automatically scales based on available CPU cores
  - Implements rate limiting to prevent network flooding

- **Flexible Port Selection**:

  - Scan specific ports: `22,80,443`
  - Scan port ranges: `1-1000`
  - Scan combinations: `22,80,1000-2000`
  - Default scan of common service ports

- **Optimized for Different Targets**:
  - Special handling for localhost scanning
  - MAC address resolution for local network targets
  - Broadcast fallback for remote targets

## Installation

### Prerequisites

- Go 1.16 or higher
- For SYN scanning: root/sudo privileges

### Building from Source

1. Clone the repository:

   ```bash
   git clone https://github.com/Chrisyhjiang/nmap-go.git
   cd nmap-go
   ```

2. Build the project:

   ```bash
   make build
   ```

   This will create the binary in the `bin` directory.

## Usage

### Basic Usage

```bash
./bin/nmap-go <scan-type> <ip-address> [ports]
```

Where:

- `<scan-type>`: `tcp`, `syn`, or `udp`
- `<ip-address>`: Target IP address to scan
- `[ports]`: Optional port specification (default: scans common ports)

### Examples

Scan specific ports with TCP Connect scan:

```bash
./bin/nmap-go tcp 192.168.1.1 22,80,443
```

Scan a range of ports with SYN scan (requires sudo):

```bash
sudo ./bin/nmap-go syn 8.8.8.8 1-1000
```

Scan common ports on localhost with UDP:

```bash
./bin/nmap-go udp 127.0.0.1
```

Scan a mix of individual ports and ranges:

```bash
./bin/nmap-go tcp 10.0.0.1 22,80,1000-2000
```

## Technical Details

### Project Structure

- `cmd/nmap-go/`: Main application entry point
- `internal/scanner/`: Scanner implementations
  - `tcp_scanner.go`: TCP Connect scanner
  - `syn_scanner.go`: SYN (half-open) scanner
  - `udp_scanner.go`: UDP scanner
  - `scanner.go`: Common scanner utilities
- `pkg/`: Shared packages and utilities
  - `portscanner.go`: Common port definitions

### Concurrency Model

The scanner uses a worker pool pattern with the following characteristics:

- TCP scanning: 4 workers per CPU core (capped at 100)
- SYN scanning: 1 worker per CPU core (capped at 10)
- UDP scanning: 2 workers per CPU core (capped at 50)

Each worker processes ports from a shared channel, with mutex protection for thread-safe result collection.

### SYN Scanning Implementation

The SYN scanner uses raw sockets via the gopacket library to:

1. Craft custom TCP SYN packets
2. Send them to target ports
3. Capture SYN-ACK or RST responses
4. Determine port state based on responses

For localhost scanning, it automatically falls back to TCP Connect scanning for better reliability.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by the [Nmap Security Scanner](https://nmap.org/)
- Built with [gopacket](https://github.com/google/gopacket) for packet crafting and capture
