package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/Chrisyhjiang/nmap-go/internal/scanner"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: nmap-go <scan-type> <ip-address> [ports]")
		fmt.Println("Scan types: tcp, syn, udp")
		fmt.Println("Ports: Specify ports to scan (optional)")
		fmt.Println("  - Single port: 80")
		fmt.Println("  - Multiple ports: 22,80,443")
		fmt.Println("  - Port range: 1-1000")
		fmt.Println("  - Mixed: 22,80,1000-2000")
		fmt.Println("  - Default: scans common ports if not specified")
		os.Exit(1)
	}

	// Take in the scan type and IP address from the command-line arguments
	scanType := os.Args[1] // First argument is the scan type
	ip := os.Args[2]       // Second argument is the IP address

	// Parse ports if provided
	var ports []int
	if len(os.Args) > 3 {
		portsArg := os.Args[3]
		ports = parsePorts(portsArg)
	}

	// Get the best network interface
	iface, err := scanner.GetBestInterface(ip)
	if err != nil {
		log.Fatalf("Error determining the best interface: %v", err)
	}

	fmt.Printf("Scanning IP: %s using interface: %s with scan type: %s\n", ip, iface.Name, scanType)
	if len(ports) > 0 {
		fmt.Printf("Scanning %d specified ports\n", len(ports))
	} else {
		fmt.Println("Scanning common ports (no ports specified)")
	}

	// Switch based on scan type
	var errScan error
	switch scanType {
	case "tcp":
		errScan = scanner.TCPScan(ip, iface, ports) // Pass ports to scan
	case "syn":
		errScan = scanner.SYNScan(ip, iface, ports) // Pass ports to scan
	case "udp":
		errScan = scanner.UDPScan(ip, iface, ports) // Pass ports to scan
	default:
		fmt.Printf("Unknown scan type: %s\n", scanType)
		os.Exit(1)
	}

	if errScan != nil {
		log.Fatalf("Scan error: %v", errScan)
	}
}

// parsePorts parses the port argument string into a slice of port numbers
func parsePorts(portsArg string) []int {
	var result []int
	
	// Split by comma
	parts := strings.Split(portsArg, ",")
	
	for _, part := range parts {
		// Check if it's a range (contains "-")
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				log.Printf("Invalid port range: %s, skipping", part)
				continue
			}
			
			start, err1 := strconv.Atoi(rangeParts[0])
			end, err2 := strconv.Atoi(rangeParts[1])
			
			if err1 != nil || err2 != nil || start > end {
				log.Printf("Invalid port range: %s, skipping", part)
				continue
			}
			
			// Add all ports in the range
			for port := start; port <= end; port++ {
				if port > 0 && port < 65536 {
					result = append(result, port)
				}
			}
		} else {
			// It's a single port
			port, err := strconv.Atoi(part)
			if err != nil || port <= 0 || port >= 65536 {
				log.Printf("Invalid port: %s, skipping", part)
				continue
			}
			result = append(result, port)
		}
	}
	
	return result
}
