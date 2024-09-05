package main

import (
	"fmt"
	"log"
	"os"

	"github.com/Chrisyhjiang/nmap-go/internal/scanner"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: nmap-go <scan-type> <ip-address>")
		fmt.Println("Scan types: tcp, syn, udp")
		os.Exit(1)
	}

	// Take in the scan type and IP address from the command-line arguments
	scanType := os.Args[1] // First argument is the scan type
	ip := os.Args[2]       // Second argument is the IP address

	// Get the best network interface
	iface, err := scanner.GetBestInterface(ip)
	if err != nil {
		log.Fatalf("Error determining the best interface: %v", err)
	}

	fmt.Printf("Scanning IP: %s using interface: %s with scan type: %s\n", ip, iface.Name, scanType)

	// Switch based on scan type
	var errScan error
	switch scanType {
	case "tcp":
		errScan = scanner.TCPScan(ip, iface) // Scan first 1000 ports for TCP
	case "syn":
		errScan = scanner.SYNScan(ip, iface) // Scan first 1000 ports for SYN
	case "udp":
		errScan = scanner.UDPScan(ip, iface) // Scan first 1000 ports for UDP
	default:
		fmt.Printf("Unknown scan type: %s\n", scanType)
		os.Exit(1)
	}

	if errScan != nil {
		log.Fatalf("Scan error: %v", errScan)
	}
}
