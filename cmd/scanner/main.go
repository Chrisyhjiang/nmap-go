package main

import (
    "fmt"
    "log"

    "github.com/christopherjiang/nmap-go/pkg"
)

func main() {
    host := "192.168.1.1" // Replace with the target IP address
    iface := "en0"        // Replace with your network interface name (e.g., "en0" for macOS)
    
    // SYN scan
    synScanner, err := pkg.NewPortScanner(host, "syn", iface)
    if err != nil {
        log.Fatalf("Error creating SYN scanner: %v", err)
    }
    fmt.Println("Performing SYN scan:")
    synScanner.ScanRange(1, 1024)

    // TCP connect scan
    tcpScanner, err := pkg.NewPortScanner(host, "tcp", "")
    if err != nil {
        log.Fatalf("Error creating TCP scanner: %v", err)
    }
    fmt.Println("\nPerforming TCP connect scan:")
    tcpScanner.ScanRange(1, 1024)

    // UDP scan
    udpScanner, err := pkg.NewPortScanner(host, "udp", "")
    if err != nil {
        log.Fatalf("Error creating UDP scanner: %v", err)
    }
    fmt.Println("\nPerforming UDP scan:")
    udpScanner.ScanRange(1, 1024)
}