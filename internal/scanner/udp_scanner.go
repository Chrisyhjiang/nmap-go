package scanner

import (
	"fmt"
	"net"
	"time"
)

// UDPScan performs a basic UDP scan and uses unified printing for open ports
func UDPScan(ip string, iface *net.Interface) error {
	var openPorts []int

	// Revert to scanning the first 1000 ports
	for port := 1; port <= 1000; port++ {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("udp", address, time.Second*1)
		if err != nil {
			continue // Skip closed ports
		}
		defer conn.Close()

		openPorts = append(openPorts, port)
	}

	PrintResults(openPorts, ip)
	return nil
}
