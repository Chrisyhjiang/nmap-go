package scanner

import (
	"net"
)

// TCPScan performs a TCP connect scan and uses unified printing for open ports
func TCPScan(ip string, iface *net.Interface) error {
	var openPorts []int

	// Revert to scanning the first 1000 ports
	for port := 1; port <= 1000; port++ {
		if IsPortOpen(ip, port) {
			openPorts = append(openPorts, port)
		}
	}

	PrintResults(openPorts, ip)
	return nil
}
