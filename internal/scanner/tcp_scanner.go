package scanner

import (
	"net"
	"github.com/Chrisyhjiang/nmap-go/pkg" // Assuming ImportantPorts is defined in pkg/portscanner.go
)

// TCPScan performs a TCP connect scan and uses unified printing for open ports
func TCPScan(ip string, iface *net.Interface) error {
	var openPorts []int

	// Loop through ImportantPorts instead of scanning the first 1000 ports
	for port := range pkg.ImportantPorts {
		if IsPortOpen(ip, port) {
			openPorts = append(openPorts, port)
		}
	}

	PrintResults(openPorts, ip)
	return nil
}
