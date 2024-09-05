package scanner

import (
	"fmt"
	"net"
	"time"
	"github.com/Chrisyhjiang/nmap-go/pkg" // Assuming ImportantPorts is defined in pkg/portscanner.go
)

// UDPScan performs a basic UDP scan and uses unified printing for open ports
func UDPScan(ip string, iface *net.Interface) error {
	var openPorts []int

	// Loop through ImportantPorts instead of scanning the first 1000 ports
	for port := range pkg.ImportantPorts {
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
