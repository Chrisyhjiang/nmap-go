package scanner

import (
	"fmt"
	"net"
	"time"
)

// Modify the GetBestInterface function to avoid virtual interfaces like "bridge100"
func GetBestInterface(targetIP string) (*net.Interface, error) {
	parsedTargetIP := net.ParseIP(targetIP)
	if parsedTargetIP == nil {
		return nil, fmt.Errorf("invalid target IP address: %s", targetIP)
	}

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %v", err)
	}

	// Iterate over each network interface
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 { // Skip interfaces that are down or loopback
			continue
		}

		// Exclude virtual interfaces like bridge100
		if iface.Name == "bridge100" || iface.Name == "vboxnet" || iface.Name == "docker0" {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil { // Ensure it's an IPv4 address
				continue
			}

			// Return this interface if it has a valid IPv4 address
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("no suitable network interface found")
}


// IsPortOpen checks if a TCP port is open using a simple connect scan
func IsPortOpen(ip string, port int) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, time.Second*1)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// PrintResults handles unified output for open ports
func PrintResults(openPorts []int, ip string) {
	fmt.Printf("Nmap scan report for %s\n", ip)
	fmt.Println("Host is up.")
	if len(openPorts) == 0 {
		fmt.Println("No open ports found.")
		return
	}

	for _, port := range openPorts {
		// Print open ports in the format "PORT/tcp open service"
		fmt.Printf("%d/tcp open\n", port)
	}
}
