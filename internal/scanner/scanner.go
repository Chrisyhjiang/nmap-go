package scanner

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// GetBestInterface identifies the best network interface to scan the target IP.
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

	// Store a fallback interface in case no matching subnet is found
	var fallbackIface *net.Interface

	// Iterate over each network interface
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 { // Skip interfaces that are down
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

			// If the target IP is in the same subnet as one of the interface addresses, return this interface
			if ipNet.Contains(parsedTargetIP) {
				return &iface, nil
			}

			// Store the first valid interface as a fallback
			if fallbackIface == nil {
				fallbackIface = &iface
			}
		}
	}

	// If no matching subnet was found, return the first valid interface as a fallback
	if fallbackIface != nil {
		return fallbackIface, nil
	}

	return nil, errors.New("no suitable network interface found")
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
