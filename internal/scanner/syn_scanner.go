package scanner

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/Chrisyhjiang/nmap-go/pkg" // Assuming ImportantPorts is defined in pkg/portscanner.go
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// SYNScan performs a SYN scan using raw sockets and gopacket, and prints open ports
func SYNScan(ip string, iface *net.Interface, ports []int) error {
	// Special case for localhost - use TCP connect scan instead of SYN scan
	if ip == "127.0.0.1" || ip == "localhost" {
		log.Printf("Detected localhost scan, using TCP connect scan instead of SYN scan for better reliability")
		return TCPScan(ip, iface, ports)
	}

	srcIP := getSourceIP(iface)
	if srcIP == nil {
		return fmt.Errorf("failed to get source IP for interface %s", iface.Name)
	}

	dstIP := net.ParseIP(ip)
	if dstIP == nil {
		return fmt.Errorf("invalid destination IP address: %s", ip)
	}

	log.Printf("Performing SYN scan on %s using interface %s", ip, iface.Name)

	var openPorts []int
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// Determine the number of worker goroutines to use
	// SYN scanning is more resource-intensive, so use fewer workers
	numWorkers := runtime.NumCPU()
	if numWorkers > 10 {
		numWorkers = 10 // Cap at 10 workers to avoid overwhelming the system
	}

	// Create a channel to distribute ports to workers
	portsChan := make(chan int)
	
	// Create a rate limiter to avoid overwhelming the network
	// 100 packets per second (10ms between packets)
	rateLimiter := time.Tick(10 * time.Millisecond)

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			// Each worker gets its own pcap handle
			handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
			if err != nil {
				log.Printf("Worker %d: Error opening device %s: %v", workerID, iface.Name, err)
				return
			}
			defer handle.Close()
			
			for port := range portsChan {
				<-rateLimiter // Rate limit the packet sending
				
				// Only log at debug level (commented out for less verbosity)
				// log.Printf("Worker %d: Scanning port %d", workerID, port)
				if sendSYN(handle, iface.HardwareAddr, srcIP, dstIP, port) {
					mutex.Lock()
					openPorts = append(openPorts, port)
					mutex.Unlock()
					// Only log open ports
					log.Printf("Port %d is open", port)
				}
				// Don't log closed ports to reduce verbosity
			}
		}(i)
	}

	// Send ports to workers
	go func() {
		// If specific ports are provided, scan only those
		if len(ports) > 0 {
			for _, port := range ports {
				portsChan <- port
			}
		} else {
			// Otherwise, scan the predefined ImportantPorts
			for port := range pkg.ImportantPorts {
				portsChan <- port
			}
		}
		close(portsChan) // Close the channel when all ports are sent
	}()

	// Wait for all workers to finish
	wg.Wait()

	// Print results
	PrintResults(openPorts, ip)
	return nil
}

// sendSYN sends a SYN packet to a specific port and listens for the SYN-ACK response
func sendSYN(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP, dstPort int) bool {
	// Use a consistent source port that will be checked in captureSYNACK
	sourcePort := layers.TCPPort(54321)

	// Determine if we're scanning localhost
	isLocalhost := dstIP.IsLoopback() || dstIP.Equal(srcIP)

	var dstMAC net.HardwareAddr
	if isLocalhost {
		// For localhost, use our own MAC address
		dstMAC = srcMAC
	} else {
		// For remote hosts, try to resolve MAC address or use broadcast
		resolvedMAC, err := resolveMAC(dstIP.String())
		if err != nil {
			// Fall back to broadcast if resolution fails
			dstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		} else {
			dstMAC = resolvedMAC
		}
	}

	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: sourcePort,        // Use consistent source port
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}

	// Create the buffer and serialize the packet layers
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	// Set the network layer for the TCP checksum
	tcp.SetNetworkLayerForChecksum(&ip)

	err := gopacket.SerializeLayers(buffer, options, &eth, &ip, &tcp)
	if err != nil {
		// Reduce verbosity - only log errors at debug level
		// log.Printf("Error serializing packet for port %d: %v", dstPort, err)
		return false
	}

	// Send the complete TCP packet
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		// Reduce verbosity - only log errors at debug level
		// log.Printf("Error sending SYN packet to port %d: %v", dstPort, err)
		return false
	}

	// Capture the response
	return captureSYNACK(handle, srcIP, dstIP, dstPort)
}

// captureSYNACK listens for SYN-ACK or RST response to determine port status
func captureSYNACK(handle *pcap.Handle, srcIP, dstIP net.IP, dstPort int) bool {
	// Set up a BPF filter to only capture relevant packets
	// This filter captures TCP packets from the target IP to our source IP
	// with either the SYN+ACK flags set or the RST flag set
	filter := fmt.Sprintf("tcp and src host %s and dst host %s and src port %d and dst port %d", 
		dstIP.String(), srcIP.String(), dstPort, 54321)
	
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Printf("Error setting BPF filter: %v", err)
		return false
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	// Create a timeout ticker to avoid waiting indefinitely
	// Reduce timeout for concurrent scanning
	timeout := time.After(2 * time.Second)

	for {
		select {
		case packet := <-packetSource.Packets():
			// Check for TCP layer
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				
				// Check if this is a response to our SYN packet
				if int(tcp.SrcPort) == dstPort && int(tcp.DstPort) == 54321 {
					if tcp.SYN && tcp.ACK {
						// SYN-ACK indicates the port is open
						return true
					} else if tcp.RST {
						// RST indicates the port is closed
						return false
					}
				}
			}
		case <-timeout:
			// Reset the BPF filter to not interfere with subsequent scans
			handle.SetBPFFilter("")
			return false
		}
	}
}

// getSourceIP determines the source IP address based on the network interface
func getSourceIP(iface *net.Interface) net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		log.Fatalf("Unable to get IP address for interface %s: %v", iface.Name, err)
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			return ipNet.IP
		}
	}
	return nil
}

// resolveMAC attempts to resolve an IP address to a MAC address
func resolveMAC(ip string) (net.HardwareAddr, error) {
	// For simplicity, we'll use a dummy implementation that returns an error
	// In a real implementation, you would use ARP to resolve the MAC address
	return nil, fmt.Errorf("MAC resolution not implemented")
}
