package scanner

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/Chrisyhjiang/nmap-go/pkg" // Assuming ImportantPorts is defined in pkg/portscanner.go
)

// SYNScan performs a SYN scan using raw sockets and gopacket, and prints open ports
func SYNScan(ip string, iface *net.Interface) error {
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening device %s: %v", iface.Name, err)
	}
	defer handle.Close()

	srcIP := getSourceIP(iface)
	dstIP := net.ParseIP(ip)

	// Resolve the destination MAC address using ARP
	dstMAC, err := resolveMACAddress(iface, srcIP, dstIP)
	if err != nil {
		return fmt.Errorf("failed to resolve MAC address for %s: %v", ip, err)
	}

	var openPorts []int

	// Loop through ImportantPorts instead of scanning the first 1000 ports
	for port := range pkg.ImportantPorts {
		if sendSYN(handle, iface.HardwareAddr, dstIP, dstMAC, port) {
			openPorts = append(openPorts, port)
		}
	}

	// Use the PrintResults function from scanner.go
	PrintResults(openPorts, ip)
	return nil
}

// sendSYN sends a SYN packet to a specific port and listens for the SYN-ACK response
func sendSYN(handle *pcap.Handle, srcMAC net.HardwareAddr, dstIP net.IP, dstMAC net.HardwareAddr, dstPort int) bool {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{SrcIP: dstIP, DstIP: dstIP}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(54321),
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
		log.Printf("Error serializing packet: %v", err)
		return false
	}

	// Send the SYN packet
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Printf("Error sending packet to port %d: %v", dstPort, err)
		return false
	}

	// Capture the response
	return captureSYNACK(handle, dstIP, dstIP, dstPort)
}

// resolveMACAddress performs ARP request to resolve the MAC address of the target IP
func resolveMACAddress(iface *net.Interface, srcIP, dstIP net.IP) (net.HardwareAddr, error) {
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	// Get the source MAC address from the provided interface
	srcMAC := iface.HardwareAddr
	if srcMAC == nil {
		return nil, fmt.Errorf("failed to get MAC address for interface %s", iface.Name)
	}

	// Create an ARP request packet
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Broadcast MAC address
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet, // Ethernet (6-byte addresses)
		Protocol:          layers.EthernetTypeIPv4, // IPv4 (4-byte addresses)
		HwAddressSize:     6,                       // Hardware address size: 6 bytes for MAC addresses
		ProtAddressSize:   4,                       // Protocol address size: 4 bytes for IPv4
		Operation:         layers.ARPRequest,       // ARP request operation
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Target MAC address unknown
		DstProtAddress:    dstIP.To4(),
	}

	// Serialize and send the ARP request
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buffer, options, &eth, &arp)
	if err != nil {
		return nil, fmt.Errorf("error serializing ARP request: %v", err)
	}

	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error sending ARP request: %v", err)
	}

	// Listen for the ARP reply
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arpReply, _ := arpLayer.(*layers.ARP)
			if net.IP(arpReply.SourceProtAddress).Equal(dstIP) {
				// Return the MAC address from the ARP reply
				return net.HardwareAddr(arpReply.SourceHwAddress), nil
			}
		}
	}
	return nil, fmt.Errorf("ARP reply not received")
}

// captureSYNACK listens for SYN-ACK or RST response to determine port status
func captureSYNACK(handle *pcap.Handle, srcIP, dstIP net.IP, dstPort int) bool {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if int(tcp.DstPort) == 54321 && int(tcp.SrcPort) == dstPort {
				if tcp.SYN && tcp.ACK {
					// SYN-ACK indicates the port is open
					return true
				} else if tcp.RST {
					// RST indicates the port is closed
					return false
				}
			}
		}
	}
	// No response indicates the port may be filtered or unreachable
	return false
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
