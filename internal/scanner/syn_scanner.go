package scanner

import (
    "fmt"
    "log"
    "net"
	"time"

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
    if srcIP == nil {
        return fmt.Errorf("failed to get source IP for interface %s", iface.Name)
    }

    dstIP := net.ParseIP(ip)
    if dstIP == nil {
        return fmt.Errorf("invalid destination IP address: %s", ip)
    }

    log.Printf("Performing SYN scan on %s using interface %s", ip, iface.Name)

    var openPorts []int

    // Loop through ImportantPorts instead of scanning the first 1000 ports
    for port := range pkg.ImportantPorts {
        log.Printf("Scanning port %d", port)
        if sendSYN(handle, iface.HardwareAddr, srcIP, dstIP, port) {
            openPorts = append(openPorts, port)
            log.Printf("Port %d is open", port)
        } else {
            log.Printf("Port %d is closed or filtered", port)
        }
    }

    // Print results
    PrintResults(openPorts, ip)
    return nil
}

// sendSYN sends a SYN packet to a specific port and listens for the SYN-ACK response
func sendSYN(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP, dstPort int) bool {
    eth := layers.Ethernet{
        SrcMAC:       srcMAC,
        DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Default broadcast for all
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
        SrcPort: layers.TCPPort(54321), // Random source port
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
        log.Printf("Error serializing packet for port %d: %v", dstPort, err)
        return false
    }

    // Send the SYN packet
    err = handle.WritePacketData(buffer.Bytes())
    if err != nil {
        log.Printf("Error sending SYN packet to port %d: %v", dstPort, err)
        return false
    }

    // Capture the response
    return captureSYNACK(handle, srcIP, dstIP, dstPort)
}

// captureSYNACK listens for SYN-ACK or RST response to determine port status
func captureSYNACK(handle *pcap.Handle, srcIP, dstIP net.IP, dstPort int) bool {
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    // Create a timeout ticker to avoid waiting indefinitely
    timeout := time.After(3 * time.Second)

    for {
        select {
        case packet := <-packetSource.Packets():
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
        case <-timeout:
            log.Printf("Timeout reached, no response for port %d", dstPort)
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
