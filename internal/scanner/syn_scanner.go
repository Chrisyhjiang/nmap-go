package scanner

import (
    "fmt"
    "log"
    "net"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

type SynScanner struct {
    handle *pcap.Handle
    iface  *net.Interface
    localIP net.IP
}

func NewSynScanner(ifaceName string) (*SynScanner, error) {
    iface, err := net.InterfaceByName(ifaceName)
    if err != nil {
        return nil, err
    }

    handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
    if err != nil {
        return nil, err
    }

    addrs, err := iface.Addrs()
    if err != nil {
        return nil, err
    }

    var localIP net.IP
    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok {
            if ipnet.IP.To4() != nil {
                localIP = ipnet.IP
                break
            }
        }
    }

    if localIP == nil {
        return nil, fmt.Errorf("couldn't find local IPv4 address for interface %s", ifaceName)
    }

    return &SynScanner{handle: handle, iface: iface, localIP: localIP}, nil
}

func (s *SynScanner) Scan(host string, port int) bool {
    ip := net.ParseIP(host)
    if ip == nil {
        log.Printf("Invalid IP address: %s", host)
        return false
    }

    // Craft SYN packet
    ethernetLayer := &layers.Ethernet{SrcMAC: s.iface.HardwareAddr, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}
    ipLayer := &layers.IPv4{SrcIP: s.localIP, DstIP: ip, Protocol: layers.IPProtocolTCP}
    tcpLayer := &layers.TCP{SrcPort: layers.TCPPort(12345), DstPort: layers.TCPPort(port), SYN: true}
    tcpLayer.SetNetworkLayerForChecksum(ipLayer)

    buffer := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
    if err := gopacket.SerializeLayers(buffer, opts, ethernetLayer, ipLayer, tcpLayer); err != nil {
        log.Printf("Error serializing packet: %v", err)
        return false
    }

    // Send packet
    if err := s.handle.WritePacketData(buffer.Bytes()); err != nil {
        log.Printf("Error sending packet: %v", err)
        return false
    }

    // Listen for response
    start := time.Now()
    for time.Since(start) < time.Second {
        packet, _, err := s.handle.ReadPacketData()
        if err != nil {
            continue
        }
        if tcp := gopacket.NewPacket(packet, layers.LayerTypeTCP, gopacket.Default).Layer(layers.LayerTypeTCP); tcp != nil {
            tcpLayer, _ := tcp.(*layers.TCP)
            if tcpLayer.SrcPort == layers.TCPPort(port) && tcpLayer.SYN && tcpLayer.ACK {
                return true
            }
        }
    }
    return false
}