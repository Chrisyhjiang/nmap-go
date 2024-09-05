package pkg

import (
    "fmt"
    "sync"

    "github.com/christopherjiang/nmap-go/internal/scanner"
)

type Scanner interface {
    Scan(host string, port int) bool
}

type PortScanner struct {
    host    string
    scanner Scanner
}

func NewPortScanner(host string, scanType string, iface string) (*PortScanner, error) {
    var s Scanner
    var err error
    switch scanType {
    case "syn":
        s, err = scanner.NewSynScanner(iface)
        if err != nil {
            return nil, err
        }
    case "tcp":
        s = &scanner.TcpConnectScanner{}
    case "udp":
        s = &scanner.UdpScanner{}
    default:
        return nil, fmt.Errorf("Invalid scan type")
    }
    return &PortScanner{host: host, scanner: s}, nil
}

func (ps *PortScanner) ScanPort(port int) {
    if ps.scanner.Scan(ps.host, port) {
        fmt.Printf("Port %d is open\n", port)
    }
}

func (ps *PortScanner) ScanRange(start, end int) {
    var wg sync.WaitGroup
    for port := start; port <= end; port++ {
        wg.Add(1)
        go func(p int) {
            defer wg.Done()
            ps.ScanPort(p)
        }(port)
    }
    wg.Wait()
}