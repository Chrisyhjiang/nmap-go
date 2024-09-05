package scanner

import (
    "fmt"
    "net"
    "time"
)

type TcpConnectScanner struct{}

func (s *TcpConnectScanner) Scan(host string, port int) bool {
    address := fmt.Sprintf("%s:%d", host, port)
    conn, err := net.DialTimeout("tcp", address, time.Second)
    if err != nil {
        return false
    }
    defer conn.Close()
    return true
}