package scanner

import (
    "fmt"
    "net"
    "time"
)

type UdpScanner struct{}

func (s *UdpScanner) Scan(host string, port int) bool {
    address := fmt.Sprintf("%s:%d", host, port)
    conn, err := net.DialTimeout("udp", address, time.Second)
    if err != nil {
        return false
    }
    defer conn.Close()
    
    // Send a UDP packet
    _, err = conn.Write([]byte("Hello, UDP Server"))
    if err != nil {
        return false
    }
    
    // Set a read deadline
    conn.SetReadDeadline(time.Now().Add(time.Second))
    
    // Try to read the response
    buffer := make([]byte, 1024)
    _, err = conn.Read(buffer)
    if err != nil {
        // If it's a timeout error, the port might be open but not responding
        if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
            return true
        }
        // For other errors, consider the port closed
        return false
    }
    
    // If we received a response, the port is definitely open
    return true
}