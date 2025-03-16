package scanner

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/Chrisyhjiang/nmap-go/pkg" // Assuming ImportantPorts is defined in pkg/portscanner.go
)

// UDPScan performs a basic UDP scan and uses unified printing for open ports
func UDPScan(ip string, iface *net.Interface, ports []int) error {
	var openPorts []int
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// Determine the number of worker goroutines to use
	numWorkers := runtime.NumCPU() * 2 // Use 2 workers per CPU core for UDP (less aggressive than TCP)
	if numWorkers > 50 {
		numWorkers = 50 // Cap at 50 workers to avoid overwhelming the system
	}

	// Create a channel to distribute ports to workers
	portsChan := make(chan int)

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				address := fmt.Sprintf("%s:%d", ip, port)
				conn, err := net.DialTimeout("udp", address, time.Second*1)
				if err != nil {
					continue // Skip closed ports
				}
				
				// Important: Close connection inside the goroutine to prevent resource leaks
				conn.Close()
				
				mutex.Lock()
				openPorts = append(openPorts, port)
				mutex.Unlock()
				
				// Only log open ports
				log.Printf("Port %d is open", port)
			}
		}()
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

	PrintResults(openPorts, ip)
	return nil
}
