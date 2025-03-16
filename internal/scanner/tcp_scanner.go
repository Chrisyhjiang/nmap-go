package scanner

import (
	"log"
	"net"
	"runtime"
	"sync"

	"github.com/Chrisyhjiang/nmap-go/pkg" // Assuming ImportantPorts is defined in pkg/portscanner.go
)

// TCPScan performs a TCP connect scan and uses unified printing for open ports
func TCPScan(ip string, iface *net.Interface, ports []int) error {
	var openPorts []int
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// Determine the number of worker goroutines to use
	numWorkers := runtime.NumCPU() * 4 // Use 4 workers per CPU core
	if numWorkers > 100 {
		numWorkers = 100 // Cap at 100 workers to avoid overwhelming the system
	}

	// Create a channel to distribute ports to workers
	portsChan := make(chan int)

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				if IsPortOpen(ip, port) {
					mutex.Lock()
					openPorts = append(openPorts, port)
					mutex.Unlock()
					// Only log open ports
					log.Printf("Port %d is open", port)
				}
				// Don't log closed ports to reduce verbosity
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
