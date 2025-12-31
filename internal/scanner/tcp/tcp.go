// Package tcp implements TCP connect scanning for network discovery.
package tcp

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"maki/internal/scanner"
)

// Common ports to scan (standard network services).
var commonPorts = []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389, 8080}

// Scanner implements the Scanner interface for TCP connect scanning.
type Scanner struct {
	timeout time.Duration
	ports   []int
}

// New creates a new TCP scanner with the specified timeout.
func New(timeout time.Duration) *Scanner {
	return &Scanner{
		timeout: timeout,
		ports:   commonPorts,
	}
}

// Name returns the human-readable name of this scanner.
func (s *Scanner) Name() string {
	return "TCP Connect Scan"
}

// Scan performs a TCP connect scan on the given IP address.
// It scans all common ports concurrently and returns a Result indicating
// which ports are open.
func (s *Scanner) Scan(ctx context.Context, ip string) scanner.Result {
	start := time.Now()
	openPorts := s.scanPorts(ctx, ip)
	duration := time.Since(start)

	if len(openPorts) > 0 {
		return scanner.Result{
			IP:       ip,
			Alive:    true,
			Method:   s.Name(),
			Details:  fmt.Sprintf("Ports: %s", formatPorts(openPorts)),
			Duration: duration,
		}
	}

	return scanner.Result{
		IP:       ip,
		Alive:    false,
		Method:   s.Name(),
		Details:  "No open ports",
		Duration: duration,
	}
}

// scanPorts scans all configured ports for the given IP address concurrently.
func (s *Scanner) scanPorts(ctx context.Context, ip string) []int {
	var (
		openPorts []int
		mu        sync.Mutex
		wg        sync.WaitGroup
	)

	for _, port := range s.ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			// Check if context is cancelled
			select {
			case <-ctx.Done():
				return
			default:
				if s.isPortOpen(ctx, ip, p) {
					mu.Lock()
					openPorts = append(openPorts, p)
					mu.Unlock()
				}
			}
		}(port)
	}

	wg.Wait()
	sort.Ints(openPorts)
	return openPorts
}

// isPortOpen checks if a specific port is open on the given IP address.
func (s *Scanner) isPortOpen(ctx context.Context, ip string, port int) bool {
	address := fmt.Sprintf("%s:%d", ip, port)

	dialer := &net.Dialer{
		Timeout: s.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}

	conn.Close()
	return true
}

// formatPorts formats a slice of port numbers as a comma-separated string.
func formatPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	result := fmt.Sprintf("%d", ports[0])
	for i := 1; i < len(ports); i++ {
		result += fmt.Sprintf(",%d", ports[i])
	}
	return result
}
