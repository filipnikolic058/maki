// Package arp implements ARP-based host discovery for local network scanning.
package arp

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"maki/internal/scanner"
)

// Scanner implements ARP scanning using the arping utility.
type Scanner struct {
	timeout time.Duration
}

// New creates a new ARP scanner with the given timeout.
func New(timeout time.Duration) *Scanner {
	return &Scanner{
		timeout: timeout,
	}
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "ARP Scan"
}

// Scan performs an ARP scan on the target IP by sending a single ARP request.
// ARP scanning only works on the local network segment.
func (s *Scanner) Scan(ctx context.Context, ip string) scanner.Result {
	start := time.Now()

	// Use arping to send ARP request to individual host
	macAddr, err := s.arpPing(ctx, ip)
	duration := time.Since(start)

	if err == nil && macAddr != "" {
		return scanner.Result{
			IP:       ip,
			Alive:    true,
			Method:   s.Name(),
			Details:  fmt.Sprintf("MAC: %s", macAddr),
			Duration: duration,
		}
	}

	return scanner.Result{
		IP:       ip,
		Alive:    false,
		Method:   s.Name(),
		Details:  "No ARP response",
		Duration: duration,
	}
}

// permissionWarningShown tracks if we've already shown the permission warning
var permissionWarningShown bool

// arpPing sends a single ARP request using the arping utility.
func (s *Scanner) arpPing(ctx context.Context, ip string) (string, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		// arping -c 1 -w timeout IP
		cmd = exec.CommandContext(ctx, "arping", "-c", "1", "-w", fmt.Sprintf("%d", int(s.timeout.Seconds())), ip)
	case "darwin":
		// arping -c 1 -W timeout IP
		cmd = exec.CommandContext(ctx, "arping", "-c", "1", "-W", fmt.Sprintf("%d", s.timeout.Milliseconds()), ip)
	default:
		return "", fmt.Errorf("arping not supported on %s", runtime.GOOS)
	}

	output, err := cmd.CombinedOutput()

	if err != nil {
		// Check for permission errors
		outputStr := string(output)
		if strings.Contains(outputStr, "Operation not permitted") ||
			strings.Contains(err.Error(), "Operation not permitted") ||
			strings.Contains(outputStr, "Permission denied") ||
			strings.Contains(err.Error(), "permission denied") {

			if !permissionWarningShown {
				fmt.Println("\n⚠️  WARNING: ARP scan requires root/sudo privileges")
				fmt.Println("   Please run with: sudo")
				fmt.Println()
				permissionWarningShown = true
			}
		}
		return "", err
	}

	// Parse MAC address from output
	mac := parseMAC(string(output))

	return mac, nil
}

// parseMAC extracts a MAC address from command output.
func parseMAC(output string) string {
	// Try to match MAC address patterns
	// Common formats: xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx
	patterns := []string{
		`([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})`,     // Standard MAC format
		`\[([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\]`, // Bracketed format
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(output)
		if len(matches) > 0 {
			mac := matches[0]
			// Clean up the MAC address
			mac = strings.Trim(mac, "[]")
			// Validate it's a proper MAC
			if _, err := net.ParseMAC(mac); err == nil {
				return strings.ToUpper(mac)
			}
		}
	}

	return ""
}
