// Package icmp implements ICMP echo (ping) based host discovery.
package icmp

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"maki/internal/scanner"
)

// Scanner implements ICMP ping scanning using the system ping command.
type Scanner struct {
	timeout time.Duration
}

// New creates a new ICMP scanner with the given timeout.
func New(timeout time.Duration) *Scanner {
	return &Scanner{
		timeout: timeout,
	}
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "ICMP Ping"
}

// Scan performs an ICMP ping scan on the target IP.
func (s *Scanner) Scan(ctx context.Context, ip string) scanner.Result {
	start := time.Now()

	cmd := s.buildPingCommand(ctx, ip)
	err := cmd.Run()
	duration := time.Since(start)

	if err == nil {
		return scanner.Result{
			IP:       ip,
			Alive:    true,
			Method:   s.Name(),
			Details:  fmt.Sprintf("Response in %v", duration.Round(time.Millisecond)),
			Duration: duration,
		}
	}

	return scanner.Result{
		IP:       ip,
		Alive:    false,
		Method:   s.Name(),
		Details:  "No response",
		Duration: duration,
	}
}

// buildPingCommand creates the appropriate ping command for the current OS.
func (s *Scanner) buildPingCommand(ctx context.Context, ip string) *exec.Cmd {
	switch runtime.GOOS {
	case "windows":
		return exec.CommandContext(ctx, "ping", "-n", "1", "-w", fmt.Sprintf("%d", s.timeout.Milliseconds()), ip)
	case "darwin":
		return exec.CommandContext(ctx, "ping", "-c", "1", "-W", fmt.Sprintf("%d", int(s.timeout.Seconds())*1000), ip)
	default: // Linux
		return exec.CommandContext(ctx, "ping", "-c", "1", "-W", fmt.Sprintf("%d", int(s.timeout.Seconds())), ip)
	}
}
