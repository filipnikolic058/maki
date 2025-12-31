// Package scanner defines the common interface and types for all scanners.
package scanner

import (
	"context"
	"time"
)

// Result holds the result of a host scan.
type Result struct {
	IP       string
	Alive    bool
	Method   string
	Details  string
	Duration time.Duration
}

// Scanner defines the interface that all scanner implementations must satisfy.
type Scanner interface {
	// Scan performs a scan on the given IP address.
	Scan(ctx context.Context, ip string) Result

	// Name returns the human-readable name of the scanner.
	Name() string
}
