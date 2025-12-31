// Package engine provides the concurrent scan execution engine.
package engine

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"

	"maki/internal/network"
	"maki/internal/scanner"
)

// Engine coordinates concurrent scanning operations.
type Engine struct {
	scanner      scanner.Scanner
	workers      int
	showProgress bool
}

// New creates a new scan engine.
func New(s scanner.Scanner, workers int) *Engine {
	if workers <= 0 {
		workers = runtime.NumCPU() * 10
		if workers > 100 {
			workers = 100
		}
	}

	return &Engine{
		scanner:      s,
		workers:      workers,
		showProgress: true,
	}
}

// SetShowProgress enables or disables progress output.
func (e *Engine) SetShowProgress(show bool) {
	e.showProgress = show
}

// Scan runs the scanner against all target IPs concurrently.
func (e *Engine) Scan(ctx context.Context, targets []string) []scanner.Result {
	var (
		results []scanner.Result
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	jobs := make(chan string, len(targets))

	var scanned int
	var progressMu sync.Mutex

	// Start worker goroutines
	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					result := e.scanner.Scan(ctx, ip)

					mu.Lock()
					results = append(results, result)
					mu.Unlock()

					if e.showProgress {
						progressMu.Lock()
						scanned++
						printProgress(scanned, len(targets))
						progressMu.Unlock()
					}
				}
			}
		}()
	}

	// Send jobs to workers
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)

	wg.Wait()

	if e.showProgress {
		fmt.Println() // Newline after progress bar
	}

	// Sort results by IP address
	sort.Slice(results, func(i, j int) bool {
		ip1 := net.ParseIP(results[i].IP)
		ip2 := net.ParseIP(results[j].IP)
		return network.IPToUint32(ip1) < network.IPToUint32(ip2)
	})

	return results
}

// printProgress displays a progress bar.
func printProgress(current, total int) {
	percentage := float64(current) / float64(total) * 100
	barWidth := 40
	filled := int(float64(barWidth) * float64(current) / float64(total))

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	fmt.Printf("\r[%s] %3.0f%% (%d/%d)", bar, percentage, current, total)
}
