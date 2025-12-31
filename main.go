package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"maki/internal/engine"
	"maki/internal/network"
	"maki/internal/output"
	"maki/internal/scanner"
	"maki/internal/scanner/icmp"
)

func main() {
	printBanner()

	// Get subnet from user
	subnet := getUserInput("Enter target subnet (e.g., 192.168.1.0/24): ")
	if subnet == "" {
		fmt.Println("Error: No subnet provided")
		os.Exit(1)
	}

	// Parse the subnet
	targets, err := network.ParseCIDR(subnet)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n📡 Target range: %s (%d hosts)\n\n", subnet, len(targets))

	// Ask for output directory
	outputDir := getUserInput("Enter output directory path (leave empty to skip file export): ")

	// Create report
	report := output.NewReport(subnet)

	// For now, only ICMP scan is available
	fmt.Println("\nStarting ICMP Ping Scan...")
	fmt.Println()

	// Create scanner and engine
	timeout := 2 * time.Second
	icmpScanner := icmp.New(timeout)
	scanEngine := engine.New(icmpScanner, 0) // 0 = auto-detect workers

	// Run the scan
	ctx := context.Background()
	results := scanEngine.Scan(ctx, targets)

	// Add results to report
	report.AddScan(output.ScanTypeICMP, results)

	// Print results to console
	printResults(results)

	// Export to file if path provided
	if outputDir != "" {
		filePath, err := report.SaveToFile(outputDir)
		if err != nil {
			fmt.Printf("\n❌ Error saving results: %v\n", err)
		} else {
			fmt.Printf("\n✅ Results saved to: %s\n", filePath)
		}
	}
}

func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════╗
║              🔍 Network Host Discovery Tool 🔍                ║
╚═══════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}

func getUserInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func printResults(results []scanner.Result) {
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("                        SCAN RESULTS                            ")
	fmt.Println("════════════════════════════════════════════════════════════════")

	aliveCount := 0
	for _, r := range results {
		if r.Alive {
			aliveCount++
			fmt.Printf("  ✅ %-15s  %s\n", r.IP, r.Details)
		}
	}

	if aliveCount == 0 {
		fmt.Println("  No live hosts found.")
	}

	fmt.Println()
	fmt.Println("────────────────────────────────────────────────────────────────")
	fmt.Printf("  Total: %d hosts | Alive: %d | No response: %d\n",
		len(results), aliveCount, len(results)-aliveCount)
	fmt.Println("════════════════════════════════════════════════════════════════")
}
