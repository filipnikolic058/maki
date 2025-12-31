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
	"maki/internal/scanner/tcp"
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

	fmt.Printf("\n📡 Target range: %s (%d hosts)\n", subnet, len(targets))

	// Get scan type choice
	scanChoice := getScanChoice()

	// Ask for output directory
	outputDir := getUserInput("\nEnter output directory path (leave empty to skip file export): ")

	// Create report
	report := output.NewReport(subnet)

	// Execute scan based on user choice
	ctx := context.Background()
	timeout := 2 * time.Second

	switch scanChoice {
	case "1":
		runICMPScan(ctx, targets, report, timeout)
	case "2":
		runTCPScan(ctx, targets, report, timeout)
	case "3":
		runICMPScan(ctx, targets, report, timeout)
		runTCPScan(ctx, targets, report, timeout)
	default:
		fmt.Println("Invalid choice. Defaulting to ICMP scan.")
		runICMPScan(ctx, targets, report, timeout)
	}

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

func getScanChoice() string {
	fmt.Println("\nSelect scan type:")
	fmt.Println("  1. ICMP Ping Scan")
	fmt.Println("  2. TCP Connect Scan (common ports)")
	fmt.Println("  3. All Scans Combined")
	fmt.Println()
	return getUserInput("Enter your choice (1-3): ")
}

func runICMPScan(ctx context.Context, targets []string, report *output.Report, timeout time.Duration) {
	fmt.Println("\n🏓 Starting ICMP Ping Scan...")
	fmt.Println()

	icmpScanner := icmp.New(timeout)
	scanEngine := engine.New(icmpScanner, 0)
	results := scanEngine.Scan(ctx, targets)

	report.AddScan(output.ScanTypeICMP, results)
	printResults(results, "ICMP Ping Scan")
}

func runTCPScan(ctx context.Context, targets []string, report *output.Report, timeout time.Duration) {
	fmt.Println("\n🔌 Starting TCP Connect Scan...")
	fmt.Println()

	tcpScanner := tcp.New(timeout)
	scanEngine := engine.New(tcpScanner, 0)
	results := scanEngine.Scan(ctx, targets)

	report.AddScan(output.ScanTypeTCP, results)
	printResults(results, "TCP Connect Scan")
}

func printResults(results []scanner.Result, scanName string) {
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Printf("                    %s RESULTS                    \n", strings.ToUpper(scanName))
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
