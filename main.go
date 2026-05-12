package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"maki/internal/engine"
	"maki/internal/network"
	nmapscan "maki/internal/nmap"
	"maki/internal/output"
	"maki/internal/scanner"
	"maki/internal/scanner/arp"
	"maki/internal/scanner/icmp"
	"maki/internal/scanner/tcp"
)

func main() {
	printBanner()

	// Get subnet from user
	subnet := getUserInput("Enter target subnet (default: 192.168.1.0/24): ")
	if subnet == "" {
		subnet = "192.168.1.0/24"
		fmt.Printf("Using default subnet: %s\n", subnet)
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

	// Get network interface if ARP scan is selected
	var networkInterface string
	if scanChoice == "3" || scanChoice == "4" {
		networkInterface = getUserInput("\nEnter network interface for ARP scan (e.g., eth0, wlan0): ")
		if networkInterface == "" {
			fmt.Println("Error: Network interface is required for ARP scan")
			os.Exit(1)
		}
	}

	// Ask for output directory
	outputDir := getUserInput("\nEnter output directory path (leave empty to skip file export): ")

	// Create report
	report := output.NewReport(subnet)

	// Execute scan based on user choice
	ctx := context.Background()
	timeout := 2 * time.Second
	arpTimeout := 5 * time.Second // ARP needs more time for broadcast/response

	switch scanChoice {
	case "1":
		runICMPScan(ctx, targets, report, timeout)
	case "2":
		runTCPScan(ctx, targets, report, timeout)
	case "3":
		runARPScan(ctx, targets, report, arpTimeout, networkInterface)
	case "4":
		runICMPScan(ctx, targets, report, timeout)
		runTCPScan(ctx, targets, report, timeout)
		runARPScan(ctx, targets, report, arpTimeout, networkInterface)
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
			savedDir := filepath.Dir(filePath)
			hostsPath := filepath.Join(savedDir, "hosts.txt")
			fmt.Printf("\n✅ Results saved to: %s\n", filePath)
			fmt.Printf("✅ Host list saved to: %s (use with `nmap -iL %s`)\n", hostsPath, hostsPath)

			maybeRunNmap(hostsPath, savedDir, subnet, len(report.UniqueHosts()))
		}
	}
}

func maybeRunNmap(hostsPath, outputDir, subnet string, aliveCount int) {
	if aliveCount == 0 {
		return
	}

	fmt.Println()
	answer := strings.ToLower(getUserInput("Map this network with nmap -A -F? (y/N): "))
	if answer != "y" && answer != "yes" {
		return
	}

	fmt.Println("\n🗺️  Running nmap -A -F (this may take a while)...")
	fmt.Println()

	_, jsonPath, err := nmapscan.Run(hostsPath, outputDir, subnet)
	if err != nil {
		fmt.Printf("\n❌ nmap scan failed: %v\n", err)
		return
	}
	fmt.Printf("\n✅ Network map saved to: %s\n", jsonPath)
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
	fmt.Println("  3. ARP Scan (local network)")
	fmt.Println("  4. All Scans Combined")
	fmt.Println()
	return getUserInput("Enter your choice (1-4): ")
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

func runARPScan(ctx context.Context, targets []string, report *output.Report, timeout time.Duration, iface string) {
	fmt.Printf("\n📡 Starting ARP Scan on interface %s...\n", iface)
	fmt.Println()

	arpScanner := arp.New(timeout, iface)
	scanEngine := engine.New(arpScanner, 0)
	results := scanEngine.Scan(ctx, targets)

	report.AddScan(output.ScanTypeARP, results)
	printResults(results, "ARP Scan")
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
