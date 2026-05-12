// Package output handles formatting and exporting scan results.
package output

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"maki/internal/scanner"
)

// ScanType represents the type of scan performed.
type ScanType string

const (
	ScanTypeICMP ScanType = "ICMP_SCAN"
	ScanTypeTCP  ScanType = "TCP_SCAN"
	ScanTypeARP  ScanType = "ARP_SCAN"
	ScanTypeDNS  ScanType = "DNS_SCAN"
)

// ScanData holds results for a specific scan type.
type ScanData struct {
	Type    ScanType
	Results []scanner.Result
}

// Report contains all scan results for export.
type Report struct {
	Subnet    string
	Timestamp time.Time
	Scans     []ScanData
}

// NewReport creates a new report for the given subnet.
func NewReport(subnet string) *Report {
	return &Report{
		Subnet:    subnet,
		Timestamp: time.Now(),
		Scans:     make([]ScanData, 0),
	}
}

// AddScan adds scan results to the report.
func (r *Report) AddScan(scanType ScanType, results []scanner.Result) {
	r.Scans = append(r.Scans, ScanData{
		Type:    scanType,
		Results: results,
	})
}

// Format generates the formatted report string.
func (r *Report) Format() string {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("Result of: %s\n", r.Subnet))
	sb.WriteString(fmt.Sprintf("Scan time: %s\n", r.Timestamp.Format("2006-01-02 15:04:05")))
	sb.WriteString(strings.Repeat("-", 50) + "\n\n")

	// Each scan section
	for _, scan := range r.Scans {
		sb.WriteString(fmt.Sprintf("%s:\n", scan.Type))

		aliveCount := 0
		for _, result := range scan.Results {
			if result.Alive {
				aliveCount++
				// Format: IP address followed by details if available
				if result.Details != "" && result.Details != "No response" {
					sb.WriteString(fmt.Sprintf("%s (%s)\n", result.IP, result.Details))
				} else {
					sb.WriteString(fmt.Sprintf("%s\n", result.IP))
				}
			}
		}

		if aliveCount == 0 {
			sb.WriteString("No live hosts found\n")
		}

		sb.WriteString("\n")
	}

	// Summary
	sb.WriteString(strings.Repeat("-", 50) + "\n")
	sb.WriteString("SUMMARY:\n")
	for _, scan := range r.Scans {
		alive := countAlive(scan.Results)
		sb.WriteString(fmt.Sprintf("  %s: %d hosts alive\n", scan.Type, alive))
	}

	return sb.String()
}

// UniqueHosts returns a sorted, deduplicated list of IPs that were
// found alive across all scans in the report.
func (r *Report) UniqueHosts() []string {
	seen := make(map[string]struct{})
	for _, scan := range r.Scans {
		for _, result := range scan.Results {
			if result.Alive {
				seen[result.IP] = struct{}{}
			}
		}
	}

	hosts := make([]string, 0, len(seen))
	for ip := range seen {
		hosts = append(hosts, ip)
	}

	sort.Slice(hosts, func(i, j int) bool {
		ipI := net.ParseIP(hosts[i])
		ipJ := net.ParseIP(hosts[j])
		if ipI == nil || ipJ == nil {
			return hosts[i] < hosts[j]
		}
		return bytes.Compare(ipI.To16(), ipJ.To16()) < 0
	})

	return hosts
}

// SaveToFile writes the report and the deduplicated hosts list to the
// specified directory. It returns the path to result.txt.
//
// When invoked under sudo, newly-created files and directories are
// chown'd back to the invoking user (SUDO_UID/SUDO_GID) so output is
// not left root-owned. `~` is expanded relative to SUDO_USER's home
// when running under sudo.
func (r *Report) SaveToFile(dirPath string) (string, error) {
	// Expand home directory if needed
	if strings.HasPrefix(dirPath, "~") {
		home, err := invokingUserHome()
		if err != nil {
			return "", fmt.Errorf("cannot expand home directory: %v", err)
		}
		dirPath = filepath.Join(home, dirPath[1:])
	}

	// Clean the path
	dirPath = filepath.Clean(dirPath)

	// Capture any path components that don't exist yet so we can chown
	// them after MkdirAll creates them.
	createdDirs := missingPathComponents(dirPath)

	// Check if directory exists, create if not
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return "", fmt.Errorf("cannot create directory: %v", err)
	}

	uid, gid, hasSudoOwner := sudoOwner()
	if hasSudoOwner {
		for _, d := range createdDirs {
			_ = os.Chown(d, uid, gid)
		}
	}

	// Create the result file
	filePath := filepath.Join(dirPath, "result.txt")

	content := r.Format()

	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("cannot write file: %v", err)
	}
	if hasSudoOwner {
		_ = os.Chown(filePath, uid, gid)
	}

	// Write hosts.txt: one IP per line, suitable for `nmap -iL`.
	hostsPath := filepath.Join(dirPath, "hosts.txt")
	hosts := r.UniqueHosts()
	var hostsContent string
	if len(hosts) > 0 {
		hostsContent = strings.Join(hosts, "\n") + "\n"
	}
	if err := os.WriteFile(hostsPath, []byte(hostsContent), 0644); err != nil {
		return "", fmt.Errorf("cannot write hosts file: %v", err)
	}
	if hasSudoOwner {
		_ = os.Chown(hostsPath, uid, gid)
	}

	return filePath, nil
}

// sudoOwner returns the UID/GID of the user who invoked sudo, if any.
func sudoOwner() (int, int, bool) {
	uidStr := os.Getenv("SUDO_UID")
	gidStr := os.Getenv("SUDO_GID")
	if uidStr == "" || gidStr == "" {
		return 0, 0, false
	}
	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		return 0, 0, false
	}
	gid, err := strconv.Atoi(gidStr)
	if err != nil {
		return 0, 0, false
	}
	return uid, gid, true
}

// invokingUserHome returns the home directory of the user who invoked
// the program. Under sudo, this is SUDO_USER's home rather than root's.
func invokingUserHome() (string, error) {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		if u, err := user.Lookup(sudoUser); err == nil && u.HomeDir != "" {
			return u.HomeDir, nil
		}
	}
	return os.UserHomeDir()
}

// missingPathComponents returns the list of ancestor directories of p
// (including p itself) that do not yet exist on disk, ordered from
// outermost to innermost.
func missingPathComponents(p string) []string {
	var missing []string
	cur := p
	for {
		if _, err := os.Stat(cur); err == nil {
			break
		}
		missing = append([]string{cur}, missing...)
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return missing
}

// countAlive counts the number of alive hosts in results.
func countAlive(results []scanner.Result) int {
	count := 0
	for _, r := range results {
		if r.Alive {
			count++
		}
	}
	return count
}
