# 🔍 Network Host Discovery Tool

A fast, multithreaded network host discovery tool written in Go. Supports multiple scanning techniques including ICMP ping, TCP connect, ARP scanning, and DNS reverse lookup.

## Features

- **ICMP Ping Scan** - Traditional ping using ICMP echo requests
- **TCP Connect Scan** - Probes common ports to detect live hosts
- **ARP Scan** - Discovers hosts on local network via ARP cache
- **DNS Reverse Lookup** - Finds hostnames via PTR records
- **Combined Scan** - Run all methods simultaneously
- **Multithreaded** - Fast scanning with configurable worker count
- **Cross-platform** - Works on Linux, macOS, and Windows
- **Export Results** - Save scan results to file

## Ports Scanned (TCP Mode)

| Port | Service |
|------|---------|
| 21   | FTP     |
| 22   | SSH     |
| 23   | Telnet  |
| 25   | SMTP    |
| 53   | DNS     |
| 80   | HTTP    |
| 110  | POP3    |
| 135  | RPC     |
| 139  | NetBIOS |
| 143  | IMAP    |
| 443  | HTTPS   |
| 445  | SMB     |
| 993  | IMAPS   |
| 995  | POP3S   |
| 3389 | RDP     |
| 8080 | HTTP-Alt|

## Installation

### Prerequisites
- Go 1.21 or later

### Build from Source

```bash
# Clone or download the files
cd host-discovery

# Build the binary
go build -o hostdiscovery .

# (Optional) Install system-wide
sudo mv hostdiscovery /usr/local/bin/
```

## Usage

```bash
# Run the tool
./hostdiscovery

# Or if installed system-wide
hostdiscovery
```

### Interactive Menu

1. Enter your target subnet in CIDR notation (e.g., `192.168.1.0/24`)
2. Select scan type:
   - `1` - ICMP Ping Scan
   - `2` - TCP Connect Scan  
   - `3` - ARP Scan
   - `4` - DNS Reverse Lookup
   - `5` - All Scans Combined

### Example Session

```
╔═══════════════════════════════════════════════════════════════╗
║              🔍 Network Host Discovery Tool 🔍                ║
║                     Written in Go                             ║
╚═══════════════════════════════════════════════════════════════╝

Enter target subnet (e.g., 192.168.1.0/24): 192.168.1.0/24

📡 Target range: 192.168.1.0/24 (254 hosts)

Select scan type:
  1. ICMP Ping Scan       - Standard ping using ICMP echo requests
  2. TCP Connect Scan     - Probe common ports (80, 443, 22, 21, 53, 135, 445)
  3. ARP Scan             - Discover hosts via ARP (local network only)
  4. DNS Reverse Lookup   - Find hostnames via PTR records
  5. All Scans Combined   - Run all discovery methods

Enter your choice (1-5): 1

🏓 Starting ICMP Ping Scan...
[████████████████████████████████████████] 100% (254/254)

╔═══════════════════════════════════════════════════════════════╗
║                       SCAN RESULTS                            ║
╠═══════════════════════════════════════════════════════════════╣
║ ✅ 192.168.1.1     │ Response in 2ms                          ║
║ ✅ 192.168.1.10    │ Response in 5ms                          ║
║ ✅ 192.168.1.15    │ Response in 3ms                          ║
╠═══════════════════════════════════════════════════════════════╣
║ Total hosts scanned: 254   │ Alive: 3     │ Dead: 251         ║
╚═══════════════════════════════════════════════════════════════╝
```

## Scan Types Explained

### ICMP Ping Scan
Uses the system's `ping` command to send ICMP echo requests. Most reliable for discovering hosts that respond to ping. May be blocked by firewalls.

### TCP Connect Scan
Attempts to establish TCP connections to common ports. Useful when ICMP is blocked. Detects hosts running network services.

### ARP Scan
Queries the local ARP cache after sending UDP packets. Only works for hosts on the same network segment. Can discover hosts that block ICMP/TCP.

### DNS Reverse Lookup
Performs PTR record lookups to find hostnames. Useful for network documentation but may not find all hosts.

### Combined Scan
Runs all four methods and merges results. Provides the most comprehensive discovery but takes longer.

## Performance Tuning

The tool automatically scales workers based on CPU count:
- Default: `NumCPU * 10` workers (max 100)
- ARP scan uses fewer workers to avoid ARP cache pollution

Timeout: 2 seconds per probe

## Notes

- **Root/Admin privileges** may be required for some operations
- **ARP scanning** only works on the local network segment
- **Firewalls** may block ICMP or certain TCP ports
- Results are automatically sorted by IP address

## Output File Format

When exporting, results are saved as:
```
scan_results_YYYYMMDD_HHMMSS.txt
```

## License

MIT License - Feel free to modify and distribute.

## Contributing

Contributions welcome! Areas for improvement:
- Raw socket ICMP (no system ping dependency)
- UDP port scanning
- mDNS/DNS-SD discovery
- JSON/CSV export formats
- Custom port lists via CLI
- Configurable timeout and workers
