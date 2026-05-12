# 🔍 Maki - Network Host Discovery Tool

A fast, multithreaded network host discovery tool written in Go. Supports multiple scanning techniques (ICMP ping, TCP connect, ARP), can chain into an `nmap -A -F` map of the discovered hosts, and ships a static HTML viewer to visualize the result.

## Features

- **ICMP Ping Scan** - Traditional ping using ICMP echo requests
- **TCP Connect Scan** - Probes 500 most common ports to detect live hosts
- **ARP Scan** - Active ARP scanning using arping for local network discovery
- **Combined Scan** - Run all methods simultaneously for comprehensive results
- **Multithreaded** - Fast concurrent scanning
- **Cross-platform** - Works on Linux and macOS
- **Export Results** - Save scan results to text file
- **Unified host list** - Deduplicated `hosts.txt` of every alive IP across scans, ready for `nmap -iL`
- **Optional network map** - Chain `nmap -A -F` on the discovered hosts and emit a JSON report
- **Web viewer** - Static `web/index.html` page renders the JSON as an interactive network graph
- **Sudo-friendly output** - Files created under `sudo` are chown'd back to the invoking user
- **Default Subnet** - Quick scanning with 192.168.1.0/24 as default
- **MAC Address Discovery** - ARP scan displays MAC addresses

## Ports Scanned (TCP Mode)

TCP scan uses **500 common ports** loaded from `internal/commonPorts.txt`:
- Top services: HTTP (80, 443, 8080), SSH (22), FTP (21), SMB (445), RDP (3389)
- Database ports: MySQL (3306), PostgreSQL (5432), MSSQL (1433)
- And 490+ additional commonly used ports

Full port list includes: 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, and many more...

## Installation

### Prerequisites
- Go 1.21 or later
- `arping` utility for ARP scanning (install via package manager)
  - Linux: `sudo apt install arping` or `sudo yum install arping`
  - macOS: `brew install arping`
- `nmap` (optional, only needed for the post-scan network map step)
  - Linux: `sudo apt install nmap` / `sudo pacman -S nmap`
  - macOS: `brew install nmap`

### Build from Source

```bash
# Clone or download the files
cd maki

# Build the binary
go build -o maki .

# ARP scan requires root privileges
sudo ./maki
```

## Usage

```bash
# Run with sudo for ARP scanning capabilities
sudo ./maki

# Or run without sudo (ICMP and TCP scans only)
./maki
```

### Interactive Menu

1. Enter your target subnet in CIDR notation (default: `192.168.1.0/24`)
   - Just press Enter to use the default subnet
2. Select scan type:
   - `1` - ICMP Ping Scan
   - `2` - TCP Connect Scan (500 ports)
   - `3` - ARP Scan (requires network interface input)
   - `4` - All Scans Combined
3. For ARP scan (options 3 & 4):
   - Enter your network interface (e.g., `eth0`, `wlan0`, `en0`)
4. Optionally specify output directory to save results
5. When an output directory was provided and any host came back alive, you'll be asked whether to **map the network with `nmap -A -F`** — answering yes runs nmap against `hosts.txt` and writes `nmap.json` (and `nmap.xml`) into the same folder.

### Example Session

```
╔═══════════════════════════════════════════════════════════════╗
║              🔍 Network Host Discovery Tool 🔍                ║
╚═══════════════════════════════════════════════════════════════╝

Enter target subnet (default: 192.168.1.0/24):
Using default subnet: 192.168.1.0/24

📡 Target range: 192.168.1.0/24 (254 hosts)

Select scan type:
  1. ICMP Ping Scan
  2. TCP Connect Scan (common ports)
  3. ARP Scan (local network)
  4. All Scans Combined

Enter your choice (1-4): 3

Enter network interface for ARP scan (e.g., eth0, wlan0): wlan0

Enter output directory path (leave empty to skip file export):

📡 Starting ARP Scan on interface wlan0...

════════════════════════════════════════════════════════════════
                    ARP SCAN RESULTS
════════════════════════════════════════════════════════════════
  ✅ 192.168.1.1      MAC: AA:BB:CC:DD:EE:FF
  ✅ 192.168.1.10     MAC: 11:22:33:44:55:66
  ✅ 192.168.1.15     MAC: 77:88:99:AA:BB:CC

────────────────────────────────────────────────────────────────
  Total: 254 hosts | Alive: 3 | No response: 251
════════════════════════════════════════════════════════════════
```

## Scan Types Explained

### ICMP Ping Scan
Uses the system's `ping` command to send ICMP echo requests. Most reliable for discovering hosts that respond to ping. May be blocked by firewalls.
- **Timeout**: 2 seconds per host
- **Use case**: General host discovery

### TCP Connect Scan
Attempts to establish TCP connections to 500 common ports. Useful when ICMP is blocked. Detects hosts running network services.
- **Ports scanned**: 500 common ports from `internal/commonPorts.txt`
- **Timeout**: 2 seconds per port
- **Use case**: Discovering hosts with services running, bypassing ICMP blocks

### ARP Scan
Sends ARP requests using the `arping` utility. Only works on the local network segment (Layer 2). Can discover hosts that block ICMP/TCP. Displays MAC addresses.
- **Timeout**: 5 seconds per host
- **Requirements**: Root privileges, `arping` utility, network interface name
- **Use case**: Complete local network discovery, MAC address identification

### Combined Scan (All Scans)
Runs ICMP, TCP, and ARP scans sequentially and combines results. Provides the most comprehensive discovery.
- **Use case**: Maximum coverage when you need to find all possible hosts

## Performance

- **Concurrent scanning**: All scans run with parallel goroutines for speed
- **TCP scan**: Scans all 500 ports on all targets concurrently
- **ICMP/ARP**: Scans all hosts concurrently with timeout management

## Notes

- **Root/sudo privileges** required for ARP scanning (uses raw sockets)
- **ARP scanning** only works on the local network segment (same broadcast domain)
- **Firewalls** may block ICMP or certain TCP ports
- **Network interface** must be specified for ARP scans (e.g., eth0, wlan0, en0)
- Results are displayed in real-time as they're discovered

## Output Files

When an output directory is provided, maki writes the following into it:

| File | Purpose |
| --- | --- |
| `result.txt` | Human-readable per-scan results |
| `hosts.txt` | Deduplicated, sorted list of every alive IP (one per line). Ready for `nmap -iL hosts.txt` |
| `nmap.xml` | Raw nmap XML output (only if the nmap map step was run) |
| `nmap.json` | Processed JSON consumed by the web viewer (only if the nmap map step was run) |

When maki is run with `sudo`, all of these files are chown'd back to the invoking user (`$SUDO_UID`/`$SUDO_GID`) so they aren't left root-owned.

### `result.txt`
```
Result of: 192.168.1.0/24
Scan time: 2025-01-15 14:30:45
--------------------------------------------------

ICMP_SCAN:
192.168.1.1 (Response in 2ms)
192.168.1.10 (Response in 5ms)

TCP_SCAN:
192.168.1.1 (Ports: 22,80,443)
192.168.1.10 (Ports: 22,3306)

ARP_SCAN:
192.168.1.1 (MAC: AA:BB:CC:DD:EE:FF)
192.168.1.10 (MAC: 11:22:33:44:55:66)

--------------------------------------------------
SUMMARY:
  ICMP_SCAN: 2 hosts alive
  TCP_SCAN: 2 hosts alive
  ARP_SCAN: 2 hosts alive
```

### `hosts.txt`
```
192.168.1.1
192.168.1.10
192.168.1.15
```

### `nmap.json`
```json
{
  "subnet": "192.168.1.0/24",
  "timestamp": "2025-01-15T14:31:02Z",
  "command": "nmap -A -F -iL hosts.txt -oX nmap.xml",
  "hosts": [
    {
      "ip": "192.168.1.1",
      "hostname": "router.local",
      "status": "up",
      "mac": "AA:BB:CC:DD:EE:FF",
      "vendor": "TP-Link",
      "os": "Linux 5.x",
      "os_accuracy": 95,
      "ports": [
        { "port": 22, "protocol": "tcp", "state": "open",
          "service": "ssh", "product": "OpenSSH", "version": "8.0" },
        { "port": 80, "protocol": "tcp", "state": "open",
          "service": "http", "product": "nginx", "version": "1.24.0" }
      ]
    }
  ]
}
```

## Web Viewer

`web/index.html` is a self-contained static page that renders `nmap.json` as an interactive force-directed graph (vis-network), with a side panel showing the selected host's IP, hostname, MAC + vendor, OS detection, and open-port table.

Two ways to use it:

1. **Open the file directly** — double-click `web/index.html` (or open it as a `file://` URL) and use the **Load nmap.json** button in the header to pick a file from disk.
2. **Serve over HTTP** — drop `nmap.json` next to `index.html` and serve the folder, e.g.:
   ```bash
   cp /path/to/output/nmap.json web/
   cd web && python3 -m http.server 8000
   # then open http://localhost:8000
   ```
   The page auto-fetches `./nmap.json` on load.

Loaded data is cached in `localStorage` and restored on reload. Use the **Clear saved** button in the header to drop the cached copy.

## Troubleshooting

### ARP Scan Issues
- **"Operation not permitted"**: Run with `sudo`
- **No results**: Verify network interface name with `ip link` or `ifconfig`
- **Inconsistent results**: Make sure you're using the correct interface for your network

### Finding Your Network Interface
```bash
# Linux
ip link show
# or
ifconfig

# macOS
ifconfig
networksetup -listallhardwareports
```

## License

MIT License - Feel free to modify and distribute.
