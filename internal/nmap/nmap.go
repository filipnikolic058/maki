// Package nmap runs an nmap scan against a list of hosts and emits
// a JSON report intended for frontend consumption.
package nmap

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"maki/internal/output"
)

// Port is the JSON shape exposed to the frontend.
type Port struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	Extra    string `json:"extra_info,omitempty"`
}

// Host is the JSON shape exposed to the frontend.
type Host struct {
	IP         string `json:"ip"`
	Hostname   string `json:"hostname,omitempty"`
	Status     string `json:"status"`
	MAC        string `json:"mac,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	OS         string `json:"os,omitempty"`
	OSAccuracy int    `json:"os_accuracy,omitempty"`
	Ports      []Port `json:"ports"`
}

// Report is the top-level JSON document written to disk.
type Report struct {
	Subnet    string    `json:"subnet"`
	Timestamp time.Time `json:"timestamp"`
	Command   string    `json:"command"`
	Hosts     []Host    `json:"hosts"`
}

// nmap XML schema (only the fields we care about).
type xmlNmaprun struct {
	XMLName xml.Name  `xml:"nmaprun"`
	Args    string    `xml:"args,attr"`
	Hosts   []xmlHost `xml:"host"`
}

type xmlHost struct {
	Status    xmlStatus    `xml:"status"`
	Addresses []xmlAddress `xml:"address"`
	Hostnames xmlHostnames `xml:"hostnames"`
	Ports     xmlPorts     `xml:"ports"`
	OS        xmlOS        `xml:"os"`
}

type xmlStatus struct {
	State string `xml:"state,attr"`
}

type xmlAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type xmlHostnames struct {
	Hostnames []xmlHostname `xml:"hostname"`
}

type xmlHostname struct {
	Name string `xml:"name,attr"`
}

type xmlPorts struct {
	Ports []xmlPort `xml:"port"`
}

type xmlPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    xmlPortState `xml:"state"`
	Service  xmlService   `xml:"service"`
}

type xmlPortState struct {
	State string `xml:"state,attr"`
}

type xmlService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	Extra   string `xml:"extrainfo,attr"`
}

type xmlOS struct {
	Matches []xmlOSMatch `xml:"osmatch"`
}

type xmlOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy int    `xml:"accuracy,attr"`
}

// Run executes `nmap -A -F -iL hostsFile`, writes the XML report and a
// processed JSON report into outputDir, and returns the parsed report
// along with the JSON path.
func Run(hostsFile, outputDir, subnet string) (*Report, string, error) {
	info, err := os.Stat(hostsFile)
	if err != nil {
		return nil, "", fmt.Errorf("hosts file not found: %v", err)
	}
	if info.Size() == 0 {
		return nil, "", fmt.Errorf("hosts file is empty — nothing to scan")
	}

	if _, err := exec.LookPath("nmap"); err != nil {
		return nil, "", fmt.Errorf("nmap is not installed or not in PATH")
	}

	xmlPath := filepath.Join(outputDir, "nmap.xml")
	jsonPath := filepath.Join(outputDir, "nmap.json")

	cmd := exec.Command("nmap", "-A", "-F", "-iL", hostsFile, "-oX", xmlPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, "", fmt.Errorf("nmap failed: %v", err)
	}
	_ = output.ChownToInvokingUser(xmlPath)

	xmlData, err := os.ReadFile(xmlPath)
	if err != nil {
		return nil, "", fmt.Errorf("cannot read nmap XML: %v", err)
	}

	var parsed xmlNmaprun
	if err := xml.Unmarshal(xmlData, &parsed); err != nil {
		return nil, "", fmt.Errorf("cannot parse nmap XML: %v", err)
	}

	report := &Report{
		Subnet:    subnet,
		Timestamp: time.Now(),
		Command:   "nmap " + parsed.Args,
		Hosts:     make([]Host, 0, len(parsed.Hosts)),
	}

	for _, h := range parsed.Hosts {
		host := Host{
			Status: h.Status.State,
			Ports:  make([]Port, 0, len(h.Ports.Ports)),
		}
		for _, addr := range h.Addresses {
			switch addr.AddrType {
			case "ipv4", "ipv6":
				host.IP = addr.Addr
			case "mac":
				host.MAC = addr.Addr
				host.Vendor = addr.Vendor
			}
		}
		if len(h.Hostnames.Hostnames) > 0 {
			host.Hostname = h.Hostnames.Hostnames[0].Name
		}
		if len(h.OS.Matches) > 0 {
			best := h.OS.Matches[0]
			for _, m := range h.OS.Matches[1:] {
				if m.Accuracy > best.Accuracy {
					best = m
				}
			}
			host.OS = best.Name
			host.OSAccuracy = best.Accuracy
		}
		for _, p := range h.Ports.Ports {
			host.Ports = append(host.Ports, Port{
				Port:     p.PortID,
				Protocol: p.Protocol,
				State:    p.State.State,
				Service:  p.Service.Name,
				Product:  p.Service.Product,
				Version:  p.Service.Version,
				Extra:    p.Service.Extra,
			})
		}
		report.Hosts = append(report.Hosts, host)
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("cannot marshal JSON: %v", err)
	}
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return nil, "", fmt.Errorf("cannot write JSON: %v", err)
	}
	_ = output.ChownToInvokingUser(jsonPath)

	return report, jsonPath, nil
}
