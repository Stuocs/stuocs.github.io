---
title: Network Discovery
date: 2026-02-15 21:00:00 +0100
categories: [01-Reconnaissance, Network]
tags: [nmap, masscan, ping, recon]
author: kairos
---

## Arp-Scan

```shell
sudo arp-scan -I eth1 --localnet
```

This command performs an ARP (Address Resolution Protocol) scan across the local network to identify active devices and their MAC addresses.

**Breakdown of the command:**

- `sudo`: Executes the command with elevated privileges, which is necessary because ARP scanning requires raw socket access.
    
- `arp-scan`: The tool used to send ARP requests across a network to discover active hosts.
    
- `-I eth1`: Specifies the network interface to use for scanning, in this case, `eth1`. It's crucial to select the correct interface to target the intended network.
    
- `--localnet`: Automatically calculates the network range based on the interface's IP and subnet mask, sending ARP requests to all possible hosts within that range.
    

**Output Explanation:**

- Lists discovered IP addresses and their corresponding MAC addresses.
    
- `(Unknown)` indicates that the vendor database could not be accessed to resolve MAC addresses to manufacturers, likely due to permission issues (`Cannot open MAC/Vendor file ieee-oui.txt`).
    
- Summary: Total hosts scanned, response rate, and scan duration.
    

---

**Other Available Arguments for `arp-scan`:**

- `-l` → Shortcut for `--localnet`, scans the local network.
    
- `-I <interface>` → Specifies the network interface to use.
    
- `-g <gateway>` → Defines the gateway IP address if needed.
    
- `-r <count>` → Number of times to repeat ARP requests to each host.
    
- `-s <source-ip>` → Spoofs the source IP address for the scan.
    
- `--ignoredups` → Ignores duplicate responses from the same IP/MAC pair.
    
- `--retry <count>` → Sets the retry count for unanswered ARP requests.
    
- `--verbose` → Provides more detailed output.
    
- `--file <filename>` → Reads targets from a file instead of scanning an entire subnet.
    
- `--plain` → Displays raw output without additional formatting.
    
- `--destaddr <mac>` → Sets the destination MAC address for ARP requests.
    

This tool is widely used for network discovery during penetration testing, Red Team assessments, and general administrative tasks.

---


---

---

## Nmap

```bash
sudo nmap -p- -sS -sC -sV --min-rate 5000 -n -vvv -Pn 192.168.0.23 -oN escaneo
```

This command performs a comprehensive and aggressive port and service scan on the host `192.168.0.23` using Nmap, optimized for speed and detail.

---

### **Breakdown of the Command:**

- `sudo`: Runs the command with root privileges, required for certain scan types like SYN scans.
    
- `nmap`: The network mapping and port scanning tool.
    

**Options used:**

- `-p-`: Scans all 65,535 TCP ports, from 1 to 65535.
    
- `-sS`: Performs a TCP SYN scan (half-open scan). It's stealthier and faster, often used in Red Team or stealth assessments.
    
- `-sC`: Executes default NSE (Nmap Scripting Engine) scripts. Useful for basic service enumeration and vulnerability checks.
    
- `-sV`: Attempts to determine service versions running on open ports.
    
- `--min-rate 5000`: Forces Nmap to send at least 5000 packets per second, making the scan much faster, but potentially noisier.
    
- `-n`: Disables DNS resolution for faster results.
    
- `-vvv`: Maximum verbosity level. Displays detailed information during the scan.
    
- `-Pn`: Treats the host as "up", skips ICMP ping checks. Useful for targets that block ping requests.
    
- `192.168.0.23`: Target IP address.
    
- `-oN thl/merchan/merchan_escaneo`: Outputs the scan results in normal format to the file `merchan_escaneo` inside the specified directory.
    

---

### **Other Available Arguments for Nmap:**

- `-F` → Fast scan (scans top 100 ports).
    
- `-p <port-range>` → Custom port range (e.g., `-p 1-1000`).
    
- `-sU` → UDP port scan.
    
- `-sT` → TCP Connect scan (less stealthy).
    
- `-A` → Aggressive scan: version detection, OS detection, traceroute, scripts.
    
- `-O` → OS detection.
    
- `--script <script>` → Run specific NSE scripts.
    
- `-iL <file>` → Read targets from a file.
    
- `-oX <file>` → Output results in XML format.
    
- `-oG <file>` → Output in grepable format.
    
- `--max-retries <num>` → Sets the maximum number of probe retransmissions.
    
- `--max-rate <rate>` → Limits the maximum number of packets per second.
    

This scan is highly aggressive, designed for rapid, detailed enumeration of a specific host, often used in Red Team scenarios or during time-sensitive engagements.

---


---

---

