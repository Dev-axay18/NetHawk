---

<div align="center">

<img src="https://github.com/Dev-axay18/NetHawk/blob/main/screenshots/Untitled%20design.png?raw=true" width="100%" style="border-radius:14px; margin-bottom:25px;">

# 🦅 **NetHawk Security Toolkit**

### *Next-Generation Packet & Path Intelligence Platform*

<br>

<a href="https://www.python.org/downloads/">
<img src="https://img.shields.io/badge/Python-3.7%2B-1e90ff?style=for-the-badge&logo=python&logoColor=yellow">
</a>

<a href="LICENSE">
<img src="https://img.shields.io/badge/License-MIT-32cd32?style=for-the-badge&logo=open-source-initiative&logoColor=white">
</a>

<a>
<img src="https://img.shields.io/badge/Platform-Linux-808080?style=for-the-badge&logo=linux&logoColor=white">
</a>

<a href="https://scapy.net/">
<img src="https://img.shields.io/badge/Powered%20By-Scapy-fb8c00?style=for-the-badge&logo=python&logoColor=white">
</a>

<br><br>

### ⚡ **Advanced network reconnaissance, packet analysis, and threat detection**  <br> **{ unified in one elite toolkit.}**

<br>

[🚀 **Features**](#-features) • [🛠️ **Installation**](#-installation) • [🧭 **Usage**](#-usage) • [🖼️ **Screenshots**](#-screenshots) • [📚 **Documentation**](#-documentation)

---

</div>

---



# 🎯 **Overview**

> ### **NetHawk**
>
> **High-precision network intelligence for modern cybersecurity operations.**
>
> ▌ NetHawk delivers a unified toolkit for **packet inspection, anomaly detection, flow analytics**,
> and **enhanced traceroute intelligence**, engineered for analysts who demand absolute clarity
> in complex or hostile network environments.
>
> ▌ Designed for professionals. Optimized for performance. Built for real threat landscapes.

<br>

---

# ⚡ **Why NetHawk?**

```
┌───────────────────────────────────────────────┐
│   CORE CAPABILITIES — BUILT FOR REAL OPS      │
└───────────────────────────────────────────────┘
```

### ▌ **01 : Deep Packet Inspection**

> Precision-level packet capture with **layer-by-layer decoding**, protocol fingerprinting,
> and hidden traffic exposure.

---

### ▌ **02 : AI-Powered Anomaly Detection**

> ML-driven detection engine that spots **outliers, covert scans, beaconing, and malicious flow patterns**
> in real time.

---

### ▌ **03 : Enhanced Traceroute Engine**

> A modern traceroute with **hop intelligence**, latency signature mapping, and **geo-IP augmented paths**.

---

### ▌ **04 : Flow Analytics**

> Real-time flow reviewing with **session behavior metrics**, bandwidth profiling,
> and traffic distribution intelligence.

---

### ▌ **05 : Threat Intelligence Layer**

> Integrated detection using **IOC matches**, blacklists, and **adaptive endpoint scoring**
> for rapid threat classification.

---

### ▌ **06 : Automated Reporting**

> Every operation outputs a **structured, SIEM-ready JSON report** for pipelines, auditing,
> and forensic analysis.

---

# ✨ **Features**

## 🎯 **Core Capabilities**

> ### **📡 PACKET SNIFFING**
>
> **────────────────────────────────────**
>
> * Live packet capture on any interface
> * BPF filtering support
> * TCP / UDP / ICMP / DNS classification
> * TLS/SSL handshake detection
> * SYN / XMAS / NULL scan signature detection

---

> ### **🔬 FLOW ANALYSIS**
>
> **────────────────────────────────────**
>
> * Top talkers identification
> * Port & protocol distribution
> * Protocol-level statistics
> * TCP handshake lifecycle tracking
> * Full connection flow mapping

---

> ### **🚨 ANOMALY DETECTION**
>
> **────────────────────────────────────**
>
> * Port scan detection
> * DNS tunneling identification
> * Stealth scan detection
> * Behavioral traffic pattern analysis
> * Real-time alerting engine

---

> ### **🗺️ ADVANCED TRACEROUTE**
>
> **────────────────────────────────────**
>
> * Multi-hop path tracing
> * Latency & jitter metrics
> * Reverse DNS lookup
> * GeoIP hop mapping
> * Smart timeout & retry handling

---

# 🛡️ **Security Features**

> **• Threat Intelligence Integration** : Blacklist-powered detection <br>
> **• Real-time Monitoring** : Continuous capture + instant alerts <br>
> **• Comprehensive Logging** :  JSON-based forensic reporting <br>
> **• Customizable Filters** : Precision capture via BPF expressions<br>

---

## 🚀 Installation

### Prerequisites

```bash
# Kali Linux / Debian / Ubuntu
sudo apt update
sudo apt install python3 python3-pip pipx

# Install Scapy
pip3 install scapy
```

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/nethawk.git
cd nethawk

# Install using pipx (recommended)
pipx install .

# Or run the install script
chmod +x install.sh
./install.sh
```

### Manual Installation

```bash
# Install in development mode
pip3 install -e .

# Create system-wide command (requires sudo)
sudo ln -s ~/.local/bin/nethawk /usr/local/bin/nethawk
```

### Verify Installation

```bash
nethawk --help
```

---

## 📖 Usage

### Basic Commands

```bash
# Display help
nethawk --help

# Packet sniffing (requires sudo)
sudo nethawk --sniff wlan0 --timeout 30

# Advanced traceroute
sudo nethawk --trace google.com

# Full security scan
sudo nethawk --fullscan 8.8.8.8
```

### 🎯 Packet Capture

#### Basic Sniffing
```bash
# Capture on interface for 30 seconds
sudo nethawk --sniff eth0 --timeout 30
```

#### With BPF Filters
```bash
# Capture only TCP traffic
sudo nethawk --sniff eth0 --filter "tcp" --timeout 20

# Capture HTTP/HTTPS traffic
sudo nethawk --sniff eth0 --filter "tcp port 80 or tcp port 443" --timeout 30

# Capture DNS queries
sudo nethawk --sniff eth0 --filter "udp port 53" --timeout 15
```

#### With Analysis Features
```bash
# Enable flow analysis
sudo nethawk --sniff wlan0 --flows --timeout 30

# Enable anomaly detection
sudo nethawk --sniff wlan0 --detect --timeout 30

# Enable both
sudo nethawk --sniff wlan0 --flows --detect --timeout 30
```

### 🗺️ Traceroute

```bash
# Trace route to domain
sudo nethawk --trace google.com

# Trace route to IP
sudo nethawk --trace 8.8.8.8

# Trace with custom timeout
sudo nethawk --trace example.com --timeout 5
```

### 🔍 Full Security Scan

```bash
# Complete security assessment
sudo nethawk --fullscan target.com

# This performs:
# 1. Advanced traceroute
# 2. Packet capture (20s)
# 3. Flow analysis
# 4. Anomaly detection
# 5. Threat intelligence check
```

---

## 📸 Screenshots

### 🎨 Banner & Interface

![NetHawk Banner](https://github.com/Dev-axay18/NetHawk/blob/main/screenshots/Screenshot%20From%202025-11-30%2010-00-35.png?raw=true) <br>
*NetHawk's stunning ASCII art banner and interface*

### 📡 Packet Capture in Action

![Packet Capture](https://github.com/Dev-axay18/NetHawk/blob/main/screenshots/Screenshot%20From%202025-11-30%2010-04-21.png?raw=true) <br>
*Real-time packet sniffing with protocol classification*

### 📊 Flow Analysis Dashboard

![Flow Analysis](https://github.com/Dev-axay18/NetHawk/blob/main/screenshots/Screenshot%20From%202025-11-30%2010-04-57.png?raw=true) <br>
*Comprehensive traffic flow analysis with top talkers and port distribution*

### 🚨 Anomaly Detection

![Anomaly Detection](https://github.com/Dev-axay18/NetHawk/blob/main/screenshots/Screenshot%20From%202025-11-30%2010-13-21.png?raw=true) <br>
*Real-time anomaly detection identifying suspicious patterns*

### 🗺️ Advanced Traceroute

![Traceroute](https://github.com/Dev-axay18/NetHawk/blob/main/screenshots/Screenshot%20From%202025-11-30%2010-15-26.png?raw=true) <br>
*Enhanced traceroute with latency metrics and geolocation*

### 🛡️ Threat Intelligence

![Threat Detection](https://github.com/Dev-axay18/NetHawk/blob/main/screenshots/Screenshot%20From%202025-11-30%2010-17-22.png?raw=true) <br>
*Threat intelligence alerts for blacklisted IPs*

### 📝 JSON Reports

![Reports](https://github.com/Dev-axay18/NetHawk/blob/main/screenshots/Screenshot%20From%202025-11-30%2015-51-20.png?raw=true)<br>
*Detailed JSON reports for forensic analysis*

---

## 🎓 Advanced Usage

### Custom Threat Intelligence

Create and populate your threat blacklist:

```bash
# Create data directory
mkdir -p data

# Add malicious IPs to blacklist
cat > data/threat_blacklist.txt << EOF
# Malware C2 Servers
185.220.101.1
45.142.212.61

# Known Botnet IPs
103.109.247.10
EOF

# Run capture with threat detection
sudo nethawk --sniff eth0 --timeout 30
```

### BPF Filter Examples

```bash
# Capture specific host
sudo nethawk --sniff eth0 --filter "host 192.168.1.1"

# Capture specific port range
sudo nethawk --sniff eth0 --filter "portrange 8000-9000"

# Capture ICMP only
sudo nethawk --sniff eth0 --filter "icmp"

# Complex filter
sudo nethawk --sniff eth0 --filter "tcp and (port 80 or port 443) and host 192.168.1.0/24"
```

### Analyzing Reports

```bash
# List all reports
ls -lh reports/

# View latest report (with jq)
cat reports/report-*.json | jq .

# Extract specific data
jq '.flows.top_sources' reports/report-2025-11-29-2219.json

# Count anomalies
jq '.anomalies | length' reports/report-*.json
```

---

## 🏗️ Architecture

```
NetHawk/
├── nethawk/
│   ├── core/              # Core functionality modules
│   │   ├── sniffer.py     # Packet capture engine
│   │   ├── tracer.py      # Advanced traceroute
│   │   ├── flow_analyzer.py    # Traffic flow analysis
│   │   ├── anomaly_detector.py # Anomaly detection
│   │   ├── threat_intel.py     # Threat intelligence
│   │   └── logger.py      # Report generation
│   ├── ui/                # User interface
│   │   ├── banner.py      # ASCII art banner
│   │   └── console.py     # Colored output
│   ├── utils/             # Utility modules
│   │   ├── config.py      # Configuration
│   │   └── geoip.py       # GeoIP lookup
│   └── cli.py             # Command-line interface
├── data/                  # Threat intelligence data
├── reports/               # Generated reports
├── main.py               # Alternative entry point
├── setup.py              # Package setup
└── install.sh            # Installation script
```

---

## 🔧 Configuration

### Default Settings

Edit `nethawk/utils/config.py` to customize:

```python
class Config:
    sniff_timeout = 30              # Default capture timeout
    default_interface = "eth0"      # Default network interface
    report_dir = "reports"          # Report output directory
    max_hops = 30                   # Traceroute max hops
    traceroute_timeout = 2          # Traceroute timeout per hop
```

---

## 📊 Output & Reports

NetHawk automatically generates detailed JSON reports for every operation:

### Report Structure

```json
{
  "metadata": {
    "timestamp": "2025-11-29T22:19:00",
    "tool": "NetHawk Security Toolkit",
    "version": "1.0"
  },
  "traceroute": [...],
  "flows": {
    "total_packets": 112,
    "top_sources": {...},
    "top_destinations": {...},
    "protocols": {...}
  },
  "anomalies": [...],
  "threats": [...]
}
```

Reports are saved to `reports/report-YYYY-MM-DD-HHMM.json`

---

## 🛠️ Troubleshooting

### Permission Denied

```bash
# Ensure you're using sudo for packet capture
sudo nethawk --sniff eth0

# Or grant capabilities to Python
sudo setcap cap_net_raw=eip $(which python3)
```

### Command Not Found

```bash
# Use full path with sudo
sudo /home/user/.local/bin/nethawk --sniff eth0

# Or create system symlink
sudo ln -s ~/.local/bin/nethawk /usr/local/bin/nethawk
```

### No Packets Captured

```bash
# Check interface name
ip link show

# Use a BPF filter to capture specific traffic
sudo nethawk --sniff wlan0 --filter "tcp" --timeout 30

# Verify interface is up
sudo ip link set wlan0 up
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/nethawk.git
cd nethawk

# Install in development mode
pip3 install -e .

# Run tests (if available)
python3 -m pytest
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
## 📞 Contact & Support

<div align="center">

**Created by: Akshay Kale (Dev-axay18)**

[![GitHub](https://img.shields.io/badge/GitHub-Dev--axay18-black?style=for-the-badge&logo=github)](https://github.com/Dev-axay18)

### ⭐ Star this repository if you find it useful!

</div>


---

<div align="center">

### 🦅 NetHawk - *Hunt. Analyze. Secure.*

</div>
