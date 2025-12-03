# 🔍 Network Scanner & Reconnaissance Tool  
Single‑File Python Network Scanner (TCP/UDP + Host Discovery)

A fast, lightweight, multi‑threaded network scanner and reconnaissance tool written entirely in **one Python file**. This tool can perform TCP/UDP port scanning, basic banner grabbing, host discovery, and export results to JSON — making it useful for system administrators, students, researchers, and ethical hackers.

---

## 🚀 Features

### 🔸 Scanning
- **TCP Port Scan**
- **UDP Port Scan** (simple open/filtered detection)
- **Banner Grabbing** (service identification)
- Configurable **port ranges**
- High‑speed **multi‑threading**

### 🔸 Reconnaissance
- **Host Discovery** using ARP/ICMP (requires Scapy)
- Identifies active hosts on a network
- Output stored cleanly in JSON format

### 🔸 Performance
- Uses threading for large‑scale scans
- Adjustable number of worker threads
- Lightweight, low memory usage

### 🔸 Output
- Saves all findings to `results.json`
- Includes:
  - Target scanned
  - Open ports
  - Protocol type
  - Banner/service info
  - Discovered hosts
  - Timestamp

---

## 📦 Requirements

### Required
- Python **3.x**

### Optional (for host discovery)
- `scapy`

Install dependencies:

```bash
pip install scapy
