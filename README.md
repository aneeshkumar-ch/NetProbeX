# LAB 03: Automated Network Vulnerability Scanner
**Python + Nmap — Host Discovery, CVE Correlation, CVSS Severity Scoring & Remediation Reporting**

---

## 📌 Overview
This repository contains the complete implementation for **Lab 03: Network Vulnerability Scanner**. The tool wraps the underlying network scanning engine (`Nmap`) within a secure Python application to discover active hosts, identify open network ports and services, correlate banners to known Common Vulnerabilities and Exposures (CVEs) using the NIST National Vulnerability Database (NVD API v2.0), score severity via CVSS metrics, and generate audit-ready **CSV** and **HTML** vulnerability reports for a Security Operations Center (SOC) handoff.

---

## 📁 Repository Structure
```
Lab03_Network_Vulnerability_Scanner/
├── scanner.py                 # Main scanner application (Python 3)
├── scope.txt                  # Authorized target IP list / CIDR definitions
├── cve_cache.json             # Local JSON cache for NVD CVE queries & offline database
├── vulnerability_report.csv   # Structured vulnerability data export for SIEM / Excel
├── vulnerability_report.html  # Modern SOC dashboard report with color-coded severity tables
├── LAB03_REPORT_SUMMARY.md    # Executive write-up and Top 3 Remediation Priorities
└── README.md                  # Project documentation and user guide
```

---

## ⚙️ Prerequisites & Installation

### 1. Python Environment
Python 3.10 or higher is required. Install the necessary Python packages:
```bash
pip install python-nmap requests pandas
```

### 2. Nmap Installation
The underlying scanner utilizes the `nmap` binary:
- **Windows:**
  - Install via Windows Package Manager:
    ```powershell
    winget install Insecure.Nmap
    ```
  - Or download and run the installer from the [Official Nmap Site](https://nmap.org/download.html). Ensure `C:\Program Files (x86)\Nmap` is added to your system `PATH`.
- **Linux (Debian/Ubuntu):**
  ```bash
  sudo apt update && sudo apt install -y nmap
  ```
- **macOS:**
  ```bash
  brew install nmap
  ```

> **Note:** If `nmap` is not currently installed on the host running the test, the script automatically provides a `--demo` flag that simulates live mentor lab VMs (`192.168.56.101`, `.102`, and `.103`) so all modules, CVE correlation, caching, and reports can be tested and demonstrated end-to-end.

---

## 🔒 Scope & Ethics Configuration (`scope.txt`)
Before running any scan, ensure your target IP addresses or CIDR subnets are specified in [`scope.txt`](file:///C:/Users/delln/.gemini/antigravity/scratch/Lab03_Network_Vulnerability_Scanner/scope.txt):
```text
# Authorized Lab Scan Scope
192.168.56.101
192.168.56.102
192.168.56.103
```
> **Ethics Enforcement:** Any IP address outside the ranges listed in `scope.txt` will be automatically rejected and aborted by the `ScopeManager` class.

---

## 🚀 Running the Scanner

### Standard Live Scan:
```bash
python scanner.py --scope scope.txt --output-csv vulnerability_report.csv --output-html vulnerability_report.html
```

### Simulated Lab Demo Mode:
```bash
python scanner.py --demo
```

### Offline Mode (Using Curated Lab Database without Internet):
```bash
python scanner.py --offline
```

### With an NVD API Key (Faster Lookups without Rate Limits):
```bash
python scanner.py --api-key YOUR_NIST_NVD_API_KEY
# Or set via environment variable:
export NVD_API_KEY="YOUR_KEY"
```

---

## 📊 Deliverables & Output Description

1. **[`scanner.py`](file:///C:/Users/delln/.gemini/antigravity/scratch/Lab03_Network_Vulnerability_Scanner/scanner.py):**
   - **Host Discovery (`-sn`):** Ping sweep to detect responsive hosts.
   - **Service & Version Enumeration (`-sV`):** Deep inspection of open ports, daemon banners, and protocols.
   - **CVE Mapping & CVSS Scoring:** Queries NIST NVD v2.0 REST API, extracts CVSS v3.1 base score, categorizes into Critical (9.0–10.0), High (7.0–8.9), Medium (4.0–6.9), Low (0.1–3.9).
   - **Local Cache (`cve_cache.json`):** Avoids redundant queries and complies with NVD rate limiting.
   - **Remediation Engine:** Maps vulnerabilities to specific configuration and patch instructions.

2. **[`vulnerability_report.csv`](file:///C:/Users/delln/.gemini/antigravity/scratch/Lab03_Network_Vulnerability_Scanner/vulnerability_report.csv):**
   - Columns: `Host, Port, Protocol, Service, Version, CVE ID, CVSS Score, Severity, Remediation`

3. **[`vulnerability_report.html`](file:///C:/Users/delln/.gemini/antigravity/scratch/Lab03_Network_Vulnerability_Scanner/vulnerability_report.html):**
   - SOC executive summary banner.
   - Top 3 Remediation Priorities callout.
   - Live metrics summary cards.
   - Interactive table with color-coded severity badges (Red, Orange, Yellow, Green).

4. **[`LAB03_REPORT_SUMMARY.md`](file:///C:/Users/delln/.gemini/antigravity/scratch/Lab03_Network_Vulnerability_Scanner/LAB03_REPORT_SUMMARY.md):**
   - Executive write-up detailing the methodology, compliance attestation, findings, and remediation roadmaps.
