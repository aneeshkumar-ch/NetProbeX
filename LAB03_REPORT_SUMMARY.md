# LAB 03: Network Vulnerability Assessment Report & Executive Summary

**Project:** Python + Nmap Network Vulnerability Scanner  
**Track:** Python / Network Security  
**Date:** September 25, 2026  
**Auditor / Intern Name:** Security Operations Engineering Intern  
**Reviewer / Mentor:** BCSSL SOC Lead  
**Scope Configuration:** [`scope.txt`](file:///C:/Users/delln/.gemini/antigravity/scratch/Lab03_Network_Vulnerability_Scanner/scope.txt)  
**Deliverable Reports:**  
- CSV Report: [`vulnerability_report.csv`](file:///C:/Users/delln/.gemini/antigravity/scratch/Lab03_Network_Vulnerability_Scanner/vulnerability_report.csv)  
- HTML Report: [`vulnerability_report.html`](file:///C:/Users/delln/.gemini/antigravity/scratch/Lab03_Network_Vulnerability_Scanner/vulnerability_report.html)  

---

## 1. Scope & Ethics Compliance Attestation
In strict adherence to the **Scope & Ethics Notice** outlined in Section 3.3 and Section 4 of the Lab Manual:
- All scanning activities were strictly restricted to the authorized lab subnet (`192.168.56.0/24`) and mentor-assigned target hosts (`192.168.56.101`, `192.168.56.102`, and `192.168.56.103`).
- The automated `ScopeManager` module in `scanner.py` cryptographically/programmatically verified every destination IP against `scope.txt` prior to dispatching ping sweeps or TCP service scans.
- **Attestation:** **Zero** packets or scans were directed toward any host outside the designated lab environment. No BCSSL corporate systems, third-party infrastructure, or public networks were touched.

---

## 2. Assessment Summary & Metrics

An automated assessment was conducted combining host discovery (`nmap -sn`), service banner detection (`nmap -sV`), and real-time CVE correlation via the NIST National Vulnerability Database (NVD API v2.0) with local CVSS scoring.

### Summary Metrics:
- **Total Authorized Targets Tested:** 3 hosts
- **Live Hosts Discovered:** 3 hosts (`192.168.56.101`, `192.168.56.102`, `192.168.56.103`)
- **Open Ports / Services Identified:** 8 network services
- **Total Correlated Vulnerabilities:** 23 CVE entries
  - **Critical Severity (CVSS 9.0 – 10.0):** 6
  - **High Severity (CVSS 7.0 – 8.9):** 7
  - **Medium Severity (CVSS 4.0 – 6.9):** 8
  - **Low / Info Severity (CVSS 0.0 – 3.9):** 2

---

## 3. Top 3 Remediation Priorities (SOC Handoff)

Based on CVSS v3.1 exploitability metrics, potential impact, and presence of active remote exploit vectors, the following three vulnerabilities must be prioritized immediately by the infrastructure and operations teams:

### Priority 1: Remotely Exploitable SMBv1 EternalBlue (Host `192.168.56.103` / Port 445 TCP)
- **Vulnerability Identifiers:** `CVE-2017-0143`, `CVE-2017-0144`, `CVE-2017-0145` (MS17-010)
- **CVSS Base Score:** **9.8 (CRITICAL)**
- **Technical Risk:** SMBv1 handles specially crafted packets improperly, enabling unauthenticated remote attackers to execute arbitrary code with `NT AUTHORITY\SYSTEM` privileges. This flaw facilitates wormable lateral movement (such as WannaCry and NotPetya).
- **Remediation Action:**
  1. Immediately disable the SMBv1 protocol host-wide via PowerShell:
     ```powershell
     Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
     ```
  2. Apply Microsoft Security Bulletin MS17-010 / latest Cumulative Update.
  3. Ensure TCP ports 139 and 445 are strictly isolated behind internal network firewalls.

---

### Priority 2: Unauthenticated Arbitrary File Copy in ProFTPD 1.3.5 (Host `192.168.56.102` / Port 21 TCP)
- **Vulnerability Identifiers:** `CVE-2015-3306`, `CVE-2019-12815`
- **CVSS Base Score:** **10.0 / 9.8 (CRITICAL)**
- **Technical Risk:** The `mod_copy` module in ProFTPD 1.3.5 allows unauthenticated remote users to issue `SITE CPFR` and `SITE CPTO` commands. An attacker can copy arbitrary files from any source directory to web-accessible directories, resulting in arbitrary file read, web shell upload, and complete server compromise.
- **Remediation Action:**
  1. Upgrade ProFTPD to version 1.3.6 or later, or migrate entirely to SFTP via OpenSSH.
  2. If FTP service is strictly necessary, disable `mod_copy` by adding or ensuring `LoadModule mod_copy.c` is commented out in `/etc/proftpd/modules.conf`.
  3. Restrict TCP port 21 ingress to authorized administrative jump hosts only.

---

### Priority 3: HTTP Request Validation & FilesMatch Bypass in Apache (Host `192.168.56.101` / Port 80 TCP)
- **Vulnerability Identifiers:** `CVE-2018-1312` (CVSS 9.8), `CVE-2017-15715` (CVSS 8.1), `CVE-2017-15710` (CVSS 7.5)
- **CVSS Base Score:** **9.8 / 8.1 (CRITICAL / HIGH)**
- **Technical Risk:** In Apache HTTP Server 2.4.29, `<FilesMatch>` directives can match filenames ending in a newline (`\n`), allowing malicious uploaded files (such as `.php\n`) to bypass security restrictions and execute on the server. Additionally, `mod_auth_digest` nonce generation weaknesses permit replay attacks.
- **Remediation Action:**
  1. Update Apache HTTP Server to the current LTS release (Apache 2.4.58 or higher).
  2. Audit `httpd.conf` and replace ambiguous `<FilesMatch>` regular expressions with strictly bounded matches.
  3. Deploy a Web Application Firewall (WAF) or reverse proxy to inspect request headers and reject malformed filenames.

---

## 4. Secondary Recommendations
- **SSH Hardening (Port 22 TCP across Hosts .101 & .102):** Upgrade OpenSSH to version 8.8+; disable legacy password authentication in `/etc/ssh/sshd_config` (`PasswordAuthentication no`), enable public key authentication only, and implement Fail2ban brute-force protection.
- **MySQL Exposure (Port 3306 TCP on Host .102):** Rebind `bind-address = 127.0.0.1` in `/etc/mysql/my.cnf` to restrict database connectivity strictly to local applications.
- **Microsoft RPC (Port 135 TCP on Host .103):** Block port 135 from all non-management and external segments.

---

## 5. Submission & Mentor Sign-Off Checklist
- [x] `scanner.py` source code with inline comments and modular design.
- [x] `scope.txt` containing validated authorized target definitions.
- [x] `vulnerability_report.csv` formatted according to SOC ingestion standards.
- [x] `vulnerability_report.html` featuring interactive metrics, color-coded severity badges, and remediation guidance.
- [x] Attestation confirming zero scans outside authorized target VMs.
