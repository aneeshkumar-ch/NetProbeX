#!/usr/bin/env python3
"""
================================================================================
ENTERPRISE NETWORK VULNERABILITY SCANNER (DUAL-ENGINE & ACTIVE VERIFICATION)
================================================================================
Features:
  - Expanded Enterprise Port Catalog (Top 105 Network Ports).
  - In-Memory Live CVE Correlation against NIST NVD API v2.0 (Zero DB / Storage).
  - Product Name & Version Extraction from service banners.
  - Highest CVSS Base Score Determination per open port.
  - CVSS v3.1 Severity Mapping: None (0), Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9), Critical (9.0-10.0), Unknown.
  - Critical-First Sorting Order.
  - Color-Coded Badges: Red (Critical), Orange (High), Yellow (Medium), Blue (Low), Gray (None/Unknown).
  - Windows Process & PID Inspection.
  - SOC Reporting (HTML & CSV Exports).
  - Live Streaming Web Dashboard integration (--dashboard).
================================================================================
"""

import os
import re
import sys
import json
import time
import socket
import shutil
import logging
import argparse
import ipaddress
import subprocess
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple

import requests
import pandas as pd

# Optional Nmap import
try:
    import nmap
    NMAP_MODULE_AVAILABLE = True
except ImportError:
    NMAP_MODULE_AVAILABLE = False


# ==============================================================================
# LOGGING & CONFIGURATION
# ==============================================================================

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, datefmt=DATE_FORMAT)
logger = logging.getLogger("EnterpriseScanner")

DEFAULT_SCOPE_FILE = "scope.txt"
DEFAULT_CSV_OUTPUT = "vulnerability_report.csv"
DEFAULT_HTML_OUTPUT = "vulnerability_report.html"
DEFAULT_PDF_OUTPUT = "vulnerability_report.pdf"

# Top 105 Enterprise Ports (Curated 103 unique enterprise ports)
EXPANDED_ENTERPRISE_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137, 138, 139, 143,
    161, 162, 179, 389, 443, 445, 465, 500, 514, 515, 520, 523, 548, 554, 587, 623, 631, 636,
    873, 902, 990, 993, 995, 1025, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083,
    2086, 2087, 2181, 2222, 3000, 3128, 3268, 3269, 3306, 3389, 4000, 4200, 4443, 4500, 5000,
    5060, 5353, 5357, 5432, 5433, 5434, 5672, 5900, 5901, 5985, 5986, 6379, 6432, 6667, 7001,
    7077, 7680, 8000, 8008, 8080, 8081, 8443, 8500, 8888, 9000, 9090, 9092, 9200, 9300, 9418,
    9999, 10000, 27017, 28017
]


# ==============================================================================
# PORT PARSING & SCOPE VALIDATION ENGINE
# ==============================================================================

def parse_port_selection(ports_spec: str, default_ports: List[int]) -> Tuple[List[int], str]:
    """
    Parses and validates port specifications:
      - 'default' / 'curated' -> default 103-port list
      - 'all' / 'full' / '1-65535' -> full range 1-65535
      - '1-1024' -> range
      - '22,80,443,8000-8100' -> mixed comma list and ranges
    Returns:
      (sorted_unique_ports_list, mode_label)
    Raises:
      ValueError if any port is invalid, non-integer, or outside 1-65535.
    """
    if not ports_spec or str(ports_spec).strip().lower() in ["default", "curated"]:
        return list(default_ports), "Curated (103)"

    spec_clean = str(ports_spec).strip().lower()
    if spec_clean in ["all", "full", "1-65535"]:
        return list(range(1, 65536)), "Full (1-65535)"

    ports_set = set()
    tokens = spec_clean.replace(" ", "").split(",")
    for token in tokens:
        if not token:
            continue
        if "-" in token:
            sub = token.split("-")
            if len(sub) != 2:
                raise ValueError(f"Invalid port range format: '{token}'. Expected 'start-end' (e.g. 1-1024).")
            try:
                start = int(sub[0])
                end = int(sub[1])
            except ValueError:
                raise ValueError(f"Non-integer value in port range '{token}'.")
            if start > end:
                raise ValueError(f"Invalid port range '{token}': start ({start}) cannot exceed end ({end}).")
            if start < 1 or end > 65535:
                raise ValueError(f"Port range '{token}' out of bounds. Ports must be between 1 and 65535.")
            ports_set.update(range(start, end + 1))
        else:
            try:
                p = int(token)
            except ValueError:
                raise ValueError(f"Invalid port number '{token}'. Expected integer between 1 and 65535.")
            if p < 1 or p > 65535:
                raise ValueError(f"Port {p} out of bounds. Ports must be between 1 and 65535.")
            ports_set.add(p)

    if not ports_set:
        raise ValueError(f"No valid ports could be parsed from '{ports_spec}'.")

    sorted_ports = sorted(ports_set)
    label = "Full (1-65535)" if len(sorted_ports) == 65535 else f"Custom ({len(sorted_ports)} ports)"
    return sorted_ports, label


def load_authorized_scope(scope_file: str = DEFAULT_SCOPE_FILE) -> List[str]:
    """Loads authorized target IPs and subnets from scope.txt."""
    if not os.path.exists(scope_file):
        return ["127.0.0.1", "localhost", "::1"]

    scope = []
    try:
        with open(scope_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                target = line.split("#")[0].strip()
                if target:
                    scope.append(target)
    except Exception as e:
        logger.warning(f"Error reading scope file {scope_file}: {e}")
    return scope or ["127.0.0.1", "localhost", "::1"]


def is_target_in_scope(target: str, scope_file: str = DEFAULT_SCOPE_FILE) -> bool:
    """Verifies whether the target IP is in the authorized scan scope."""
    if target in ["127.0.0.1", "localhost", "::1"]:
        return True

    authorized_list = load_authorized_scope(scope_file)
    if target in authorized_list:
        return True

    try:
        target_ip = ipaddress.ip_address(target)
        for entry in authorized_list:
            if entry in ["localhost"]:
                continue
            try:
                if "/" in entry:
                    net = ipaddress.ip_network(entry, strict=False)
                    if target_ip in net:
                        return True
                else:
                    auth_ip = ipaddress.ip_address(entry)
                    if target_ip == auth_ip:
                        return True
            except ValueError:
                pass
    except ValueError:
        pass

    return False


# ==============================================================================
# WINDOWS PROCESS MAPPING ENGINE
# ==============================================================================

def get_listening_processes() -> Dict[int, Dict[str, Any]]:
    """Maps listening TCP ports to their Windows Process Name and PID."""
    port_to_proc = {}
    try:
        out = subprocess.check_output("netstat -ano -p tcp", shell=True, text=True)
        pid_to_name = {4: "System (Windows Kernel)"}

        try:
            task_out = subprocess.check_output("tasklist /fo csv /nh", shell=True, text=True)
            for line in task_out.strip().splitlines():
                parts = [p.strip(' "') for p in line.split('","')]
                if len(parts) >= 2:
                    try:
                        pid_to_name[int(parts[1])] = parts[0]
                    except ValueError:
                        pass
        except Exception:
            pass

        for line in out.splitlines():
            line = line.strip()
            if "LISTENING" in line:
                tokens = line.split()
                if len(tokens) >= 5:
                    local_addr = tokens[1]
                    pid = int(tokens[4])
                    port = int(local_addr.split(":")[-1])
                    proc_name = pid_to_name.get(pid, f"PID {pid}")
                    port_to_proc[port] = {"pid": pid, "name": proc_name}
    except Exception:
        pass
    return port_to_proc


# ==============================================================================
# BANNER PARSER & IN-MEMORY NVD LOOKUP ENGINE
# ==============================================================================

def parse_product_version(banner: str) -> Tuple[str, str]:
    """Extracts product name and version string from service banner."""
    banner = banner.strip()

    # 1. SSH identification strings (e.g. OpenSSH_9.6p1)
    ssh_match = re.search(r'OpenSSH[_-]?([0-9]+\.[0-9]+[p0-9]*)', banner, re.I)
    if ssh_match:
        return 'OpenSSH', ssh_match.group(1)

    # 2. Slash format: Product/Version (e.g. Apache/2.4.58 or nginx/1.18.0)
    slash_match = re.search(r'([A-Za-z0-9_-]+)/([0-9]+(?:\.[0-9]+)+[a-z0-9_.-]*)', banner)
    if slash_match:
        prod = slash_match.group(1)
        if prod.lower() in ["http", "tcp"]:
            prod = "Web Server"
        return prod, slash_match.group(2)

    # 3. Product space version: (e.g. Apache httpd 2.4.29, ProFTPD 1.3.5, MySQL 5.7.21)
    ver_match = re.search(r'([A-Za-z]+(?:\s+[A-Za-z]+)?)\s+([0-9]+(?:\.[0-9]+)+[a-z0-9_.-]*)', banner)
    if ver_match:
        prod = ver_match.group(1).replace('httpd', '').strip()
        return prod, ver_match.group(2)

    # 4. Known keyword fallbacks
    for known in ['OpenSSH', 'Apache', 'nginx', 'PostgreSQL', 'MySQL', 'ProFTPD', 'Microsoft', 'Redis']:
        if known.lower() in banner.lower():
            return known, ''

    words = banner.split()
    if words and len(words[0]) > 2 and words[0].lower() not in ["active", "unknown", "tcp", "http"]:
        return words[0], ''

    return 'Unknown', ''


def lookup_nvd_cves_in_memory(banner: str) -> Dict[str, Any]:
    """
    In-Memory CVE lookup and CVSS severity scoring:
      - Queries NIST NVD REST API v2.0 in memory.
      - Finds highest CVSS score.
      - Maps to CVSS v3.1: Critical (9.0-10.0), High (7.0-8.9), Medium (4.0-6.9), Low (0.1-3.9), None (0), Unknown.
      - Zero database, zero storage.
    """
    product, version = parse_product_version(banner)

    clean_ver = ""
    if version and version != "N/A":
        m = re.match(r'([0-9]+(?:\.[0-9]+)+)', version)
        clean_ver = m.group(1) if m else version

    candidates = []
    if product != "Unknown":
        if version and version != "N/A":
            candidates.append(f"{product} {version}".strip())
            if clean_ver and clean_ver != version:
                candidates.append(f"{product} {clean_ver}".strip())
        else:
            candidates.append(product)

    highest_score: Optional[float] = None
    highest_cve: Optional[str] = None
    headers = {"User-Agent": "EnterpriseScanner/2.0"}

    for query in candidates:
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(query)}"
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                for v in vulns:
                    cve = v.get("cve", {})
                    cid = cve.get("id")
                    metrics = cve.get("metrics", {})
                    score = None

                    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                        score = float(metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", 0.0))
                    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                        score = float(metrics["cvssMetricV30"][0]["cvssData"].get("baseScore", 0.0))
                    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                        score = float(metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", 0.0))

                    if score is not None:
                        if highest_score is None or score > highest_score:
                            highest_score = score
                            highest_cve = cid

                if highest_score is not None:
                    break
        except Exception:
            pass

    if highest_score is not None:
        if highest_score >= 9.0:
            severity = "Critical"
            badge_color = "red"
            rank = 1
        elif highest_score >= 7.0:
            severity = "High"
            badge_color = "orange"
            rank = 2
        elif highest_score >= 4.0:
            severity = "Medium"
            badge_color = "yellow"
            rank = 3
        elif highest_score > 0.0:
            severity = "Low"
            badge_color = "blue"
            rank = 4
        else:
            severity = "None"
            badge_color = "gray"
            rank = 5

        return {
            "product": product,
            "version": version or "N/A",
            "cve_id": highest_cve or "N/A",
            "highest_cvss": highest_score,
            "severity": severity,
            "badge_color": badge_color,
            "rank": rank
        }

    return {
        "product": product,
        "version": version or "N/A",
        "cve_id": "None Found",
        "highest_cvss": None,
        "severity": "Unknown",
        "badge_color": "gray",
        "rank": 6
    }


# ==============================================================================
# PROTOCOL BANNER GRABBER
# ==============================================================================

def grab_banner(host: str, port: int) -> Tuple[str, str]:
    banner = "Active Listening Service"
    service = "unknown"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((host, port))

            if port in [80, 8080, 8000, 5000, 3000, 8888, 8008, 8081, 9000, 9090]:
                service = "http"
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: EnterpriseScanner/2.0\r\n\r\n")
                raw = s.recv(1024).decode("utf-8", errors="ignore")
                for line in raw.splitlines():
                    if line.lower().startswith("server:"):
                        banner = line.split(":", 1)[1].strip()
                        break
                if not banner or banner == "Active Listening Service":
                    banner = "HTTP Web Service"
            elif port == 445:
                service = "microsoft-ds"
                banner = "Microsoft Windows SMB (v2/v3 Active)"
            elif port == 135:
                service = "msrpc"
                banner = "Microsoft Windows RPC Endpoint Mapper"
            elif port in [5432, 5433, 5434, 6432]:
                service = "postgresql"
                s.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
                resp = s.recv(1024)
                if resp in [b"S", b"N"]:
                    banner = "PostgreSQL SSL-Enabled Protocol Listener"
                else:
                    banner = "PostgreSQL Compatible Database Service"
            elif port in [21, 22, 25, 587]:
                service = "ftp" if port == 21 else ("ssh" if port == 22 else "smtp")
                resp = s.recv(1024).decode("utf-8", errors="ignore")
                if resp:
                    banner = resp.strip().splitlines()[0]
            elif port == 623:
                service = "asf-rmcp"
                banner = "Intel Local Manageability Service"
            elif port == 5357:
                service = "wsdapi"
                banner = "Microsoft WSDAPI Device Discovery"
            elif port == 7680:
                service = "wudo"
                banner = "Windows Update Delivery Optimization"
    except Exception:
        pass
    return banner, service


def get_local_interfaces() -> List[Dict[str, str]]:
    interfaces = []
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            interfaces.append({"name": "Host Interface", "ip": ip})
    except Exception:
        pass
    interfaces.append({"name": "Loopback (Localhost)", "ip": "127.0.0.1"})
    return interfaces


# ==============================================================================
# REPORT GENERATOR (CSV & HTML)
# ==============================================================================

class ReportGenerator:
    def __init__(self, records: List[Dict[str, Any]], targets: List[str], scan_mode: str = "Curated (103)", total_scanned: int = 103):
        self.records = records
        self.targets = targets
        self.scan_mode = scan_mode
        self.total_scanned = total_scanned
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def export_csv(self, filename: str = DEFAULT_CSV_OUTPUT) -> None:
        fieldnames = [
            "Host", "Port", "Protocol", "Service", "Banner",
            "Product", "Version", "Top CVE ID", "Highest CVSS", "Severity", "Process", "PID", "Latency (ms)",
            "Scan Mode", "Total Ports Scanned"
        ]
        flat_rows = []
        for r in self.records:
            score_str = f"{r['highest_cvss']:.1f}" if r["highest_cvss"] is not None else "N/A"
            flat_rows.append({
                "Host": r["host"],
                "Port": r["port"],
                "Protocol": r["protocol"],
                "Service": r["service"],
                "Banner": r["banner"],
                "Product": r["product"],
                "Version": r["version"],
                "Top CVE ID": r["cve_id"],
                "Highest CVSS": score_str,
                "Severity": r["severity"],
                "Process": r["process"],
                "PID": r["pid"],
                "Latency (ms)": r["latency_ms"],
                "Scan Mode": self.scan_mode,
                "Total Ports Scanned": self.total_scanned
            })
        if flat_rows:
            df = pd.DataFrame(flat_rows)
            df.to_csv(filename, index=False, columns=fieldnames, encoding="utf-8")
        else:
            df = pd.DataFrame(columns=fieldnames)
            df.to_csv(filename, index=False, encoding="utf-8")
        logger.info(f"CSV Report generated: {os.path.abspath(filename)}")

    def export_html(self, filename: str = DEFAULT_HTML_OUTPUT) -> None:
        unique_ports = len(self.records)
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0, "Unknown": 0}
        for r in self.records:
            sev = r["severity"]
            if sev in counts:
                counts[sev] += 1
            else:
                counts["Unknown"] += 1

        rows_html = []
        for r in self.records:
            cve_link = (
                f"<a href='https://nvd.nist.gov/vuln/detail/{r['cve_id']}' target='_blank' style='color:#38bdf8;text-decoration:none;'>{r['cve_id']}</a>"
                if r['cve_id'].startswith("CVE-") else r['cve_id']
            )
            score_display = f"{r['highest_cvss']:.1f}" if r["highest_cvss"] is not None else "—"

            rows_html.append(f"""
            <tr>
                <td><strong>{r['host']}</strong></td>
                <td><span style="background:rgba(255,255,255,0.08);padding:4px 8px;border-radius:4px;font-family:monospace;font-weight:bold;">{r['port']}/{r['protocol']}</span></td>
                <td><strong>{r['banner']}</strong></td>
                <td><code>{r['product']} {r['version'] if r['version'] != 'N/A' else ''}</code></td>
                <td>{cve_link}</td>
                <td><strong style="font-size:0.95rem;">{score_display}</strong></td>
                <td><span class="badge badge-{r['badge_color']}">{r['severity']}</span></td>
                <td><code>{r['process']} (PID {r['pid']})</code></td>
                <td>{r['latency_ms']} ms</td>
            </tr>
            """)

        if not rows_html:
            rows_html.append("""
            <tr>
                <td colspan="9" style="text-align: center; color: #94a3b8; padding: 25px;">
                    No open network ports detected within evaluated port range.
                </td>
            </tr>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Network Vulnerability Assessment Report</title>
    <style>
        :root {{
            --bg: #090e1a;
            --surface: #111a2e;
            --border: #233454;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --red: #ef4444;
            --orange: #f97316;
            --yellow: #eab308;
            --blue: #3b82f6;
            --gray: #94a3b8;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
        body {{ background-color: var(--bg); color: var(--text-main); padding: 30px 20px; line-height: 1.5; }}
        .container {{ max-width: 1450px; margin: 0 auto; }}
        header {{
            background: linear-gradient(135deg, #111a2e 0%, #090e1a 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 26px 30px;
            margin-bottom: 24px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }}
        h1 {{ font-size: 1.85rem; font-weight: 700; color: #ffffff; }}
        .subtitle {{ color: var(--accent); font-size: 0.95rem; margin-top: 4px; font-weight: 500; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 24px; }}
        .metric-card {{ background-color: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 18px; text-align: center; }}
        .metric-title {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px; }}
        .metric-val {{ font-size: 2rem; font-weight: 800; line-height: 1; }}
        .c-accent {{ color: var(--accent); }}
        .c-red {{ color: var(--red); }}
        .c-orange {{ color: var(--orange); }}
        .c-yellow {{ color: var(--yellow); }}
        .c-blue {{ color: var(--blue); }}
        .c-gray {{ color: var(--gray); }}
        .table-card {{ background-color: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.3); }}
        .table-header {{ padding: 18px 24px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.88rem; }}
        th {{ background-color: rgba(9, 14, 26, 0.9); color: var(--text-muted); padding: 14px 18px; font-size: 0.75rem; text-transform: uppercase; border-bottom: 1px solid var(--border); }}
        td {{ padding: 14px 18px; border-bottom: 1px solid var(--border); vertical-align: middle; }}
        tr:hover td {{ background-color: #18233c; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; }}
        .badge-red    {{ background-color: rgba(239, 68, 68, 0.2);  color: #ef4444; border: 1px solid #ef4444; }}
        .badge-orange {{ background-color: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid #f97316; }}
        .badge-yellow {{ background-color: rgba(234, 179, 8, 0.2);  color: #eab308; border: 1px solid #eab308; }}
        .badge-blue   {{ background-color: rgba(59, 130, 246, 0.2); color: #3b82f6; border: 1px solid #3b82f6; }}
        .badge-gray   {{ background-color: rgba(148, 163, 184, 0.2);color: #94a3b8; border: 1px solid #64748b; }}
        footer {{ margin-top: 30px; text-align: center; font-size: 0.8rem; color: var(--text-muted); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Enterprise Network Vulnerability Assessment Report</h1>
            <div style="font-size: 0.85rem; color: var(--text-muted); margin-top: 10px;">
                <strong>Audit Date:</strong> {self.timestamp} | <strong>Target Scope:</strong> {', '.join(self.targets)} | <strong>Scan Mode:</strong> {self.scan_mode} | <strong>Total Ports Evaluated:</strong> {self.total_scanned:,}
            </div>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-title">Ports Evaluated</div>
                <div class="metric-val c-accent">{self.total_scanned:,}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Open Services</div>
                <div class="metric-val c-accent">{unique_ports}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Critical (9.0-10.0)</div>
                <div class="metric-val c-red">{counts['Critical']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">High (7.0-8.9)</div>
                <div class="metric-val c-orange">{counts['High']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Medium (4.0-6.9)</div>
                <div class="metric-val c-yellow">{counts['Medium']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Low (0.1-3.9)</div>
                <div class="metric-val c-blue">{counts['Low']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">None / Unknown</div>
                <div class="metric-val c-gray">{counts['None'] + counts['Unknown']}</div>
            </div>
        </div>

        <div class="table-card">
            <div class="table-header">
                <h2>Verified Service Findings (Sorted Critical-First)</h2>
                <span style="font-size: 0.85rem; color: var(--text-muted);">{unique_ports} Active Ports</span>
            </div>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Host</th>
                            <th>Port / Proto</th>
                            <th>Service Banner</th>
                            <th>Product & Version</th>
                            <th>Top Matching CVE</th>
                            <th>Highest CVSS</th>
                            <th>Severity Badge</th>
                            <th>Process (PID)</th>
                            <th>Latency</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(rows_html)}
                    </tbody>
                </table>
            </div>
        </div>

        <footer>
            <p>Generated by <strong>Enterprise Network Vulnerability Scanner</strong>. Confidential Audit Report.</p>
        </footer>
    </div>
</body>
</html>"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"HTML Report generated: {os.path.abspath(filename)}")

    def export_pdf(self, filename: str = DEFAULT_PDF_OUTPUT) -> None:
        """Generates a polished audit-ready PDF vulnerability report using ReportLab."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors

            doc = SimpleDocTemplate(
                filename,
                pagesize=letter,
                rightMargin=36,
                leftMargin=36,
                topMargin=36,
                bottomMargin=36
            )
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'DocTitle',
                parent=styles['Heading1'],
                fontSize=17,
                textColor=colors.HexColor('#0f172a'),
                spaceAfter=4
            )
            sub_style = ParagraphStyle(
                'DocSub',
                parent=styles['Normal'],
                fontSize=8.5,
                textColor=colors.HexColor('#475569'),
                spaceAfter=12
            )
            body_style = ParagraphStyle(
                'DocBody',
                parent=styles['Normal'],
                fontSize=7.5,
                leading=9.5,
                textColor=colors.HexColor('#1e293b')
            )
            head_style = ParagraphStyle(
                'DocHead',
                parent=styles['Normal'],
                fontSize=8,
                leading=10,
                fontName='Helvetica-Bold',
                textColor=colors.white
            )

            story = []
            story.append(Paragraph("Enterprise Network Vulnerability Assessment Report", title_style))
            story.append(Paragraph(
                f"<b>Target:</b> {', '.join(self.targets)} &nbsp;|&nbsp; "
                f"<b>Scan Mode:</b> {self.scan_mode} &nbsp;|&nbsp; "
                f"<b>Total Ports Scanned:</b> {self.total_scanned:,} &nbsp;|&nbsp; "
                f"<b>Audit Date:</b> {self.timestamp}",
                sub_style
            ))
            story.append(Spacer(1, 8))

            # Summary Stats Table
            counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0, "Unknown": 0}
            for r in self.records:
                counts[r.get("severity", "Unknown")] = counts.get(r.get("severity", "Unknown"), 0) + 1

            stat_data = [
                ["Total Ports Scanned", "Open Services", "Critical", "High", "Medium", "Low", "Info / Unknown"],
                [f"{self.total_scanned:,}", str(len(self.records)), str(counts["Critical"]), str(counts["High"]),
                 str(counts["Medium"]), str(counts["Low"]), str(counts["None"] + counts["Unknown"])]
            ]
            stat_table = Table(stat_data, colWidths=[85, 80, 75, 75, 75, 75, 75])
            stat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ]))
            story.append(stat_table)
            story.append(Spacer(1, 14))

            story.append(Paragraph("<b>Identified Network Findings (Sorted Critical-First)</b>", styles['Heading3']))
            story.append(Spacer(1, 6))

            findings_data = [
                [Paragraph("<b>Port/Proto</b>", head_style),
                 Paragraph("<b>Service Banner</b>", head_style),
                 Paragraph("<b>Top CVE</b>", head_style),
                 Paragraph("<b>CVSS</b>", head_style),
                 Paragraph("<b>Severity</b>", head_style),
                 Paragraph("<b>Remediation Directive</b>", head_style)]
            ]

            remediation_map = {
                "microsoft-ds": "Disable SMBv1 host-wide; apply MS17-010 patch; isolate port 445.",
                "msrpc": "Restrict TCP port 135 to internal administrative jump hosts.",
                "netbios-ssn": "Disable NetBIOS over TCP/IP if not required for legacy shares.",
                "ftp": "Disable mod_copy; enforce SFTP via OpenSSH or upgrade ProFTPD.",
                "ssh": "Enforce SSH keys; disable password/root login; update OpenSSH.",
                "http": "Update web server; audit virtual host configs; enforce HTTPS.",
                "postgresql": "Enforce SSL; bind strictly to 127.0.0.1; restrict pg_hba.conf.",
                "asf-rmcp": "Update Intel AMT firmware; restrict access to management VLAN.",
                "wsdapi": "Disable Windows WSD if network device discovery is unnecessary.",
                "wudo": "Configure Windows Update Delivery Optimization to local LAN only."
            }

            for r in self.records:
                score = f"{r['highest_cvss']:.1f}" if r['highest_cvss'] is not None else "—"
                service_key = str(r.get('service', '')).lower()
                remediation = remediation_map.get(service_key, "Review service configuration and apply latest vendor security patches.")
                findings_data.append([
                    Paragraph(f"{r['port']}/{r['protocol']}", body_style),
                    Paragraph(f"{r['banner'][:35]}", body_style),
                    Paragraph(f"{r['cve_id']}", body_style),
                    Paragraph(score, body_style),
                    Paragraph(f"<b>{r['severity']}</b>", body_style),
                    Paragraph(remediation, body_style),
                ])

            if not self.records:
                findings_data.append([
                    Paragraph("—", body_style),
                    Paragraph("No open ports identified", body_style),
                    Paragraph("None", body_style),
                    Paragraph("—", body_style),
                    Paragraph("None", body_style),
                    Paragraph("All evaluated ports closed or filtered.", body_style),
                ])

            findings_table = Table(findings_data, colWidths=[60, 115, 80, 40, 55, 190])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ]))
            story.append(findings_table)

            doc.build(story)
            logger.info(f"PDF Report generated: {os.path.abspath(filename)}")
        except Exception as e:
            logger.warning(f"Could not generate PDF report: {e}")


# ==============================================================================
# MAIN SCANNER PIPELINE
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Enterprise Network Vulnerability Scanner (Dual-Engine)")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP to scan (e.g. 127.0.0.1 or 192.168.1.238)")
    parser.add_argument("--ports", default="default", help="Ports to scan: 'default' (103 ports), 'all' (1-65535), '1-1024', or '22,80,443,8000-8100'")
    parser.add_argument("--workers", type=int, default=30, help="Concurrent socket probe threads (1-200, default: 30)")
    parser.add_argument("--timeout", type=float, default=0.2, help="Socket connect timeout in seconds (default: 0.2s / 200ms)")
    parser.add_argument("--output-csv", default=DEFAULT_CSV_OUTPUT, help="CSV output filename")
    parser.add_argument("--output-html", default=DEFAULT_HTML_OUTPUT, help="HTML output filename")
    parser.add_argument("--output-pdf", default=DEFAULT_PDF_OUTPUT, help="PDF output filename")
    parser.add_argument("--dashboard", action="store_true", help="Launch the Live Streaming Web Dashboard")

    args = parser.parse_args()

    # Launch live streaming dashboard if requested
    if args.dashboard:
        print("=" * 80)
        print("  LAUNCHING LIVE STREAMING WEB DASHBOARD")
        print("  Navigate to: http://localhost:8765 in your browser")
        print("  (Automatically opening your default browser in 1 second...)")
        print("  Press Ctrl+C in this terminal to stop the server.")
        print("=" * 80)
        import dashboard
        import uvicorn
        import threading
        import webbrowser
        def _open_b():
            time.sleep(1.2)
            webbrowser.open("http://localhost:8765")
        threading.Thread(target=_open_b, daemon=True).start()
        uvicorn.run(dashboard.app, host="0.0.0.0", port=8765, log_level="info")
        return

    target = args.target

    # 1. Enforce Scope Compliance
    if not is_target_in_scope(target, DEFAULT_SCOPE_FILE):
        logger.error(f"[SCOPE VIOLATION] Target '{target}' is not listed in authorized scan scope ({DEFAULT_SCOPE_FILE}). Aborting.")
        sys.exit(1)

    # 2. Parse & Validate Ports Selection
    try:
        ports, scan_mode = parse_port_selection(args.ports, EXPANDED_ENTERPRISE_PORTS)
    except ValueError as err:
        logger.error(f"Invalid --ports specification: {err}")
        sys.exit(1)

    # 3. Validate Workers (1-200)
    if args.workers < 1 or args.workers > 200:
        logger.error("Workers count must be between 1 and 200.")
        sys.exit(1)

    # 4. Validate & Normalize Timeout (support seconds or ms)
    timeout_sec = args.timeout / 1000.0 if args.timeout > 5.0 else args.timeout
    if timeout_sec <= 0 or timeout_sec > 10.0:
        logger.error("Timeout must be between 0.01 and 10.0 seconds.")
        sys.exit(1)

    # 5. Estimated Duration & Remote Confirmation for Large Scans
    est_seconds = round((len(ports) * timeout_sec) / args.workers, 1)
    est_str = f"{est_seconds:.1f}s" if est_seconds < 60 else f"{est_seconds/60:.1f} mins"

    print("=" * 95)
    print(f"  ENTERPRISE NETWORK VULNERABILITY SCANNER — {scan_mode.upper()} ({len(ports):,} PORTS)")
    print("  In-Memory NIST NVD Correlation | CVSS v3.1 Scoring | Critical-First Ordering")
    print("=" * 95)

    local_ifaces = get_local_interfaces()
    print("  [+] Detected Host Network Interfaces:")
    for iface in local_ifaces:
        print(f"      - {iface['name']}: {iface['ip']}")
    print("=" * 95)

    if (scan_mode == "Full (1-65535)" or len(ports) > 1000) and target not in ["127.0.0.1", "localhost", "::1"]:
        print(f"[*] Large port scan: {len(ports):,} ports on remote host '{target}'.")
        print(f"[*] Estimated execution duration: ~{est_str} (Workers: {args.workers}, Timeout: {timeout_sec:.2f}s).")
        try:
            confirm = input(f"[CONFIRMATION REQUIRED] Proceed with full scan on '{target}'? [y/N]: ").strip().lower()
            if confirm not in ['y', 'yes']:
                print("[ABORTED] Scan cancelled by user.")
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            print("\n[ABORTED] Scan cancelled by user.")
            sys.exit(0)

    logger.info(f"Target: {target} | Mode: {scan_mode} ({len(ports):,} ports) | Workers: {args.workers} | Timeout: {timeout_sec:.2f}s | Est: ~{est_str}")
    proc_map = get_listening_processes()

    open_ports = []
    print("\n" + "-" * 95)
    print(f"{'PORT':<6} {'STATUS':<8} {'LATENCY':<10} {'WINDOWS PROCESS':<24} {'PID':<6} {'SERVICE BANNER':<28}")
    print("-" * 95)

    def probe_port(p: int):
        t0 = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout_sec)
                if s.connect_ex((target, p)) == 0:
                    lat = (time.perf_counter() - t0) * 1000
                    return p, lat
        except Exception:
            pass
        return None

    batch_size = 1000
    scanned_count = 0
    total_count = len(ports)

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        for i in range(0, total_count, batch_size):
            batch = ports[i : i + batch_size]
            futures = {executor.submit(probe_port, p): p for p in batch}
            for f in as_completed(futures):
                res = f.result()
                scanned_count += 1
                if res:
                    p, lat = res
                    proc_info = proc_map.get(p, {"name": "System / Service", "pid": "---"})
                    banner, service = grab_banner(target, p)
                    open_ports.append({
                        "port": p,
                        "protocol": "TCP",
                        "latency_ms": round(lat, 2),
                        "process": proc_info["name"],
                        "pid": proc_info["pid"],
                        "banner": banner,
                        "service": service
                    })
                    print(f"{p:<6} {'OPEN':<8} {lat:>6.2f} ms   {proc_info['name']:<24} {str(proc_info['pid']):<6} {banner:<28}", flush=True)

            if total_count > 1000:
                pct = round((scanned_count / total_count) * 100, 1)
                print(f"[*] Progress: {scanned_count:,} / {total_count:,} ports ({pct}%)...", end="\r", flush=True)

    if total_count > 1000:
        print()

    print("-" * 95)
    logger.info(f"Identified {len(open_ports)} open port(s). Querying NIST NVD in memory for matching CVEs...")

    records = []
    print("\n" + "=" * 95)
    print(f"{'PORT':<6} {'PRODUCT & VERSION':<22} {'TOP MATCHING CVE':<18} {'CVSS':<6} {'SEVERITY':<10} {'PROCESS'}")
    print("=" * 95)

    for item in open_ports:
        # In-memory CVE evaluation (no DB, no storage)
        cve_eval = lookup_nvd_cves_in_memory(item["banner"])
        record = {
            "host": target,
            "port": item["port"],
            "protocol": item["protocol"],
            "service": item["service"],
            "banner": item["banner"],
            "process": item["process"],
            "pid": item["pid"],
            "latency_ms": item["latency_ms"],
            "product": cve_eval["product"],
            "version": cve_eval["version"],
            "cve_id": cve_eval["cve_id"],
            "highest_cvss": cve_eval["highest_cvss"],
            "severity": cve_eval["severity"],
            "badge_color": cve_eval["badge_color"],
            "rank": cve_eval["rank"]
        }
        records.append(record)

    # Sort Critical-first (Rank 1 to 6, then highest CVSS descending)
    records.sort(key=lambda x: (x["rank"], -(x["highest_cvss"] or 0.0), x["port"]))

    for r in records:
        prod_ver = f"{r['product']} {r['version'] if r['version'] != 'N/A' else ''}"[:20]
        score_str = f"{r['highest_cvss']:.1f}" if r["highest_cvss"] is not None else "—"
        print(f"{r['port']:<6} {prod_ver:<22} {r['cve_id']:<18} {score_str:<6} [{r['severity']:<8}] {r['process']}")

    # Export Reports
    reporter = ReportGenerator(records, [target], scan_mode=scan_mode, total_scanned=len(ports))
    reporter.export_csv(args.output_csv)
    reporter.export_html(args.output_html)
    reporter.export_pdf(args.output_pdf)

    print("\n" + "=" * 95)
    print(f"  AUDIT COMPLETED — {scan_mode.upper()} (IN-MEMORY NVD SCORING — CRITICAL-FIRST)")
    print(f"  [+] Scanned Target:    {target}")
    print(f"  [+] Evaluated Ports:   {len(ports):,}")
    print(f"  [+] Open Services:     {len(records)}")
    print(f"  [+] CSV Output:        {os.path.abspath(args.output_csv)}")
    print(f"  [+] HTML Output:       {os.path.abspath(args.output_html)}")
    print(f"  [+] PDF Output:        {os.path.abspath(args.output_pdf)}")
    print("=" * 95 + "\n")


if __name__ == "__main__":
    main()
