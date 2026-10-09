#!/usr/bin/env python3
"""
================================================================================
ENTERPRISE REAL-TIME NETWORK VULNERABILITY SCANNER & STREAMING DASHBOARD
================================================================================
Features:
  - Enterprise Port Sweep (Top 105 Network Ports).
  - High-Speed Concurrent Socket Probing (Non-blocking asyncio + ThreadPool).
  - In-Memory Live CVE Correlation against NIST NVD API v2.0 (Zero DB / Storage).
  - Product Name & Version Extraction from service banners.
  - Highest CVSS Base Score Determination per open port.
  - CVSS v3.1 Severity Mapping: None (0), Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9), Critical (9.0-10.0), Unknown.
  - Critical-First Sorting Order.
  - Color-Coded Badges: Red (Critical), Orange (High), Yellow (Medium), Blue (Low), Gray (None/Unknown).
  - Dual-Mode Real-Time Streaming (SSE + JSON REST Fallback).
  - Dual-Stack 0.0.0.0 Binding (Works with localhost, 127.0.0.1, and LAN IP).
  - Full CORS Support.
  - Windows Process & PID Inspection.
================================================================================
"""

import os
import re
import sys
import time
import json
import socket
import asyncio
import ipaddress
import subprocess
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, Any, List, Optional, AsyncGenerator, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import requests
import uvicorn

app = FastAPI(title="Enterprise Network Vulnerability Scanner")

# Enable CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================================
# ENTERPRISE PORT CATALOG (TOP 105 NETWORK PORTS)
# ==============================================================================
ENTERPRISE_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137, 138, 139, 143,
    161, 162, 179, 389, 443, 445, 465, 500, 514, 515, 520, 523, 548, 554, 587, 623, 631, 636,
    873, 902, 990, 993, 995, 1025, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083,
    2086, 2087, 2181, 2222, 3000, 3128, 3268, 3269, 3306, 3389, 4000, 4200, 4443, 4500, 5000,
    5060, 5353, 5357, 5432, 5433, 5434, 5672, 5900, 5901, 5985, 5986, 6379, 6432, 6667, 7001,
    7077, 7680, 8000, 8008, 8080, 8081, 8443, 8500, 8888, 9000, 9090, 9092, 9200, 9300, 9418,
    9999, 10000, 27017, 28017
]

# Thread pool for non-blocking network operations
IO_EXECUTOR = ThreadPoolExecutor(max_workers=30)

DEFAULT_SCOPE_FILE = "scope.txt"
active_scan_cancelled = False


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
        pass
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


def check_ports_chunk(target: str, chunk: List[int], timeout_sec: float, max_threads: int) -> List[Tuple[int, bool, float]]:
    """Probes a chunk of ports concurrently using ThreadPoolExecutor."""
    results = []
    def probe_single(p: int):
        t0 = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout_sec)
                res = s.connect_ex((target, p))
                lat = (time.perf_counter() - t0) * 1000
                return p, (res == 0), lat
        except Exception:
            return p, False, 0.0

    with ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = {pool.submit(probe_single, p): p for p in chunk}
        for f in as_completed(futures):
            results.append(f.result())
    return results

def get_listening_processes() -> Dict[int, Dict[str, Any]]:
    """Maps listening TCP ports to their Process Name and PID (Windows and Linux)."""
    port_to_proc = {}
    if os.name == "nt":
        try:
            netstat_out = subprocess.check_output("netstat -ano -p tcp", shell=True, text=True)
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

            for line in netstat_out.splitlines():
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
    else:
        # Linux / POSIX systems
        try:
            ss_out = subprocess.check_output(["ss", "-tlpn"], text=True, stderr=subprocess.DEVNULL)
            for line in ss_out.splitlines()[1:]:
                tokens = line.split()
                if len(tokens) >= 4 and "LISTEN" in tokens[0]:
                    addr = tokens[3]
                    port_str = addr.rsplit(":", 1)[-1]
                    try:
                        port = int(port_str)
                    except ValueError:
                        continue
                    proc_name = "System / Service"
                    pid_val: Any = "---"
                    for tok in tokens[4:]:
                        if "users:" in tok or "users:((" in tok:
                            m = re.search(r'\("([^"]+)",pid=(\d+)', tok)
                            if m:
                                proc_name = m.group(1)
                                pid_val = int(m.group(2))
                            break
                    port_to_proc[port] = {"pid": pid_val, "name": proc_name}
        except Exception:
            pass
    return port_to_proc


# ==============================================================================
# BANNER PARSING & IN-MEMORY NVD CVE LOOKUP ENGINE
# ==============================================================================

def parse_product_version(banner: str) -> Tuple[str, str]:
    """
    Extracts product name and version string from service banner.
    Examples:
      - 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4' -> ('OpenSSH', '9.6p1')
      - 'Apache/2.4.58 (Ubuntu)' -> ('Apache', '2.4.58')
      - 'nginx/1.18.0' -> ('nginx', '1.18.0')
      - 'ProFTPD 1.3.5' -> ('ProFTPD', '1.3.5')
    """
    banner = banner.strip()

    # 1. SSH identification strings (e.g., OpenSSH_9.6p1)
    ssh_match = re.search(r'OpenSSH[_-]?([0-9]+\.[0-9]+[p0-9]*)', banner, re.I)
    if ssh_match:
        return 'OpenSSH', ssh_match.group(1)

    # 2. Slash format: Product/Version (e.g., Apache/2.4.58, nginx/1.18.0, lighttpd/1.4.55)
    slash_match = re.search(r'([A-Za-z0-9_-]+)/([0-9]+(?:\.[0-9]+)+[a-z0-9_.-]*)', banner)
    if slash_match:
        prod = slash_match.group(1)
        if prod.lower() in ["http", "tcp"]:
            prod = "Web Server"
        return prod, slash_match.group(2)

    # 3. Product space version: (e.g., Apache httpd 2.4.29, ProFTPD 1.3.5, MySQL 5.7.21)
    ver_match = re.search(r'([A-Za-z]+(?:\s+[A-Za-z]+)?)\s+([0-9]+(?:\.[0-9]+)+[a-z0-9_.-]*)', banner)
    if ver_match:
        prod = ver_match.group(1).replace('httpd', '').strip()
        return prod, ver_match.group(2)

    # 4. Known keyword fallbacks
    for known in ['OpenSSH', 'Apache', 'nginx', 'PostgreSQL', 'MySQL', 'ProFTPD', 'Microsoft', 'Intel', 'Redis']:
        if known.lower() in banner.lower():
            return known, ''

    words = banner.split()
    if words and len(words[0]) > 2 and words[0].lower() not in ["active", "unknown", "tcp", "http"]:
        return words[0], ''

    return 'Unknown', ''


def lookup_nvd_cves_in_memory(banner: str) -> Dict[str, Any]:
    """
    In-Memory CVE lookup and CVSS severity scoring:
      - Parses product name and version.
      - Queries NIST NVD REST API v2.0 for matching CVEs.
      - Takes the highest CVSS score.
      - Maps score to CVSS v3.1 severity labels:
          Critical (9.0-10.0), High (7.0-8.9), Medium (4.0-6.9), Low (0.1-3.9), None (0), Unknown
      - Assigns badge color: red, orange, yellow, blue, gray
      - No database, no storage: purely in memory.
      - If no match found or error, labels 'Unknown' without raising exceptions.
    """
    product, version = parse_product_version(banner)

    # Clean version for broader NIST token matching (e.g. 9.6p1 -> 9.6)
    clean_ver = ""
    if version and version != "N/A":
        m = re.match(r'([0-9]+(?:\.[0-9]+)+)', version)
        clean_ver = m.group(1) if m else version

    # Formulate candidate queries
    candidates = []
    if product != "Unknown":
        if version and version != "N/A":
            candidates.append(f"{product} {version}".strip())
            if clean_ver and clean_ver != version:
                candidates.append(f"{product} {clean_ver}".strip())
        elif product not in ["Microsoft", "Intel", "Web Server"]:
            candidates.append(product)

    highest_score: Optional[float] = None
    highest_cve: Optional[str] = None
    headers = {"User-Agent": "EnterpriseVulnerabilityScanner/2.0"}

    for query in candidates:
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(query)}"
            r = requests.get(url, headers=headers, timeout=3.5)
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                for v in vulns:
                    cve = v.get("cve", {})
                    cid = cve.get("id")
                    metrics = cve.get("metrics", {})
                    score = None

                    # Priority: CVSS 3.1 > CVSS 3.0 > CVSS 2.0
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
            # Graceful fallback: purely non-fatal
            pass

    # Map CVSS v3.1 Severity Labels & Badge Colors
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

    # If no CVE match found or query failed
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

def grab_service_banner(host: str, port: int) -> Tuple[str, str]:
    """Sends protocol probes to identify the active service banner."""
    banner = "Active Listening Service"
    service = "unknown"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            s.connect((host, port))

            # HTTP Probing
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

            # SMB (Port 445)
            elif port == 445:
                service = "microsoft-ds"
                banner = "Microsoft Windows SMB (v2/v3 Active)"

            # RPC (Port 135)
            elif port == 135:
                service = "msrpc"
                banner = "Microsoft Windows RPC Endpoint Mapper"

            # NetBIOS (Port 139)
            elif port == 139:
                service = "netbios-ssn"
                banner = "Microsoft Windows NetBIOS Session Service"

            # PostgreSQL / Traefik / PgBouncer
            elif port in [5432, 5433, 5434, 6432]:
                service = "postgresql"
                s.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
                resp = s.recv(1024)
                if resp in [b"S", b"N"]:
                    banner = "PostgreSQL SSL-Enabled Protocol Listener"
                else:
                    banner = "PostgreSQL Compatible Database Service"

            # Interactive Daemons (SSH, FTP, SMTP)
            elif port in [21, 22, 25, 587]:
                service = "ftp" if port == 21 else ("ssh" if port == 22 else "smtp")
                resp = s.recv(1024).decode("utf-8", errors="ignore")
                if resp:
                    banner = resp.strip().splitlines()[0]

            # Intel AMT
            elif port == 623:
                service = "asf-rmcp"
                banner = "Intel Local Manageability Service"

            # Windows Services
            elif port == 5357:
                service = "wsdapi"
                banner = "Microsoft WSDAPI Device Discovery"
            elif port == 7680:
                service = "wudo"
                banner = "Windows Update Delivery Optimization"

    except Exception:
        pass

    return banner, service


# Synchronous single-port check for ThreadPool
def check_single_port(target: str, port: int) -> Tuple[int, bool, float]:
    port_start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            res = s.connect_ex((target, port))
            latency = (time.perf_counter() - port_start) * 1000
            return port, (res == 0), latency
    except Exception:
        return port, False, (time.perf_counter() - port_start) * 1000


# ==============================================================================
# REAL-TIME SCAN ENGINE (SERVER-SENT EVENTS STREAM)
# ==============================================================================

async def scan_event_stream(
    target: str = "127.0.0.1",
    ports_spec: str = "default",
    workers: int = 30,
    timeout: float = 0.2,
    request: Request = None
) -> AsyncGenerator[str, None]:
    """Streams real-time port discoveries and in-memory CVE scoring via SSE with batching and cancel support."""
    global active_scan_cancelled
    active_scan_cancelled = False
    start_time = time.time()
    loop = asyncio.get_running_loop()

    # 1. Scope Verification
    if not is_target_in_scope(target):
        err_msg = f"Scope Violation: Target '{target}' is not listed in authorized scan scope ({DEFAULT_SCOPE_FILE}). Scan rejected."
        yield f"data: {json.dumps({'type': 'error', 'message': err_msg})}\n\n"
        return

    # 2. Port Selection Parsing
    try:
        ports, scan_mode = parse_port_selection(ports_spec, ENTERPRISE_PORTS)
    except ValueError as err:
        err_msg = f"Invalid Port Selection: {str(err)}"
        yield f"data: {json.dumps({'type': 'error', 'message': err_msg})}\n\n"
        return

    # 3. Parameters Validation
    workers_clamped = max(1, min(200, int(workers)))
    timeout_sec = timeout / 1000.0 if timeout > 5.0 else timeout
    timeout_sec = max(0.01, min(10.0, float(timeout_sec)))

    total_ports = len(ports)
    proc_map = await loop.run_in_executor(IO_EXECUTOR, get_listening_processes)

    # Step 1: Send Initialization Event
    yield f"data: {json.dumps({'type': 'init', 'target': target, 'total_ports': total_ports, 'scan_mode': scan_mode, 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')})}\n\n"
    await asyncio.sleep(0.02)

    open_ports_count = 0
    records = []
    scanned_count = 0

    batch_size = min(500, max(25, total_ports // 20))

    for i in range(0, total_ports, batch_size):
        # Check cancellation
        if active_scan_cancelled or (request and await request.is_disconnected()):
            elapsed = round(time.time() - start_time, 2)
            yield f"data: {json.dumps({'type': 'cancelled', 'message': 'Scan halted by user.', 'scanned': scanned_count, 'total_ports': total_ports, 'elapsed_seconds': elapsed, 'open_ports': open_ports_count})}\n\n"
            return

        chunk = ports[i : i + batch_size]
        chunk_results = await loop.run_in_executor(None, check_ports_chunk, target, chunk, timeout_sec, workers_clamped)

        for port, is_open, port_latency in chunk_results:
            scanned_count += 1
            if is_open:
                open_ports_count += 1
                proc_info = proc_map.get(port, {"name": "System / Service", "pid": "---"})

                banner, service = await loop.run_in_executor(IO_EXECUTOR, grab_service_banner, target, port)
                cve_eval = await loop.run_in_executor(IO_EXECUTOR, lookup_nvd_cves_in_memory, banner)

                record = {
                    "port": port,
                    "protocol": "TCP",
                    "service": service,
                    "banner": banner,
                    "process": proc_info["name"],
                    "pid": proc_info["pid"],
                    "latency_ms": round(port_latency, 2),
                    "product": cve_eval["product"],
                    "version": cve_eval["version"],
                    "cve_id": cve_eval["cve_id"],
                    "highest_cvss": cve_eval["highest_cvss"],
                    "severity": cve_eval["severity"],
                    "badge_color": cve_eval["badge_color"],
                    "rank": cve_eval["rank"]
                }
                records.append(record)

                pct = round((scanned_count / total_ports) * 100, 1)
                yield f"data: {json.dumps({'type': 'port_open', 'record': record, 'progress': pct, 'current_port': port, 'open_count': open_ports_count, 'scanned': scanned_count, 'total_ports': total_ports})}\n\n"
                await asyncio.sleep(0.005)

        # Batch progress update
        pct = round((scanned_count / total_ports) * 100, 1)
        yield f"data: {json.dumps({'type': 'progress', 'progress': pct, 'current_port': chunk[-1], 'open_count': open_ports_count, 'scanned': scanned_count, 'total_ports': total_ports})}\n\n"
        await asyncio.sleep(0.005)

    # Sort results Critical-first (Rank 1 to 6, then highest CVSS descending)
    records.sort(key=lambda x: (x["rank"], -(x["highest_cvss"] or 0.0), x["port"]))

    elapsed = round(time.time() - start_time, 2)
    summary = {
        "target": target,
        "total_scanned": total_ports,
        "scan_mode": scan_mode,
        "open_ports": open_ports_count,
        "elapsed_seconds": elapsed,
        "records": records
    }
    yield f"data: {json.dumps({'type': 'complete', 'summary': summary})}\n\n"


@app.post("/api/scan/cancel")
@app.get("/api/scan/cancel")
async def cancel_scan():
    global active_scan_cancelled
    active_scan_cancelled = True
    return {"status": "ok", "message": "Scan cancellation requested."}


@app.get("/api/scan/stream")
async def stream_scan(
    request: Request,
    target: str = "127.0.0.1",
    ports: str = "default",
    workers: int = 30,
    timeout: float = 0.2
):
    return StreamingResponse(
        scan_event_stream(target, ports, workers, timeout, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )


@app.get("/api/scan/run")
async def run_scan_json(
    target: str = "127.0.0.1",
    ports: str = "default",
    workers: int = 30,
    timeout: float = 0.2
):
    """REST Fallback endpoint returning all results in JSON."""
    if not is_target_in_scope(target):
        return {"error": f"Scope Violation: Target '{target}' is not listed in authorized scan scope."}

    try:
        port_list, scan_mode = parse_port_selection(ports, ENTERPRISE_PORTS)
    except ValueError as e:
        return {"error": str(e)}

    workers_clamped = max(1, min(200, int(workers)))
    timeout_sec = timeout / 1000.0 if timeout > 5.0 else timeout
    timeout_sec = max(0.01, min(10.0, float(timeout_sec)))

    start_time = time.time()
    loop = asyncio.get_running_loop()
    proc_map = await loop.run_in_executor(IO_EXECUTOR, get_listening_processes)
    records = []

    batch_size = 500
    for i in range(0, len(port_list), batch_size):
        chunk = port_list[i : i + batch_size]
        chunk_results = await loop.run_in_executor(None, check_ports_chunk, target, chunk, timeout_sec, workers_clamped)
        for port, is_open, latency in chunk_results:
            if is_open:
                proc_info = proc_map.get(port, {"name": "System / Service", "pid": "---"})
                banner, service = await loop.run_in_executor(IO_EXECUTOR, grab_service_banner, target, port)
                cve_eval = await loop.run_in_executor(IO_EXECUTOR, lookup_nvd_cves_in_memory, banner)
                records.append({
                    "port": port,
                    "protocol": "TCP",
                    "service": service,
                    "banner": banner,
                    "process": proc_info["name"],
                    "pid": proc_info["pid"],
                    "latency_ms": round(latency, 2),
                    "product": cve_eval["product"],
                    "version": cve_eval["version"],
                    "cve_id": cve_eval["cve_id"],
                    "highest_cvss": cve_eval["highest_cvss"],
                    "severity": cve_eval["severity"],
                    "badge_color": cve_eval["badge_color"],
                    "rank": cve_eval["rank"]
                })

    records.sort(key=lambda x: (x["rank"], -(x["highest_cvss"] or 0.0), x["port"]))
    return {
        "target": target,
        "total_scanned": len(port_list),
        "scan_mode": scan_mode,
        "open_ports": len(records),
        "elapsed_seconds": round(time.time() - start_time, 2),
        "records": records
    }


# ==============================================================================
# DASHBOARD UI (HTML, CSS, JAVASCRIPT SINGLE PAGE APP)
# ==============================================================================

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Network Vulnerability Scanner</title>
    <style>
        :root {
            --bg: #090e1a;
            --surface: #0f172a;
            --surface-card: #141f36;
            --border: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #64748b;
            --text-sub: #94a3b8;
            --accent: #38bdf8;
            --red: #ef4444;
            --orange: #f97316;
            --yellow: #eab308;
            --blue: #3b82f6;
            --gray: #64748b;
            --green: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background-color: var(--bg); color: var(--text-main); padding: 25px; line-height: 1.5; }
        .container { max-width: 1450px; margin: 0 auto; }
        
        .navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: linear-gradient(135deg, #0f172a 0%, #090e1a 100%);
            border: 1px solid var(--border);
            padding: 20px 28px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        }
        .nav-title { font-size: 1.45rem; font-weight: 700; color: #ffffff; display: flex; align-items: center; gap: 10px; }
        .nav-status { font-size: 0.82rem; color: var(--text-sub); display: flex; align-items: center; gap: 8px; font-weight: 500; }
        .pulse-dot { width: 9px; height: 9px; border-radius: 50%; background-color: var(--green); display: inline-block; animation: pulse 1.8s infinite; }
        @keyframes pulse { 0% { transform: scale(0.9); opacity: 0.7; } 50% { transform: scale(1.3); opacity: 1; } 100% { transform: scale(0.9); opacity: 0.7; } }

        .control-bar {
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px 24px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
            flex-wrap: wrap;
        }
        .target-input-group { display: flex; align-items: center; gap: 12px; }
        .target-input-group label { font-size: 0.85rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-sub); }
        .target-input {
            background-color: var(--surface-card);
            border: 1px solid var(--border);
            color: #ffffff;
            padding: 9px 16px;
            border-radius: 6px;
            font-size: 0.95rem;
            width: 240px;
            outline: none;
            font-family: monospace;
        }
        .btn-scan {
            background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
            color: #ffffff;
            border: none;
            padding: 9px 24px;
            border-radius: 6px;
            font-size: 0.9rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .btn-scan:hover { background: #0284c7; transform: translateY(-1px); box-shadow: 0 4px 15px rgba(2,132,199,0.35); }
        .select-input {
            background-color: var(--surface-card);
            border: 1px solid var(--border);
            color: #ffffff;
            padding: 9px 14px;
            border-radius: 6px;
            font-size: 0.90rem;
            outline: none;
            cursor: pointer;
        }
        .select-input option {
            background-color: var(--surface-card);
            color: #ffffff;
        }
        .btn-cancel {
            background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
            color: #ffffff;
            border: none;
            padding: 9px 20px;
            border-radius: 6px;
            font-size: 0.9rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .btn-cancel:hover:not(:disabled) {
            background: #dc2626;
            transform: translateY(-1px);
            box-shadow: 0 4px 15px rgba(220,38,38,0.35);
        }
        .btn-cancel:disabled {
            opacity: 0.45;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        /* EXECUTIVE ANALYTICS: RISK GAUGE & DONUT CHART */
        .executive-panel {
            display: grid;
            grid-template-columns: 340px 1fr;
            gap: 16px;
            margin-bottom: 20px;
        }
        @media (max-width: 900px) {
            .executive-panel { grid-template-columns: 1fr; }
        }
        .analytics-card {
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px 22px;
            display: flex;
            align-items: center;
            gap: 20px;
        }
        .analytics-header {
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text-muted);
            margin-bottom: 4px;
        }
        .gauge-container {
            position: relative;
            width: 110px;
            height: 110px;
            flex-shrink: 0;
        }
        .gauge-svg {
            transform: rotate(-90deg);
            width: 100%;
            height: 100%;
        }
        .gauge-bg {
            fill: none;
            stroke: #1e293b;
            stroke-width: 9;
        }
        .gauge-bar {
            fill: none;
            stroke: var(--accent);
            stroke-width: 9;
            stroke-linecap: round;
            stroke-dasharray: 282.74;
            stroke-dashoffset: 282.74;
            transition: stroke-dashoffset 0.8s ease, stroke 0.3s ease;
        }
        .gauge-center {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
            line-height: 1;
        }
        .gauge-val {
            font-size: 1.85rem;
            font-weight: 800;
            color: #ffffff;
            letter-spacing: -0.03em;
        }
        .gauge-sub {
            font-size: 0.65rem;
            font-weight: 600;
            color: var(--text-muted);
            margin-top: 2px;
        }
        .risk-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.70rem;
            font-weight: 800;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            margin-top: 6px;
        }

        /* DONUT CHART COMPONENT */
        .donut-wrapper {
            display: flex;
            align-items: center;
            justify-content: space-between;
            width: 100%;
            gap: 24px;
        }
        .donut-container {
            position: relative;
            width: 110px;
            height: 110px;
            flex-shrink: 0;
        }
        .donut-svg {
            transform: rotate(-90deg);
            width: 100%;
            height: 100%;
        }
        .donut-center-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
            line-height: 1;
        }
        .donut-total {
            font-size: 1.4rem;
            font-weight: 800;
            color: #ffffff;
        }
        .donut-lbl {
            font-size: 0.60rem;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 0.05em;
            margin-top: 2px;
        }
        .donut-legend {
            display: flex;
            flex-wrap: wrap;
            gap: 12px 24px;
            flex-grow: 1;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.78rem;
        }
        .legend-dot {
            width: 8px;
            height: 8px;
            border-radius: 2px;
        }
        .legend-name { color: var(--text-sub); font-weight: 500; }
        .legend-val { font-weight: 700; color: #ffffff; }

        /* SEVERITY METRICS GRID WITH COLORED TOP BORDERS */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 14px;
            margin-bottom: 20px;
        }
        .metric-card {
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px 16px;
            text-align: center;
            transition: transform 0.15s ease, border-color 0.15s ease;
        }
        .metric-card:hover { transform: translateY(-2px); }
        
        /* Thin colored top borders */
        .card-scanned  { border-top: 3px solid #38bdf8; }
        .card-open     { border-top: 3px solid #0284c7; }
        .card-critical { border-top: 3px solid #ef4444; }
        .card-high     { border-top: 3px solid #f97316; }
        .card-medium   { border-top: 3px solid #eab308; }
        .card-low      { border-top: 3px solid #3b82f6; }
        .card-other    { border-top: 3px solid #64748b; }

        /* Increased spacing and font-weight contrast between labels and big numbers */
        .metric-label {
            font-size: 0.68rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text-muted);
            margin-bottom: 12px;
        }
        .metric-val {
            font-size: 2.25rem;
            font-weight: 800;
            line-height: 1;
            letter-spacing: -0.02em;
        }
        .c-accent { color: var(--accent); }
        .c-red    { color: var(--red); }
        .c-orange { color: var(--orange); }
        .c-yellow { color: var(--yellow); }
        .c-blue   { color: var(--blue); }
        .c-gray   { color: #94a3b8; }

        .progress-box {
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 20px;
        }
        .progress-header { display: flex; justify-content: space-between; font-size: 0.82rem; color: var(--text-sub); margin-bottom: 8px; font-weight: 500; }
        .progress-track { width: 100%; height: 7px; background-color: var(--surface-card); border-radius: 4px; overflow: hidden; }
        .progress-fill { height: 100%; width: 0%; background: linear-gradient(90deg, #38bdf8, #10b981); transition: width 0.15s ease; }

        .stream-terminal {
            background-color: #050811;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px 18px;
            font-family: 'Consolas', monospace;
            font-size: 0.80rem;
            color: #38bdf8;
            height: 105px;
            overflow-y: auto;
            margin-bottom: 20px;
            line-height: 1.6;
        }

        /* FINDINGS TABLE WITH COLORED LEFT-BORDER STRIPS */
        .table-card {
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        .table-head {
            padding: 16px 22px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .table-head h2 { font-size: 1.05rem; font-weight: 700; color: #ffffff; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }
        th {
            background-color: #0b1120;
            color: var(--text-muted);
            padding: 12px 18px;
            font-size: 0.70rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            border-bottom: 1px solid var(--border);
        }
        td { padding: 13px 18px; border-bottom: 1px solid var(--border); vertical-align: middle; }
        tr:hover td { background-color: rgba(255,255,255,0.02); }
        
        /* Left border strips on each row matching severity */
        tr.row-critical { border-left: 4px solid #ef4444; }
        tr.row-high     { border-left: 4px solid #f97316; }
        tr.row-medium   { border-left: 4px solid #eab308; }
        tr.row-low      { border-left: 4px solid #3b82f6; }
        tr.row-other    { border-left: 4px solid #64748b; }

        .port-badge { background-color: rgba(255,255,255,0.06); padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 0.82rem; font-weight: 700; }
        .score-pill { font-weight: 800; font-size: 0.85rem; padding: 2px 8px; border-radius: 4px; background: rgba(255,255,255,0.05); }
        
        /* High-Contrast Severity Badges on Dark Background */
        .badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 3px 9px;
            border-radius: 5px;
            font-size: 0.70rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }
        .badge-red     { background-color: rgba(239, 68, 68, 0.20);  color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.6); }
        .badge-orange  { background-color: rgba(249, 115, 22, 0.20); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.6); }
        .badge-yellow  { background-color: rgba(234, 179, 8, 0.20);  color: #fde047; border: 1px solid rgba(234, 179, 8, 0.6); }
        .badge-blue    { background-color: rgba(59, 130, 246, 0.20); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.6); }
        .badge-gray    { background-color: rgba(148, 163, 184, 0.16);color: #e2e8f0; border: 1px solid rgba(148, 163, 184, 0.4); }

        .cve-link { color: var(--accent); text-decoration: none; font-family: monospace; font-weight: 600; }
        .cve-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <!-- TOP NAVBAR -->
        <div class="navbar">
            <div>
                <div class="nav-title">🛡️ Enterprise Network Vulnerability Scanner</div>
            </div>
            <div class="nav-status">
                <span class="pulse-dot"></span> <span id="statusText">Engine Ready</span>
            </div>
        </div>

        <!-- CONTROL BAR -->
        <div class="control-bar">
            <div class="target-input-group" style="flex-wrap: wrap;">
                <label for="targetIp">Target Host:</label>
                <input type="text" id="targetIp" class="target-input" value="127.0.0.1">

                <label for="portMode" style="margin-left: 8px;">Scan Mode:</label>
                <select id="portMode" class="select-input" onchange="handlePortModeChange()">
                    <option value="default" selected>Curated (103 Ports)</option>
                    <option value="all">Full (1-65535)</option>
                    <option value="custom">Custom Range / List</option>
                </select>

                <input type="text" id="customPorts" class="target-input" placeholder="e.g. 1-1024 or 22,80,443" style="display: none; width: 220px;">

                <button class="btn-scan" id="startBtn" onclick="startLiveScan()">
                    <span>▶ Start Real-Time Scan</span>
                </button>
                <button class="btn-cancel" id="cancelBtn" onclick="cancelScan()" disabled>
                    <span>⏹ Stop Scan</span>
                </button>
            </div>
            <div id="scanModeBadge" style="font-size: 0.80rem; font-weight: 600; color: var(--accent); background: rgba(56,189,248,0.1); padding: 6px 12px; border-radius: 6px; border: 1px solid rgba(56,189,248,0.25);">
                Mode: Curated (103 Ports)
            </div>
        </div>

        <!-- EXECUTIVE ANALYTICS: RISK GAUGE & DONUT CHART -->
        <div class="executive-panel">
            <!-- RISK SCORE GAUGE -->
            <div class="analytics-card">
                <div class="gauge-container">
                    <svg class="gauge-svg" viewBox="0 0 100 100">
                        <circle class="gauge-bg" cx="50" cy="50" r="45"></circle>
                        <circle class="gauge-bar" id="gaugeBar" cx="50" cy="50" r="45"></circle>
                    </svg>
                    <div class="gauge-center">
                        <div class="gauge-val" id="riskScoreVal">0</div>
                        <div class="gauge-sub">/ 100</div>
                    </div>
                </div>
                <div>
                    <div class="analytics-header">Overall Risk Score</div>
                    <div style="font-size: 0.85rem; color: #ffffff; font-weight: 700;" id="riskPostureText">Nominal Posture</div>
                    <span class="risk-badge badge-gray" id="riskBadge">LOW RISK</span>
                    <div style="font-size: 0.70rem; color: var(--text-muted); margin-top: 6px; line-height: 1.3;">
                        Critical-weighted vulnerability risk index.
                    </div>
                </div>
            </div>

            <!-- SEVERITY DONUT CHART -->
            <div class="analytics-card">
                <div class="donut-wrapper">
                    <div class="donut-container">
                        <svg class="donut-svg" viewBox="0 0 100 100" id="donutSvg">
                            <!-- Background placeholder circle -->
                            <circle cx="50" cy="50" r="40" fill="none" stroke="#1e293b" stroke-width="12"></circle>
                        </svg>
                        <div class="donut-center-text">
                            <div class="donut-total" id="donutTotal">0</div>
                            <div class="donut-lbl">Findings</div>
                        </div>
                    </div>
                    <div class="donut-legend">
                        <div class="legend-item">
                            <div class="legend-dot" style="background-color: var(--red);"></div>
                            <span class="legend-name">Critical:</span>
                            <span class="legend-val" id="legCritical">0 (0%)</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-dot" style="background-color: var(--orange);"></div>
                            <span class="legend-name">High:</span>
                            <span class="legend-val" id="legHigh">0 (0%)</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-dot" style="background-color: var(--yellow);"></div>
                            <span class="legend-name">Medium:</span>
                            <span class="legend-val" id="legMedium">0 (0%)</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-dot" style="background-color: var(--blue);"></div>
                            <span class="legend-name">Low:</span>
                            <span class="legend-val" id="legLow">0 (0%)</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-dot" style="background-color: var(--gray);"></div>
                            <span class="legend-name">Info / None:</span>
                            <span class="legend-val" id="legOther">0 (0%)</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- SEVERITY METRICS GRID WITH THIN COLORED TOP BORDERS -->
        <div class="metrics-grid">
            <div class="metric-card card-scanned">
                <div class="metric-label">Ports Scanned</div>
                <div class="metric-val c-accent" id="metricScanned">0 / 103</div>
            </div>
            <div class="metric-card card-open">
                <div class="metric-label">Open Ports</div>
                <div class="metric-val c-accent" id="metricOpen">0</div>
            </div>
            <div class="metric-card card-critical">
                <div class="metric-label">Critical (9.0-10.0)</div>
                <div class="metric-val c-red" id="metricCritical">0</div>
            </div>
            <div class="metric-card card-high">
                <div class="metric-label">High (7.0-8.9)</div>
                <div class="metric-val c-orange" id="metricHigh">0</div>
            </div>
            <div class="metric-card card-medium">
                <div class="metric-label">Medium (4.0-6.9)</div>
                <div class="metric-val c-yellow" id="metricMedium">0</div>
            </div>
            <div class="metric-card card-low">
                <div class="metric-label">Low (0.1-3.9)</div>
                <div class="metric-val c-blue" id="metricLow">0</div>
            </div>
            <div class="metric-card card-other">
                <div class="metric-label">None / Unknown</div>
                <div class="metric-val c-gray" id="metricOther">0</div>
            </div>
        </div>

        <!-- PROGRESS TRACKER -->
        <div class="progress-box">
            <div class="progress-header">
                <span id="progressText">Ready to start scan...</span>
                <span id="progressPct">0%</span>
            </div>
            <div class="progress-track">
                <div class="progress-fill" id="progressBar"></div>
            </div>
        </div>

        <!-- LIVE STREAM TERMINAL -->
        <div class="stream-terminal" id="terminalLog">
            [System] Network scanner engine initialized. Ready for scan...
        </div>

        <!-- RESULTS TABLE (SORTED CRITICAL-FIRST) -->
        <div class="table-card">
            <div class="table-head">
                <h2>Real-Time Scan Results (Sorted Critical-First)</h2>
                <span style="font-size: 0.82rem; color: var(--text-muted); font-weight: 600;" id="resultCount">0 Open Services</span>
            </div>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
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
                    <tbody id="tableBody">
                        <tr>
                            <td colspan="8" style="text-align: center; color: var(--text-muted); padding: 35px;">
                                Click "Start Real-Time Scan" to evaluate enterprise ports with in-memory CVE correlation.
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        let eventSource = null;
        let scanRecords = [];
        let counts = { Critical: 0, High: 0, Medium: 0, Low: 0, None: 0, Unknown: 0 };

        function logToTerminal(msg) {
            const term = document.getElementById("terminalLog");
            const entry = document.createElement("div");
            entry.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
            term.appendChild(entry);
            term.scrollTop = term.scrollHeight;
        }

        // Calculate weighted Risk Score (0-100)
        function calculateRiskScore() {
            if (scanRecords.length === 0) return 0;
            let totalWeighted = 0;
            let totalWeight = 0;
            let critCount = counts.Critical;
            let highCount = counts.High;

            scanRecords.forEach(r => {
                let score = r.highest_cvss !== null ? r.highest_cvss : 0;
                let w = 1.0;
                if (r.severity === "Critical") { w = 10.0; if (score === 0) score = 9.8; }
                else if (r.severity === "High") { w = 7.5; if (score === 0) score = 7.8; }
                else if (r.severity === "Medium") { w = 5.0; if (score === 0) score = 5.5; }
                else if (r.severity === "Low") { w = 2.0; if (score === 0) score = 2.5; }
                else { w = 0.5; score = 0.5; }

                totalWeighted += score * w;
                totalWeight += w;
            });

            if (totalWeight === 0) return 0;
            let base = (totalWeighted / totalWeight) * 10;

            // Enterprise severity floor adjustment
            if (critCount > 0) {
                base = Math.max(base, 80 + Math.min(20, critCount * 5));
            } else if (highCount > 0) {
                base = Math.max(base, 65 + Math.min(20, highCount * 4));
            }
            return Math.min(100, Math.max(0, Math.round(base)));
        }

        // Update Risk Gauge UI
        function updateRiskGauge(score) {
            const bar = document.getElementById("gaugeBar");
            const scoreEl = document.getElementById("riskScoreVal");
            const textEl = document.getElementById("riskPostureText");
            const badgeEl = document.getElementById("riskBadge");

            scoreEl.textContent = score;

            // Circumference of r=45 is 282.74
            const C = 282.74;
            const offset = C - (score / 100) * C;
            bar.style.strokeDashoffset = offset;

            let strokeColor = "#38bdf8";
            let tierText = "Nominal Posture";
            let badgeClass = "badge-gray";
            let badgeLabel = "LOW RISK";

            if (score >= 85) {
                strokeColor = "#ef4444";
                tierText = "Critical Exposure";
                badgeClass = "badge-red";
                badgeLabel = "CRITICAL RISK";
            } else if (score >= 70) {
                strokeColor = "#f97316";
                tierText = "High Risk Detected";
                badgeClass = "badge-orange";
                badgeLabel = "HIGH RISK";
            } else if (score >= 40) {
                strokeColor = "#eab308";
                tierText = "Elevated Risk";
                badgeClass = "badge-yellow";
                badgeLabel = "MEDIUM RISK";
            } else if (score > 0) {
                strokeColor = "#3b82f6";
                tierText = "Controlled Posture";
                badgeClass = "badge-blue";
                badgeLabel = "LOW RISK";
            }

            bar.style.stroke = strokeColor;
            textEl.textContent = tierText;
            badgeEl.className = `risk-badge ${badgeClass}`;
            badgeEl.textContent = badgeLabel;
        }

        // Render SVG Donut Chart
        function updateDonutChart() {
            const svg = document.getElementById("donutSvg");
            const total = scanRecords.length;
            document.getElementById("donutTotal").textContent = total;

            if (total === 0) {
                svg.innerHTML = '<circle cx="50" cy="50" r="40" fill="none" stroke="#1e293b" stroke-width="12"></circle>';
                document.getElementById("legCritical").textContent = "0 (0%)";
                document.getElementById("legHigh").textContent = "0 (0%)";
                document.getElementById("legMedium").textContent = "0 (0%)";
                document.getElementById("legLow").textContent = "0 (0%)";
                document.getElementById("legOther").textContent = "0 (0%)";
                return;
            }

            const otherCount = counts.None + counts.Unknown;
            const segments = [
                { count: counts.Critical, color: "#ef4444" },
                { count: counts.High,     color: "#f97316" },
                { count: counts.Medium,   color: "#eab308" },
                { count: counts.Low,      color: "#3b82f6" },
                { count: otherCount,      color: "#64748b" }
            ];

            const C = 2 * Math.PI * 40; // ~251.327
            let accumPercent = 0;
            let svgContent = '<circle cx="50" cy="50" r="40" fill="none" stroke="#1e293b" stroke-width="12"></circle>';

            segments.forEach(seg => {
                if (seg.count > 0) {
                    const ratio = seg.count / total;
                    const strokeDash = ratio * C;
                    const strokeGap = C - strokeDash;
                    const rotation = (accumPercent * 360) - 90; // start top

                    svgContent += `<circle cx="50" cy="50" r="40" fill="none" stroke="${seg.color}" stroke-width="12"
                        stroke-dasharray="${strokeDash} ${strokeGap}"
                        transform="rotate(${rotation} 50 50)"
                        stroke-linecap="butt" style="transition: all 0.5s ease;"></circle>`;

                    accumPercent += ratio;
                }
            });

            svg.innerHTML = svgContent;

            // Update Legend
            const pct = (c) => total > 0 ? `${c} (${Math.round((c / total) * 100)}%)` : "0 (0%)";
            document.getElementById("legCritical").textContent = pct(counts.Critical);
            document.getElementById("legHigh").textContent     = pct(counts.High);
            document.getElementById("legMedium").textContent   = pct(counts.Medium);
            document.getElementById("legLow").textContent      = pct(counts.Low);
            document.getElementById("legOther").textContent    = pct(otherCount);
        }

        function renderTable() {
            // Sort Critical-First (Rank 1 to 6, then highest CVSS descending)
            scanRecords.sort((a, b) => {
                if (a.rank !== b.rank) return a.rank - b.rank;
                const scoreA = a.highest_cvss !== null ? a.highest_cvss : -1;
                const scoreB = b.highest_cvss !== null ? b.highest_cvss : -1;
                if (scoreB !== scoreA) return scoreB - scoreA;
                return a.port - b.port;
            });

            const tbody = document.getElementById("tableBody");
            tbody.innerHTML = "";

            scanRecords.forEach(r => {
                const tr = document.createElement("tr");

                // Colored left-border strip on each row matching severity
                const rowClass = r.severity === 'Critical' ? 'row-critical' :
                                 r.severity === 'High'     ? 'row-high' :
                                 r.severity === 'Medium'   ? 'row-medium' :
                                 r.severity === 'Low'      ? 'row-low' : 'row-other';
                tr.className = rowClass;

                const cveDisplay = r.cve_id && r.cve_id.startsWith("CVE-") 
                    ? `<a href="https://nvd.nist.gov/vuln/detail/${r.cve_id}" target="_blank" class="cve-link">${r.cve_id}</a>`
                    : (r.cve_id || "None Found");
                
                const scoreDisplay = r.highest_cvss !== null ? `${r.highest_cvss.toFixed(1)}` : "—";

                tr.innerHTML = `
                    <td><span class="port-badge">${r.port}/${r.protocol}</span></td>
                    <td><strong style="color: #ffffff;">${r.banner}</strong></td>
                    <td><code>${r.product} ${r.version !== 'N/A' ? r.version : ''}</code></td>
                    <td>${cveDisplay}</td>
                    <td><span class="score-pill">${scoreDisplay}</span></td>
                    <td><span class="badge badge-${r.badge_color}">${r.severity}</span></td>
                    <td><code>${r.process} (${r.pid})</code></td>
                    <td style="color: var(--text-sub);">${r.latency_ms} ms</td>
                `;
                tbody.appendChild(tr);
            });
        }

        function updateMetrics() {
            document.getElementById("metricOpen").textContent = scanRecords.length;
            document.getElementById("metricCritical").textContent = counts.Critical;
            document.getElementById("metricHigh").textContent = counts.High;
            document.getElementById("metricMedium").textContent = counts.Medium;
            document.getElementById("metricLow").textContent = counts.Low;
            document.getElementById("metricOther").textContent = counts.None + counts.Unknown;
            document.getElementById("resultCount").textContent = `${scanRecords.length} Open Services Found`;

            const score = calculateRiskScore();
            updateRiskGauge(score);
            updateDonutChart();
        }

        function handlePortModeChange() {
            const mode = document.getElementById("portMode").value;
            const customInput = document.getElementById("customPorts");
            const badge = document.getElementById("scanModeBadge");
            if (mode === "custom") {
                customInput.style.display = "inline-block";
                customInput.focus();
                badge.textContent = "Mode: Custom Range / List";
            } else if (mode === "all") {
                customInput.style.display = "none";
                badge.textContent = "Mode: Full (1-65535) [65,535 Ports]";
            } else {
                customInput.style.display = "none";
                badge.textContent = "Mode: Curated (103 Ports)";
            }
        }

        async function cancelScan() {
            logToTerminal("[!] Requesting scan halt from server...");
            const cancelBtn = document.getElementById("cancelBtn");
            cancelBtn.disabled = true;
            try {
                const res = await fetch(`${window.location.origin}/api/scan/cancel`, { method: "POST" });
                const json = await res.json();
                logToTerminal(`[!] Server response: ${json.message}`);
            } catch(err) {
                logToTerminal(`[!] Cancel request failed: ${err.message}`);
            }
        }

        function startLiveScan() {
            const target = document.getElementById("targetIp").value.trim() || "127.0.0.1";
            const mode = document.getElementById("portMode").value;
            let portsParam = "default";

            if (mode === "all") {
                portsParam = "all";
                const isLocal = (target === "127.0.0.1" || target.toLowerCase() === "localhost" || target === "::1");
                if (!isLocal) {
                    const confirmed = confirm(
                        `WARNING: You are about to initiate a full 65,535-port TCP scan against remote host '${target}'.\n\nThis may take several minutes, saturate socket connections, or trigger intrusion detection alerts.\n\nProceed with full scan?`
                    );
                    if (!confirmed) {
                        logToTerminal(`[!] Full scan against '${target}' aborted by user.`);
                        return;
                    }
                }
            } else if (mode === "custom") {
                const customVal = document.getElementById("customPorts").value.trim();
                if (!customVal) {
                    alert("Please specify a port range or comma list (e.g. 1-1024 or 22,80,443,8000-8100).");
                    document.getElementById("customPorts").focus();
                    return;
                }
                portsParam = customVal;
            }

            const btn = document.getElementById("startBtn");
            const cancelBtn = document.getElementById("cancelBtn");
            btn.disabled = true;
            btn.style.opacity = "0.6";
            cancelBtn.disabled = false;

            // Reset state
            scanRecords = [];
            counts = { Critical: 0, High: 0, Medium: 0, Low: 0, None: 0, Unknown: 0 };
            updateMetrics();
            document.getElementById("progressBar").style.width = "0%";
            document.getElementById("progressPct").textContent = "0%";
            document.getElementById("tableBody").innerHTML = "";
            document.getElementById("statusText").textContent = `Scanning ${target}...`;

            logToTerminal(`Initiating TCP port scan on ${target} (Mode: ${mode})...`);

            if (eventSource) {
                eventSource.close();
                eventSource = null;
            }

            const streamUrl = `${window.location.origin}/api/scan/stream?target=${encodeURIComponent(target)}&ports=${encodeURIComponent(portsParam)}`;
            let receivedAnyEvent = false;

            try {
                eventSource = new EventSource(streamUrl);

                eventSource.onmessage = function(e) {
                    receivedAnyEvent = true;
                    const data = JSON.parse(e.data);

                    if (data.type === "init") {
                        logToTerminal(`Target accepted: ${data.target} [${data.scan_mode}]. Total ports to evaluate: ${data.total_ports.toLocaleString()}.`);
                        document.getElementById("metricScanned").textContent = `0 / ${data.total_ports.toLocaleString()}`;
                        document.getElementById("scanModeBadge").textContent = `Mode: ${data.scan_mode}`;
                    } else if (data.type === "progress") {
                        document.getElementById("progressBar").style.width = data.progress + "%";
                        document.getElementById("progressPct").textContent = data.progress + "%";
                        document.getElementById("progressText").textContent = `Scanned ${data.scanned.toLocaleString()} / ${data.total_ports.toLocaleString()} (Port ${data.current_port})...`;
                        document.getElementById("metricScanned").textContent = `${data.scanned.toLocaleString()} / ${data.total_ports.toLocaleString()}`;
                    } else if (data.type === "port_open") {
                        const r = data.record;
                        scanRecords.push(r);

                        if (counts.hasOwnProperty(r.severity)) {
                            counts[r.severity]++;
                        } else {
                            counts.Unknown++;
                        }
                        updateMetrics();

                        logToTerminal(`[+] OPEN: Port ${r.port}/TCP -> ${r.banner} | ${r.severity} (CVSS: ${r.highest_cvss !== null ? r.highest_cvss : 'None'})`);
                        renderTable();

                        document.getElementById("metricScanned").textContent = `${data.scanned.toLocaleString()} / ${data.total_ports.toLocaleString()}`;
                        document.getElementById("progressBar").style.width = data.progress + "%";
                        document.getElementById("progressPct").textContent = data.progress + "%";
                        document.getElementById("progressText").textContent = `Port ${data.current_port} Open (${data.scanned.toLocaleString()} / ${data.total_ports.toLocaleString()})`;
                    } else if (data.type === "cancelled") {
                        document.getElementById("statusText").textContent = "Halted";
                        document.getElementById("progressText").textContent = `Scan Stopped (${data.scanned.toLocaleString()} / ${data.total_ports.toLocaleString()} ports scanned).`;
                        logToTerminal(`[!] Scan halted by user: ${data.message} Scanned ${data.scanned.toLocaleString()} / ${data.total_ports.toLocaleString()} ports in ${data.elapsed_seconds}s.`);
                        btn.disabled = false;
                        btn.style.opacity = "1";
                        cancelBtn.disabled = true;
                        if (eventSource) {
                            eventSource.close();
                            eventSource = null;
                        }
                    } else if (data.type === "error") {
                        document.getElementById("statusText").textContent = "Error";
                        document.getElementById("progressText").textContent = "Scan aborted: " + data.message;
                        logToTerminal(`[ERROR] ${data.message}`);
                        alert(data.message);
                        btn.disabled = false;
                        btn.style.opacity = "1";
                        cancelBtn.disabled = true;
                        if (eventSource) {
                            eventSource.close();
                            eventSource = null;
                        }
                    } else if (data.type === "complete") {
                        document.getElementById("progressBar").style.width = "100%";
                        document.getElementById("progressPct").textContent = "100%";
                        document.getElementById("progressText").textContent = `Assessment complete in ${data.summary.elapsed_seconds}s.`;
                        document.getElementById("metricScanned").textContent = `${data.summary.total_scanned.toLocaleString()} / ${data.summary.total_scanned.toLocaleString()}`;
                        document.getElementById("statusText").textContent = "Completed";
                        logToTerminal(`Assessment complete! Scanned ${data.summary.total_scanned.toLocaleString()} ports [${data.summary.scan_mode}], identified ${data.summary.open_ports} open ports in ${data.summary.elapsed_seconds}s.`);
                        renderTable();
                        updateMetrics();
                        btn.disabled = false;
                        btn.style.opacity = "1";
                        cancelBtn.disabled = true;
                        if (eventSource) {
                            eventSource.close();
                            eventSource = null;
                        }
                    }
                };

                eventSource.onerror = function(err) {
                    if (!receivedAnyEvent) {
                        logToTerminal("SSE stream disconnected. Engaging REST fallback scanner...");
                        if (eventSource) { eventSource.close(); eventSource = null; }
                        runRestFallback(target, portsParam, btn, cancelBtn);
                    } else if (eventSource && eventSource.readyState === EventSource.CLOSED) {
                        btn.disabled = false;
                        btn.style.opacity = "1";
                        cancelBtn.disabled = true;
                    }
                };
            } catch (err) {
                logToTerminal("Direct stream initialization failed. Switching to REST scanner...");
                runRestFallback(target, portsParam, btn, cancelBtn);
            }
        }

        async function runRestFallback(target, portsParam, btn, cancelBtn) {
            try {
                document.getElementById("progressText").textContent = "Running scan via REST fallback...";
                document.getElementById("progressBar").style.width = "40%";
                document.getElementById("progressPct").textContent = "40%";

                const resp = await fetch(`${window.location.origin}/api/scan/run?target=${encodeURIComponent(target)}&ports=${encodeURIComponent(portsParam)}`);
                const data = await resp.json();

                if (data.error) {
                    logToTerminal(`[ERROR] ${data.error}`);
                    alert(data.error);
                    document.getElementById("statusText").textContent = "Error";
                    document.getElementById("progressText").textContent = data.error;
                    return;
                }

                scanRecords = data.records;
                counts = { Critical: 0, High: 0, Medium: 0, Low: 0, None: 0, Unknown: 0 };
                scanRecords.forEach(r => {
                    if (counts.hasOwnProperty(r.severity)) counts[r.severity]++;
                    else counts.Unknown++;
                });

                document.getElementById("progressBar").style.width = "100%";
                document.getElementById("progressPct").textContent = "100%";
                document.getElementById("metricScanned").textContent = `${data.total_scanned.toLocaleString()} / ${data.total_scanned.toLocaleString()}`;
                document.getElementById("progressText").textContent = `Assessment complete in ${data.elapsed_seconds}s.`;
                document.getElementById("statusText").textContent = "Completed";
                updateMetrics();
                renderTable();

                logToTerminal(`Scan complete! Found ${data.open_ports} open ports in ${data.elapsed_seconds}s.`);
            } catch (e) {
                logToTerminal(`Scan error: ${e.message}`);
            } finally {
                btn.disabled = false;
                btn.style.opacity = "1";
                if (cancelBtn) cancelBtn.disabled = true;
            }
        }
    </script>
</body>
</html>
"""


def get_primary_ip() -> str:
    """Detects active primary LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def verify_port_available(host: str, port: int) -> Tuple[bool, str]:
    """Tests if host and port can be bound, or diagnoses the conflicting process."""
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        test_sock.bind((host, port))
        test_sock.close()
        return True, ""
    except OSError as e:
        test_sock.close()
        conflict_msg = f"Socket error: {e}"
        try:
            netstat = subprocess.check_output("netstat -ano -p tcp", shell=True, text=True)
            for line in netstat.splitlines():
                if f":{port} " in line and "LISTENING" in line:
                    tokens = line.split()
                    pid = tokens[-1]
                    try:
                        task = subprocess.check_output(f'tasklist /fi "PID eq {pid}" /fo csv /nh', shell=True, text=True).strip()
                        proc_name = task.split(",")[0].replace('"', '')
                        conflict_msg += f"\n  [!] Conflict Detected: Port {port} is occupied by '{proc_name}' (PID: {pid})."
                        conflict_msg += f"\n  [!] Fix: Run in PowerShell: Stop-Process -Id {pid} -Force"
                    except Exception:
                        conflict_msg += f"\n  [!] Conflict Detected: Port {port} is occupied by PID {pid}."
        except Exception:
            pass
        return False, conflict_msg


# ==============================================================================
# MAIN RUNNER
# ==============================================================================

if __name__ == "__main__":
    HOST = "0.0.0.0"
    PORT = int(os.environ.get("NETPROBEX_PORT", os.environ.get("DASHBOARD_PORT", 8765)))

    print("\n" + "=" * 80, flush=True)
    print("  ENTERPRISE NETWORK VULNERABILITY SCANNER — SERVER STARTUP", flush=True)
    print("=" * 80, flush=True)
    print(f"[*] Verifying socket availability on {HOST}:{PORT}...", flush=True)

    is_available, error_detail = verify_port_available(HOST, PORT)
    if not is_available:
        print("\n[CRITICAL ERROR] FAILED TO BIND TO PORT!", flush=True)
        print(f"  {error_detail}", flush=True)
        print("\n[TROUBLESHOOTING]", flush=True)
        print("  1. Another instance of the scanner or python server is already running.", flush=True)
        print("  2. To free the port, close existing Python windows or run:", flush=True)
        print("     powershell: Stop-Process -Name python -Force", flush=True)
        print("=" * 80 + "\n", flush=True)
        sys.exit(1)

    lan_ip = get_primary_ip()
    print("[SUCCESS] Socket verification passed. Port is completely free.", flush=True)
    print("\n" + "-" * 80, flush=True)
    print("  ACTIVE SERVER CONFIGURATION:", flush=True)
    print(f"  - Binding Host:      {HOST} (Listening on ALL network interfaces: IPv4, IPv6 localhost, and LAN)", flush=True)
    print(f"  - Listening Port:    {PORT}", flush=True)
    print(f"  - Localhost URL:     http://localhost:{PORT}", flush=True)
    print(f"  - IPv4 Loopback URL: http://127.0.0.1:{PORT}", flush=True)
    print(f"  - Network LAN URL:   http://{lan_ip}:{PORT}", flush=True)
    print("-" * 80, flush=True)
    print("  Server is starting up... Press Ctrl+C in this console to stop.", flush=True)
    print("=" * 80 + "\n", flush=True)

    if os.environ.get("HEADLESS", "0") != "1":
        import threading
        import webbrowser
        def _open_browser():
            time.sleep(1.2)
            try:
                webbrowser.open(f"http://localhost:{PORT}")
            except Exception:
                pass
        threading.Thread(target=_open_browser, daemon=True).start()

    try:
        # Binding to 0.0.0.0 enables access from localhost, 127.0.0.1, and LAN IP
        uvicorn.run(app, host=HOST, port=PORT, log_level="info")
    except Exception as exc:
        print("\n" + "!" * 80, flush=True)
        print("[FATAL SERVER ERROR] Uvicorn failed to start or terminated unexpectedly:", flush=True)
        print(f"  Error: {exc}", flush=True)
        import traceback
        traceback.print_exc()
        print("!" * 80 + "\n", flush=True)
        sys.exit(1)
