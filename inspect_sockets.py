import socket
import time
import subprocess

def get_listening_processes():
    """Maps listening TCP ports to their Windows Process Name and PID."""
    port_to_proc = {}
    try:
        out = subprocess.check_output("netstat -ano -p tcp", shell=True, text=True)
        pid_to_name = {4: "System (Windows Kernel)"}
        
        task_out = subprocess.check_output("tasklist /fo csv /nh", shell=True, text=True)
        for line in task_out.strip().splitlines():
            parts = [p.strip(' "') for p in line.split('","')]
            if len(parts) >= 2:
                try:
                    pid_to_name[int(parts[1])] = parts[0]
                except ValueError:
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

def run_detailed_socket_inspection():
    ports_to_test = [
        21,   # FTP (Closed)
        22,   # SSH (Closed)
        80,   # HTTP (Closed)
        135,  # RPC (Open - svchost.exe)
        139,  # NetBIOS (Closed on 127.0.0.1, open on LAN)
        443,  # HTTPS (Closed)
        445,  # SMB (Open - System Kernel)
        623,  # Intel AMT/LMS (Open - LMS.exe)
        3306, # MySQL (Closed)
        3389, # RDP (Closed)
        5357, # WSDAPI (Open - System)
        5432, # Postgres Default (Closed)
        5433, # Postgres Traefik (Open - traefik.exe)
        5434, # Postgres Traefik (Open - traefik.exe)
        6432, # PgBouncer (Open - pgbouncer.exe)
        7680, # Delivery Optimization (Open - svchost.exe)
        8080  # Web Proxy (Closed)
    ]

    proc_map = get_listening_processes()

    print("\n" + "=" * 105)
    print(f"{'PORT':<6} {'STATUS':<8} {'WINSOCK RETURN CODE & DESCRIPTION':<40} {'LATENCY':<10} {'WINDOWS PROCESS':<24} {'PID':<6}")
    print("=" * 105)

    for port in ports_to_test:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        start = time.perf_counter()
        
        try:
            # Connect with short timeout
            s.settimeout(0.3)
            s.connect(("127.0.0.1", port))
            latency = (time.perf_counter() - start) * 1000
            status = "OPEN"
            code_desc = "0 (SUCCESS: SYN-ACK received)"
        except OSError as e:
            latency = (time.perf_counter() - start) * 1000
            status = "CLOSED"
            if e.errno == 10061:
                code_desc = "10061 (WSAECONNREFUSED: RST received)"
            elif e.errno == 10060 or "timed out" in str(e):
                code_desc = "10060 (WSAETIMEDOUT: Filtered/No reply)"
            else:
                code_desc = f"{e.errno} ({e.strerror[:30]})"
        finally:
            s.close()

        proc_info = proc_map.get(port, {"name": "---", "pid": "---"})
        p_name = proc_info["name"]
        p_id = str(proc_info["pid"])

        print(f"{port:<6} {status:<8} {code_desc:<40} {latency:>6.2f} ms   {p_name:<24} {p_id:<6}")

    print("=" * 105 + "\n")

if __name__ == "__main__":
    run_detailed_socket_inspection()
