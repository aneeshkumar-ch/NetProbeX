import subprocess
import sys
import os
import time

python_exe = sys.executable
dashboard_py = os.path.join(os.path.dirname(__file__), "dashboard.py")
log_file = os.path.join(os.path.dirname(__file__), "dashboard_runtime.log")

CREATE_NEW_PROCESS_GROUP = 0x00000200
DETACHED_PROCESS = 0x00000008

with open(log_file, "a") as f:
    p = subprocess.Popen(
        [python_exe, dashboard_py],
        cwd=os.path.dirname(__file__),
        stdin=subprocess.DEVNULL,
        stdout=f,
        stderr=subprocess.STDOUT,
        creationflags=CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
        close_fds=True
    )
    print(f"[+] Started independent PID: {p.pid}")

time.sleep(2)
