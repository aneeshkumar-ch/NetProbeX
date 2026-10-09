import subprocess
import sys
import os
import time

python_exe = sys.executable
dashboard_py = os.path.join(os.path.dirname(__file__), "dashboard.py")
log_file = os.path.join(os.path.dirname(__file__), "dashboard_runtime.log")

CREATE_NEW_CONSOLE = 0x00000010

p = subprocess.Popen(
    [python_exe, dashboard_py],
    cwd=os.path.dirname(__file__),
    creationflags=CREATE_NEW_CONSOLE
)
print(f"[+] Started independent PID: {p.pid}")
