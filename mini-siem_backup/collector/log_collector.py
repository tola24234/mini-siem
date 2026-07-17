import os
import shutil

LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/secure"
]

OUTPUT_FILE = "data/auth_logs.txt"

def collect_logs():
    os.makedirs("data", exist_ok=True)

    for path in LOG_PATHS:
        if os.path.exists(path):
            shutil.copy(path, OUTPUT_FILE)
            print(f"[+] Logs collected from {path}")
            return

    print("[!] No authentication log found on this system")

if __name__ == "__main__":
    collect_logs()
