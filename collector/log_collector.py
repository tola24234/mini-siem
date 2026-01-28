import shutil
import os
from datetime import datetime

LOG_SOURCE = "/var/log/auth.log"
DEST_FILE = "data/auth_logs.txt"

def collect_logs():
    os.makedirs("data", exist_ok=True)

    if not os.path.exists(LOG_SOURCE):
        print("[!] auth.log not found")
        return

    with open(DEST_FILE, "a") as f:
        f.write(f"\n--- Logs collected at {datetime.now()} ---\n")

    shutil.copy(LOG_SOURCE, DEST_FILE)
    print("[+] Logs collected successfully")

if __name__ == "__main__":
    collect_logs()
