import re
from collections import defaultdict

LOG_FILE = "data/auth_logs.txt"
THRESHOLD = 5

def analyze_logs():
    failed_attempts = defaultdict(int)

    with open(LOG_FILE, "r", errors="ignore") as file:
        for line in file:
            if "Failed password" in line:
                ip = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
                if ip:
                    failed_attempts[ip[0]] += 1

    return failed_attempts

if __name__ == "__main__":
    results = analyze_logs()
    for ip, count in results.items():
        if count >= THRESHOLD:
            print(f"[!] Brute-force detected from {ip} ({count} attempts)")
