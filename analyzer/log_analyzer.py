from collections import defaultdict
import re
import os
from configparser import ConfigParser

# MITRE fallback
MITRE_ATTACK = {
    "SSH_BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "sub_technique": "T1110.001 - Password Guessing"
    }
}

# Alert functions
try:
    from alerts.alert_manager import write_alert, block_ip
except ImportError:
    def write_alert(ip, count, tactic, sub_technique):
        print(f"[ALERT] {ip} ({count} attempts) → {sub_technique}")
    def block_ip(ip):
        print(f"[BLOCK] Simulated block for {ip}")

def analyze_logs(log_file_path=None, threshold=None):
    """
    Analyze logs - works on local + Render.com Docker
    """
    config = ConfigParser()
    config.read("config.ini")

    # Force correct path for Render (WORKDIR=/app)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_log = "/app/data/auth_logs.txt"   # ← THIS IS THE KEY FIX

    if log_file_path is None:
        log_file_path = config.get("SIEM", "LOG_FILE", fallback=default_log)

    print(f"[DEBUG] Attempting to read: {log_file_path}")

    if threshold is None:
        threshold = config.getint("SIEM", "THRESHOLD", fallback=5)

    failed_attempts = defaultdict(int)
    ip_pattern = re.compile(r'from\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})')

    try:
        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                line = line.strip()
                if "Failed password" in line:
                    match = ip_pattern.search(line)
                    if match:
                        ip = match.group(1)
                        failed_attempts[ip] += 1
                        print(f"[DEBUG] Found attempt from {ip}")
    except Exception as e:
        print(f"Error reading log: {e}")
        return []

    # Build results
    results = []
    for ip, count in failed_attempts.items():
        if count >= threshold:
            mitre = MITRE_ATTACK["SSH_BRUTE_FORCE"]
            results.append({
                "ip": ip,
                "count": count,
                "tactic": mitre["tactic"],
                "technique": mitre["technique"],
                "sub_technique": mitre["sub_technique"]
            })
            write_alert(ip, count, mitre["tactic"], mitre["sub_technique"])
            block_ip(ip)

    print(f"[DEBUG] Detected {len(results)} suspicious IPs")
    return results
