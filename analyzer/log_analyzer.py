from collections import defaultdict
import re
import os
from configparser import ConfigParser

# MITRE ATT&CK mapping fallback
MITRE_ATTACK = {
    "SSH_BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "sub_technique": "T1110.001 - Password Guessing"
    }
}

# Alert functions with simulation fallback
try:
    from alerts.alert_manager import write_alert, block_ip
except ImportError:
    def write_alert(ip, count, tactic, sub_technique):
        timestamp = os.popen('date +"%Y-%m-%d %H:%M:%S"').read().strip()
        print(f"[{timestamp}] [ALERT SIM] {ip} ({count} attempts) → {sub_technique}")
    def block_ip(ip):
        print(f"[BLOCK SIM] Simulated firewall block for {ip}")

def analyze_logs(log_file_path=None, threshold=None):
    """
    Analyze authentication logs for brute-force SSH attacks.
    Works both locally and on Render.com (Docker).
    """
    config = ConfigParser()
    config.read("config.ini")

    # Determine base path: /app on Render, project root locally
    if os.getenv("RENDER"):  # Render sets this env var
        base_dir = "/app"
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    default_log = os.path.join(base_dir, "data", "auth_logs.txt")

    if log_file_path is None:
        log_file_path = config.get("SIEM", "LOG_FILE", fallback=default_log)

    print(f"[DEBUG] Attempting to read log file: {log_file_path}")

    if threshold is None:
        threshold = config.getint("SIEM", "THRESHOLD", fallback=3)  # lowered for easier testing

    failed_attempts = defaultdict(int)
    # Improved regex: matches common auth.log format like:
    # ... sshd[...]: Failed password for invalid user abc from 1.2.3.4 port 12345 ssh2
    ip_pattern = re.compile(r'from\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b')

    line_count = 0
    failed_count = 0
    matched_count = 0
    sample_failed_lines = []

    try:
        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                line = line.strip()
                line_count += 1
                if not line:
                    continue
                if "Failed password" in line:
                    failed_count += 1
                    # Keep first few samples for debug
                    if len(sample_failed_lines) < 5:
                        sample_failed_lines.append(line[:180] + ("..." if len(line) > 180 else ""))

                    match = ip_pattern.search(line)
                    if match:
                        ip = match.group(1)
                        failed_attempts[ip] += 1
                        matched_count += 1
                        print(f"[DEBUG] Found failed attempt from {ip} | Line excerpt: {line[:80]}...")
                    else:
                        print(f"[DEBUG] 'Failed password' found but NO IP match: {line[:80]}...")

    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {log_file_path}")
        return []
    except Exception as e:
        print(f"[ERROR] Reading log file failed: {type(e).__name__}: {e}")
        return []

    # Debug summary
    print(f"[DEBUG] Total lines read: {line_count}")
    print(f"[DEBUG] Lines containing 'Failed password': {failed_count}")
    print(f"[DEBUG] Lines with matched IP: {matched_count}")
    if sample_failed_lines:
        print("[DEBUG] Sample 'Failed password' lines (first 5):")
        for sample in sample_failed_lines:
            print(f"  → {sample}")

    # Build results list for dashboard
    results = []
    for ip, count in failed_attempts.items():
        if count >= threshold:
            mitre = MITRE_ATTACK["SSH_BRUTE_FORCE"]
            entry = {
                "ip": ip,
                "count": count,
                "tactic": mitre["tactic"],
                "technique": mitre["technique"],
                "sub_technique": mitre["sub_technique"]
            }
            results.append(entry)

            # Trigger alert and block
            write_alert(ip, count, mitre["tactic"], mitre["sub_technique"])
            block_ip(ip)

    print(f"[DEBUG] Detected {len(results)} suspicious IPs (threshold ≥ {threshold})")
    # ────────────────────────────────────────────────
    # TEMP: FORCE VISIBLE DETECTION TO CONFIRM DASHBOARD WORKS
    # Remove or comment out after testing
    force_test = True  # ← set to False later to disable
    if force_test:
        test_ip = "203.0.113.197"  # example IP (TEST-NET-3, safe)
        test_count = 12
        mitre = MITRE_ATTACK["SSH_BRUTE_FORCE"]
        entry = {
            "ip": test_ip,
            "count": test_count,
            "tactic": mitre["tactic"],
            "technique": mitre["technique"],
            "sub_technique": mitre["sub_technique"]
        }
        results.append(entry)
        write_alert(test_ip, test_count, mitre["tactic"], mitre["sub_technique"])
        block_ip(test_ip)
        print(f"[DEBUG] FORCE TEST ADDED: {test_ip} with {test_count} attempts")
    # ────────────────────────────────────────────────
    return results
