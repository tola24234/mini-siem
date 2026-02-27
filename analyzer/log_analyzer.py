from collections import defaultdict
import re
from configparser import ConfigParser

# Optional: import only if needed inside the function
try:
    from analyzer.mitre_mapping import MITRE_ATTACK
except ImportError:
    MITRE_ATTACK = {
        "SSH_BRUTE_FORCE": {
            "tactic": "Credential Access",
            "technique": "Brute Force",
            "sub_technique": "T1110.001 - Password Guessing"
        }
    }

# These can be imported here or passed as parameters
from alerts.alert_manager import write_alert, block_ip

def analyze_logs(log_file_path=None, threshold=None):
    """
    Analyze authentication logs for brute-force attempts.
    
    Args:
        log_file_path (str): Path to the log file (default from config)
        threshold (int): Minimum failed attempts to trigger alert (default from config)
    
    Returns:
        list: List of dicts with detected suspicious IPs
              Each dict: {'ip': str, 'count': int, 'tactic': str, 'technique': str, 'sub_technique': str}
    """
    # Load config if parameters not provided
    config = ConfigParser()
    config.read("config.ini")  # or use absolute path if needed

    if log_file_path is None:
        log_file_path = config.get("SIEM", "LOG_FILE", fallback="data/auth_logs.txt")

    if threshold is None:
        threshold = config.getint("SIEM", "THRESHOLD", fallback=5)

    failed_attempts = defaultdict(int)
    ip_pattern = re.compile(r'from\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})')

    try:
        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue

                # Look for common failed SSH login indicators
                if any(keyword in line for keyword in ["Failed password", "authentication failure", "invalid user"]):
                    match = ip_pattern.search(line)
                    if match:
                        ip = match.group(1)
                        failed_attempts[ip] += 1

    except FileNotFoundError:
        print(f"Error: Log file not found: {log_file_path}")
        return []
    except Exception as e:
        print(f"Error reading log file: {e}")
        return []

    # Prepare results
    results = []

    for ip, count in failed_attempts.items():
        if count >= threshold:
            mitre = MITRE_ATTACK.get("SSH_BRUTE_FORCE", {
                "tactic": "Credential Access",
                "technique": "Brute Force",
                "sub_technique": "T1110.001 - Password Guessing"
            })

            entry = {
                "ip": ip,
                "count": count,
                "tactic": mitre["tactic"],
                "technique": mitre["technique"],
                "sub_technique": mitre["sub_technique"]
            }

            results.append(entry)

            # Generate alert & simulate block
            try:
                write_alert(ip, count, mitre["tactic"], mitre["sub_technique"])
                block_ip(ip)
            except Exception as alert_err:
                print(f"Alert/block failed for {ip}: {alert_err}")

    return results
