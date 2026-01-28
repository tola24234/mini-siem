from collections import defaultdict
from configparser import ConfigParser
from analyzer.mitre_mapping import MITRE_ATTACK
from alerts.alert_manager import write_alert, block_ip

# Load configuration
config = ConfigParser()
config.read("config.ini")

LOG_FILE = config.get("SIEM", "LOG_FILE")
THRESHOLD = config.getint("SIEM", "THRESHOLD")

def analyze_logs():
    failed_attempts = defaultdict(int)

    with open(LOG_FILE, "r", errors="ignore") as file:
        for line in file:
            if "Failed password" in line:
                ip = line.split("from")[1].split()[0]
                failed_attempts[ip] += 1

    results = {}

    for ip, count in failed_attempts.items():
        if count >= THRESHOLD:
            mitre = MITRE_ATTACK["SSH_BRUTE_FORCE"]
            results[ip] = {
                "count": count,
                "mitre": mitre
            }

            # Alert + block simulation
            write_alert(ip, count, mitre)
            block_ip(ip)

    return results
