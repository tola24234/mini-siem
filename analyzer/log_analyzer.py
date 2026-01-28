from collections import defaultdict
from analyzer.mitre_mapping import MITRE_ATTACK

LOG_FILE = "data/auth_logs.txt"
THRESHOLD = 5

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
            results[ip] = {
                "count": count,
                "mitre": MITRE_ATTACK["SSH_BRUTE_FORCE"]
            }

    return results
