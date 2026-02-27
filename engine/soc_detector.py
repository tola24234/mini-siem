import re
from collections import defaultdict
import time

# Store failed attempts per IP
failed_attempts = defaultdict(list)

# Threshold
ATTEMPT_THRESHOLD = 5
TIME_WINDOW = 60  # seconds


def detect_bruteforce(log_line):
    if "Failed password" not in log_line:
        return None

    # Extract IP address
    match = re.search(r'from (\S+)', log_line)
    if not match:
        return None

    ip = match.group(1)
    current_time = time.time()

    # Store timestamp
    failed_attempts[ip].append(current_time)

    # Remove old attempts outside time window
    failed_attempts[ip] = [
        t for t in failed_attempts[ip]
        if current_time - t <= TIME_WINDOW
    ]

    # Check threshold
    if len(failed_attempts[ip]) >= ATTEMPT_THRESHOLD:
        return {
            "type": "SSH Brute Force",
            "ip": ip,
            "attempts": len(failed_attempts[ip]),
            "severity": "HIGH",
            "mitre_technique": "T1110.001"
        }

    return None
if __name__ == "__main__":
    print("SOC Detector Module Running")
