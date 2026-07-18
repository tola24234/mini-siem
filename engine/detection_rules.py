import re
import time

# Store failed SSH attempts by IP
failed_attempts = {}

# Number of failures before alert
BRUTE_FORCE_THRESHOLD = 3

# Time window (seconds)
TIME_WINDOW = 60


def detect_bruteforce(log_line):

    # Only process failed login events
    if (
        "Failed password" not in log_line
        and "Invalid user" not in log_line
    ):
        return None

    # Extract IPv4 or IPv6 address
    ip_match = re.search(
        r'from ([0-9a-fA-F:\.]+)',
        log_line
    )

    if not ip_match:
        return None

    ip = ip_match.group(1)

    now = time.time()

    if ip not in failed_attempts:
        failed_attempts[ip] = []

    # Remove old attempts
    failed_attempts[ip] = [
        t for t in failed_attempts[ip]
        if now - t <= TIME_WINDOW
    ]

    failed_attempts[ip].append(now)

    count = len(failed_attempts[ip])

    print(f"[FAILED LOGIN] IP={ip} Attempts={count}")

    if count >= BRUTE_FORCE_THRESHOLD:

        failed_attempts[ip] = []

        return {
            "attack_type": "SSH Brute Force Attempt",
            "source_ip": ip,
            "severity": "HIGH",
            "mitre_id": "T1110",
            "description": f"Detected {count} failed SSH login attempts from {ip}"
        }

    return None
