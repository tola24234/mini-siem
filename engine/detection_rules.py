import re

# ------------------------------
# Brute Force Detection Rule
# SOC Level Detection Logic
# ------------------------------

def detect_bruteforce(log_line):

    if not log_line:
        return None

    # Normalize log text
    line = log_line.lower()

    # Detect authentication failure patterns
    brute_patterns = [
        "failed password",
        "authentication failure",
        "invalid user",
        "pam_unix"
    ]

    if not any(pattern in line for pattern in brute_patterns):
        return None

    # Extract Source IP (IPv4 + IPv6 support)
    ip_match = re.search(
        r'from\s+([\d\.]+|[0-9a-fA-F:]+)',
        log_line
    )

    source_ip = ip_match.group(1) if ip_match else "UNKNOWN"

    # SOC Intelligence Result Structure
    return {
        "attack_type": "SSH Brute Force Attempt",
        "severity": "MEDIUM",
        "mitre_id": "T1110",
        "source_ip": source_ip
    }
