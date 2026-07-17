import re
import time


# Store failed SSH attempts by IP
failed_attempts = {}

# Number of failures before alert
BRUTE_FORCE_THRESHOLD = 5

# Time window in seconds
TIME_WINDOW = 60


def detect_bruteforce(log_line):

    # Check SSH failure events
    if (
        "Failed password" not in log_line
        and
        "Invalid user" not in log_line
    ):
        return None


    # Extract IP address
    ip_match = re.search(
        r'from (\d+\.\d+\.\d+\.\d+)',
        log_line
    )

    if not ip_match:
        return None


    ip = ip_match.group(1)

    now = time.time()


    # Create IP tracking
    if ip not in failed_attempts:
        failed_attempts[ip] = []


    # Remove expired attempts
    failed_attempts[ip] = [
        timestamp
        for timestamp in failed_attempts[ip]
        if now - timestamp <= TIME_WINDOW
    ]


    # Add new failure
    failed_attempts[ip].append(now)


    count = len(failed_attempts[ip])


    print(
        f"[FAILED LOGIN] IP={ip} Attempts={count}"
    )


    # Trigger alert after threshold
    if count >= BRUTE_FORCE_THRESHOLD:

        # Reset after detection
        failed_attempts[ip] = []


        return {

            "attack_type":
                "SSH Brute Force Attempt",

            "source_ip":
                ip,

            "severity":
                "HIGH",

            "mitre_id":
                "T1110",

            "description":
                f"Detected {count} failed SSH login attempts from {ip}"

        }


    return None
