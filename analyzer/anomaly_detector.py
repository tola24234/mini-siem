import re

FAILED_THRESHOLD = 8

def detect_anomaly(log_file):

    failed_attempts = {}

    alerts = []

    with open(log_file, "r") as f:
        logs = f.readlines()

    for line in logs:

        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)

        if match:
            ip = match.group(1)

            if "Failed password" in line:
                failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

                if failed_attempts[ip] > FAILED_THRESHOLD:
                    alerts.append(
                        f"[ANOMALY ALERT] Possible brute-force pattern from {ip}"
                    )

    return alerts
