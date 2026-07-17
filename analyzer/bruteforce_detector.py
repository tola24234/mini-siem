import re
from collections import defaultdict


FAILED_THRESHOLD = 5

seen_alerts = set()


def detect_bruteforce(log_file):

    alerts = []
    attempts = defaultdict(int)


    try:

        with open(log_file, "r", errors="ignore") as f:

            for line in f:

                if "Failed password" in line:

                    match = re.search(
                        r"from (\d+\.\d+\.\d+\.\d+)",
                        line
                    )


                    if match:

                        ip = match.group(1)

                        attempts[ip] += 1


                        if attempts[ip] >= FAILED_THRESHOLD:


                            alert_id = f"bruteforce-{ip}"


                            if alert_id not in seen_alerts:

                                alerts.append(
                                    f"[ALERT] Brute force attack detected from {ip}"
                                )

                                seen_alerts.add(alert_id)



    except FileNotFoundError:
        pass


    return alerts
