from alert_manager import calculate_severity

def detect_bruteforce(log_line):

    failed_attempts = 0

    if "Failed password" in log_line:
        failed_attempts += 1

        severity, risk = calculate_severity(failed_attempts)

        print(f"[ALERT] SSH Attack Detected | Severity={severity} Risk={risk}")
