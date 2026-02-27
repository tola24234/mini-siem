def calculate_severity(failed_attempts):
    """
    SOC-style severity scoring logic
    """
    if failed_attempts >= 10:
        return "High", 90
    elif failed_attempts >= 5:
        return "Medium", 60
    else:
        return "Low", 30


def save_alert(alert):
    """
    Save alert to log file
    """
    with open("alerts/alerts.log", "a") as f:
        f.write(alert + "\n")
