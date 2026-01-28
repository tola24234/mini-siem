from datetime import datetime

ALERT_FILE = "data/alerts.log"

def send_alert(ip, count):
    with open(ALERT_FILE, "a") as f:
        f.write(f"{datetime.now()} ALERT: {ip} failed {count} times\n")
