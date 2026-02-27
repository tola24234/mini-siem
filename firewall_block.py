import os
import re
import subprocess

def block_ip(ip):
    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )

        print(f"[🔥] Firewall blocked IP → {ip}")

    except Exception as e:
        print("Firewall error:", e)


def extract_ips_from_alerts(alert_file):

    ips = set()

    try:
        with open(alert_file, "r") as f:
            for line in f:

                match = re.search(
                    r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                    line
                )

                if match:
                    ips.add(match.group(0))

    except FileNotFoundError:
        print("Alert file not found")

    return ips


if __name__ == "__main__":

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    alert_file = os.path.join(BASE_DIR, "alerts", "alerts.log")

    print("Scanning alerts...")

    ips = extract_ips_from_alerts(alert_file)

    if not ips:
        print("No IPs found in alerts")

    for ip in ips:
        block_ip(ip)
