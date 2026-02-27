import os
import re

def block_ip(ip):
    """
    Block IP using iptables (Linux)
    """
    cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
    os.system(cmd)
    print(f"[!] Blocked IP: {ip}")

def extract_ips_from_alerts(alert_file):
    ips = set()
    with open(alert_file, "r") as f:
        for line in f:
            match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
            if match:
                ips.add(match.group(0))
    return ips

if __name__ == "__main__":
    ips = extract_ips_from_alerts("../alerts/alerts.log")
    for ip in ips:
        block_ip(ip)
