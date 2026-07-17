ALERT_FILE = "data/alerts.log"
BLOCK_FILE = "data/blocked_ips.txt"

def write_alert(ip, count, mitre):
    with open(ALERT_FILE, "a") as f:
        f.write(f"{ip} failed {count} times - MITRE {mitre['technique_id']}\n")
    print(f"Alert written for {ip}")

def block_ip(ip):
    with open(BLOCK_FILE, "a") as f:
        f.write(f"{ip}\n")
    print(f"IP {ip} blocked (simulated)")
