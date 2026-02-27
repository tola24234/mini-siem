from datetime import datetime

def write_alert(ip: str, count: int, tactic: str = "Credential Access", technique: str = "T1110.001 - Password Guessing"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{timestamp}] ALERT: Potential brute-force from {ip} ({count} attempts) → {technique}"
    print(msg)
    with open("alerts.log", "a") as f:
        f.write(msg + "\n")

def block_ip(ip: str):
    print(f"[BLOCK] Simulated block for IP: {ip}")
    with open("blocked_ips.txt", "a") as f:
        f.write(f"{ip}\n")
