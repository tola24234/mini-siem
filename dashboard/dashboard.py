from analyzer.log_analyzer import analyze_logs
from alerts.alert_manager import send_alert

THRESHOLD = 5

def show_dashboard():
    print("=== MINI SIEM DASHBOARD ===")
    results = analyze_logs()

    for ip, count in results.items():
        print(f"{ip} -> {count} failed attempts")
        if count >= THRESHOLD:
            send_alert(ip, count)
            print("  🚨 ALERT GENERATED")

if __name__ == "__main__":
    show_dashboard()
