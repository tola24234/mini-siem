import time
from analyzer.bruteforce_detector import detect_bruteforce
from analyzer.correlation_engine import correlate_events
from dashboard.firewall_block import block_ip
from analyzer.anomaly_detector import detect_anomaly
import yaml

# Load configuration
with open("config.yaml") as f:
    config = yaml.safe_load(f)

LOG_FILES = config.get("log_sources", ["logs/remote_logs.log"])

def run_detection_loop():

    print("[INFO] Mini-SIEM Real-Time Detection Engine Started")

    while True:
        try:
            malicious_ips = []

            for log_file in LOG_FILES:

                # Brute force detection
                alerts = detect_bruteforce(log_file)

                for alert in alerts:
                    if "Brute force" in alert:
                        ip = alert.split()[-1]
                        malicious_ips.append(ip)

                # Event correlation detection
                chain_alerts = correlate_events(log_file)

                for alert in chain_alerts:
                    print(alert)

                # Elite anomaly detection layer
                anomaly_alerts = detect_anomaly(log_file)

                for alert in anomaly_alerts:
                    print(alert)

            # Automatic IP blocking
            for ip in set(malicious_ips):
                block_ip(ip)

            # SOC-grade loop delay
            time.sleep(2)

        except KeyboardInterrupt:
            print("\n[INFO] Detection engine stopped safely")
            break

        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(2)

if __name__ == "__main__":
    run_detection_loop()
