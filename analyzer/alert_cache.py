import time
import yaml

from dashboard.app import app

from analyzer.bruteforce_detector import detect_bruteforce
from analyzer.correlation_engine import correlate_events
from analyzer.anomaly_detector import detect_anomaly
from analyzer.alert_cache import is_duplicate

from firewall_block import block_ip
from alerts.alert_manager import save_alert


# Load configuration
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)


LOG_FILES = config.get(
    "log_sources",
    ["logs/remote_logs.log"]
)


def run_detection_loop():

    print("[INFO] Mini-SIEM Real-Time Detection Engine Started")


    while True:

        try:

            malicious_ips = []


            for log_file in LOG_FILES:

                print(
                    f"[INFO] Scanning {log_file}"
                )


                # =========================
                # Brute Force Detection
                # =========================

                alerts = detect_bruteforce(log_file)


                for alert in alerts:

                    print(alert)


                    if "Brute force" in alert:

                        ip = alert.split()[-1]


                        # Prevent duplicate alerts
                        if is_duplicate(ip):

                            continue


                        malicious_ips.append(ip)


                        # Save alert into database

                        with app.app_context():

                            save_alert({

                                "attack_type":
                                "SSH Brute Force",

                                "severity":
                                "HIGH",

                                "mitre_id":
                                "T1110",

                                "source_ip":
                                ip,

                                "description":
                                "Multiple failed SSH login attempts detected"

                            })



                # =========================
                # Event Correlation
                # =========================

                chain_alerts = correlate_events(
                    log_file
                )


                for alert in chain_alerts:

                    print(alert)



                # =========================
                # Anomaly Detection
                # =========================

                anomaly_alerts = detect_anomaly(
                    log_file
                )


                for alert in anomaly_alerts:

                    print(alert)



            # =========================
            # Firewall Blocking
            # =========================

            for ip in set(malicious_ips):

                print(
                    f"[INFO] Blocking {ip}"
                )

                block_ip(ip)



            # Check every 2 seconds

            time.sleep(2)



        except KeyboardInterrupt:

            print(
                "\n[INFO] Detection engine stopped."
            )

            break



        except Exception as e:

            print(
                f"[ERROR] {e}"
            )

            time.sleep(2)



if __name__ == "__main__":

    run_detection_loop()

