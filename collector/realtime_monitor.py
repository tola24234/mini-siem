import time
import os

from engine.detection_rules import detect_bruteforce
from engine.soc_intelligence import soc_memory_engine
from engine.risk_scoring import calculate_risk_score

# Flask app context for database
from dashboard.app import app
from alerts.alert_manager import save_alert


def monitor_logs():

    print("🔥 Mini SIEM Real-time Monitor Started")
    print("Monitoring SSH logs using journalctl...\n")

    try:

        process = os.popen("journalctl -f -u ssh")


        for line in process:

            line = line.strip()

            if not line:
                continue


            print("[EVENT]", line)


            # Detection engine
            result = detect_bruteforce(line)


            if result:


                ip = result.get(
                    "source_ip",
                    "UNKNOWN"
                )


                # SOC Memory
                soc_memory_engine.add_event(
                    ip,
                    result.get(
                        "attack_type",
                        "UNKNOWN"
                    )
                )


                anomaly_score = soc_memory_engine.anomaly_score(ip)



                # Risk score
                risk_data = calculate_risk_score(result)



                print("\n🚨 SECURITY ALERT DETECTED")
                print("----------------------------")
                print(
                    "Attack Type :",
                    result.get("attack_type")
                )
                print(
                    "Severity    :",
                    risk_data.get("severity")
                )
                print(
                    "MITRE ID    :",
                    result.get("mitre_id")
                )
                print(
                    "Source IP   :",
                    ip
                )
                print(
                    "Risk Score  :",
                    risk_data.get("risk_score")
                )
                print(
                    "Anomaly     :",
                    anomaly_score
                )
                print("----------------------------")


                # Merge data
                result.update(risk_data)


                # Save into database safely
                with app.app_context():

                    save_alert(result)



            time.sleep(0.1)



    except KeyboardInterrupt:

        print(
            "\n[INFO] Real-time monitor stopped."
        )


    except Exception as e:

        print(
            "[ERROR]",
            e
        )



if __name__ == "__main__":

    monitor_logs()
