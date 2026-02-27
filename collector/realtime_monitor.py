import os
import time

from engine.detection_rules import detect_bruteforce
from engine.soc_intelligence import soc_memory_engine
from engine.risk_scoring import calculate_risk_score
from alerts.alert_manager import save_alert


def monitor_logs():

    print("🔥 Mini SIEM Real-time Monitor Started")
    print("Monitoring system logs using journalctl...\n")

    try:
        process = os.popen("sudo journalctl -f")

        for line in process:

            # -------------------------
            # Clean log line
            # -------------------------
            line = line.strip()

            if not line:
                continue

            print("[EVENT]", line)

            # -----------------------------
            # Detection Engine
            # -----------------------------
            result = detect_bruteforce(line)

            if result:

                ip = result.get("source_ip", "UNKNOWN")

                # -----------------------------
                # SOC Memory Learning Engine
                # -----------------------------
                soc_memory_engine.add_event(
                    ip,
                    result.get("attack_type", "UNKNOWN")
                )

                anomaly_score = soc_memory_engine.anomaly_score(ip)

                # -----------------------------
                # Risk Scoring Engine
                # -----------------------------
                risk_data = calculate_risk_score(result)

                print("\n🚨 SECURITY ALERT DETECTED!")
                print("Attack Type :", result.get("attack_type"))
                print("Severity    :", risk_data.get("severity"))
                print("MITRE ID    :", result.get("mitre_id"))
                print("Source IP   :", ip)
                print("Risk Score  :", risk_data.get("risk_score"))
                print("Anomaly Score:", anomaly_score)
                print("------------------------------")

                # Save Alert
                result.update(risk_data)
                save_alert(result)

            time.sleep(0.1)

    except KeyboardInterrupt:
        print("Monitoring stopped")

    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    monitor_logs()
