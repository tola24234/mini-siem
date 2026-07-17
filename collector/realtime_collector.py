import subprocess
import time

from engine.detection_rules import detect_bruteforce
from engine.soc_intelligence import soc_memory_engine
from engine.risk_scoring import calculate_risk_score
from alerts.alert_manager import save_alert


def monitor_logs():

    print("🔥 Mini-SIEM Real-Time Monitor Started")
    print("Monitoring SSH logs...\n")


    process = subprocess.Popen(
        ["sudo", "journalctl", "-f", "-u", "ssh"],
        stdout=subprocess.PIPE,
        text=True
    )


    try:

        for line in process.stdout:

            line = line.strip()


            if not line:
                continue


            print("[EVENT]", line)


            result = detect_bruteforce(line)


            if result:


                ip = result.get(
                    "source_ip",
                    "UNKNOWN"
                )


                soc_memory_engine.add_event(
                    ip,
                    result.get(
                        "attack_type",
                        "UNKNOWN"
                    )
                )


                anomaly_score = (
                    soc_memory_engine.anomaly_score(ip)
                )


                risk = calculate_risk_score(result)


                result.update(risk)


                result["description"] = (
                    "Multiple failed SSH login attempts detected"
                )


                print("\n🚨 SECURITY ALERT")
                print("---------------------")
                print("Attack :", result.get("attack_type"))
                print("IP     :", ip)
                print("Risk   :", risk.get("risk_score"))
                print("Level  :", risk.get("severity"))
                print("---------------------")


                save_alert(result)


            time.sleep(0.1)



    except KeyboardInterrupt:

        print("\n[INFO] Monitor stopped")


if __name__ == "__main__":
    monitor_logs()
