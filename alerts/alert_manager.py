import os

ALERT_FILE = "alerts/alerts.log"

def save_alert(alert_data):
    """
    Save detection alert to log storage
    """

    try:
        os.makedirs("alerts", exist_ok=True)

        attack_type = alert_data.get("attack_type", "UNKNOWN")
        severity = alert_data.get("severity", "LOW")
        mitre_id = alert_data.get("mitre_id", "N/A")
        source_ip = alert_data.get("source_ip", "UNKNOWN")

        with open(ALERT_FILE, "a") as f:
            f.write(
                f"{attack_type} | "
                f"{severity} | "
                f"{mitre_id} | "
                f"{source_ip}\n"
            )

    except Exception as e:
        print("Alert saving error:", e)
