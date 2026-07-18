from datetime import datetime

from models.alert_model import db, Alert
from utils.geolocation import get_ip_info


def save_alert(alert_data):
    """
    Save SIEM alert into database with threat intelligence.
    """

    try:

        source_ip = alert_data.get("source_ip", "UNKNOWN")

        # Lookup geolocation
        geo = get_ip_info(source_ip)

        alert = Alert(

            timestamp=str(datetime.now()),

            source_ip=source_ip,

            event_type=alert_data.get(
                "attack_type",
                "UNKNOWN"
            ),

            severity=alert_data.get(
                "severity",
                "LOW"
            ),

            description=alert_data.get(
                "description",
                "Security event detected"
            ),

            attack_type=alert_data.get(
                "attack_type",
                "UNKNOWN"
            ),

            mitre_id=alert_data.get(
                "mitre_id",
                "N/A"
            ),

            country=geo["country"],
            city=geo["city"],
            isp=geo["isp"],
            latitude=geo["latitude"],
            longitude=geo["longitude"]

        )

        db.session.add(alert)
        db.session.commit()

        print("[+] Alert saved to database")

    except Exception as e:

        db.session.rollback()

        print("Alert database error:", e)
