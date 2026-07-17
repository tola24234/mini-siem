from datetime import datetime
from models.alert_model import db, Alert


def save_alert(alert_data):
    """
    Save SIEM alert into database
    """

    try:

        alert = Alert(

            timestamp=str(datetime.now()),

            source_ip=alert_data.get(
                "source_ip",
                "UNKNOWN"
            ),

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
            )
        )


        db.session.add(alert)

        db.session.commit()


        print(
            "[+] Alert saved to database"
        )


    except Exception as e:

        db.session.rollback()

        print(
            "Alert database error:",
            e
        )
