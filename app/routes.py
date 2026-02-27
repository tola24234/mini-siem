from flask import Blueprint, render_template, jsonify
from app.models import Alert
from app.services.rule_engine import RuleEngine
from app.services.log_parser import parse_log_file
from app import db

# ⚠ Define Blueprint FIRST
main = Blueprint("main", __name__)

# Dashboard route
@main.route("/")
def dashboard():
    alerts = Alert.query.all()
    total_alerts = len(alerts)
    return render_template("dashboard.html", total_alerts=total_alerts, alerts=alerts)

# Analyze route
@main.route("/analyze")
def analyze():
    logs = parse_log_file("test_auth.log")  # test log
    engine = RuleEngine()
    alerts = engine.evaluate(logs)

    # Clear old alerts
    Alert.query.delete()
    db.session.commit()

    # Example MITRE mapping
    mitre_map = {
        "SSH Brute Force": {"mitre_id": "T1110", "mitre_tactic": "Initial Access"},
        "Failed Login": {"mitre_id": "T1110.001", "mitre_tactic": "Credential Access"},
        # Add more rules here
    }

    for alert in alerts:
        mitre = mitre_map.get(alert["rule"], {"mitre_id": "N/A", "mitre_tactic": "N/A"})
        new_alert = Alert(
            rule_name=alert["rule"],
            severity=alert["severity"],
            count=alert["count"],
            mitre_id=mitre["mitre_id"],
            mitre_tactic=mitre["mitre_tactic"]
        )
        db.session.add(new_alert)

    db.session.commit()
    return jsonify(alerts)
