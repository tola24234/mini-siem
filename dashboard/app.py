# ============================================
# Mini-SIEM Dashboard Application
# ============================================

import os

from flask import Flask, jsonify, render_template, request
from sqlalchemy import func

from config import Config
from models.alert_model import db, Alert

# --------------------------------------------
# Initialize Flask App
# --------------------------------------------

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates")
)

app.config.from_object(Config)

db.init_app(app)

with app.app_context():
    db.create_all()


# --------------------------------------------
# Home Dashboard Route
# --------------------------------------------

@app.route("/")
def dashboard():

    alerts = Alert.query.order_by(Alert.id.desc()).limit(100).all()

    return render_template(
        "dashboard.html",
        alerts=alerts,
        high_count=Alert.query.filter_by(severity="HIGH").count(),
        medium_count=Alert.query.filter_by(severity="MEDIUM").count(),
        low_count=Alert.query.filter_by(severity="LOW").count(),
        total_count=Alert.query.count()
    )


# --------------------------------------------
# Alerts JSON API
# --------------------------------------------

@app.route("/api/alerts")
def api_alerts():

    alerts = Alert.query.order_by(Alert.id.desc()).limit(100).all()

    return jsonify({

        "high": Alert.query.filter_by(severity="HIGH").count(),
        "medium": Alert.query.filter_by(severity="MEDIUM").count(),
        "low": Alert.query.filter_by(severity="LOW").count(),
        "total": Alert.query.count(),

        "alerts": [

            {

                "id": alert.id,
                "timestamp": alert.timestamp,

                "source_ip": alert.source_ip,

                "country": alert.country,
                "city": alert.city,
                "isp": alert.isp,

                "event_type": alert.event_type,
                "severity": alert.severity,
                "description": alert.description,

                "attack_type": alert.attack_type,
                "mitre_id": alert.mitre_id,

                "latitude": alert.latitude,
                "longitude": alert.longitude

            }

            for alert in alerts

        ]

    })


# --------------------------------------------
# Dashboard Statistics API
# --------------------------------------------

@app.route("/api/stats")
def api_stats():

    top_ips = (
        db.session.query(
            Alert.source_ip,
            func.count(Alert.id).label("count")
        )
        .group_by(Alert.source_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
        .all()
    )

    return jsonify({

        "severity": {

            "HIGH": Alert.query.filter_by(severity="HIGH").count(),
            "MEDIUM": Alert.query.filter_by(severity="MEDIUM").count(),
            "LOW": Alert.query.filter_by(severity="LOW").count()

        },

        "top_ips": [

            {
                "ip": ip,
                "count": count
            }

            for ip, count in top_ips

        ]

    })


# --------------------------------------------
# Alert Ingestion API
# --------------------------------------------

@app.route("/api/ingest", methods=["POST"])
def ingest_alert():

    data = request.get_json()

    if not data:
        return jsonify({
            "status": "error",
            "message": "No JSON received"
        }), 400

    alert = Alert(

        timestamp=data.get("timestamp"),

        source_ip=data.get("source_ip"),

        country=data.get("country"),

        city=data.get("city"),

        isp=data.get("isp"),

        latitude=data.get("latitude"),

        longitude=data.get("longitude"),

        event_type=data.get("event_type"),

        severity=data.get("severity"),

        description=data.get("description"),

        attack_type=data.get("attack_type"),

        mitre_id=data.get("mitre_id")

    )

    db.session.add(alert)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Alert received successfully"
    })


# --------------------------------------------
# Run Application
# --------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5001,
        debug=True
    )
