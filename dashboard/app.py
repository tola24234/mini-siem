# ============================================
# Mini-SIEM Dashboard Application
# ============================================

import os
from flask import Flask, jsonify, render_template
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

# Initialize Database
db.init_app(app)

with app.app_context():
    db.create_all()


# --------------------------------------------
# Home Dashboard Route
# --------------------------------------------

@app.route("/")
def dashboard():

    alerts = Alert.query.order_by(Alert.id.desc()).limit(100).all()

    high_count = Alert.query.filter_by(severity="HIGH").count()
    medium_count = Alert.query.filter_by(severity="MEDIUM").count()
    low_count = Alert.query.filter_by(severity="LOW").count()
    total_count = Alert.query.count()

    return render_template(
        "dashboard.html",
        alerts=alerts,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        total_count=total_count
    )


# --------------------------------------------
# API Endpoint (JSON Alerts)
# --------------------------------------------

@app.route("/api/alerts")
def get_alerts():

    alerts = Alert.query.order_by(Alert.id.desc()).limit(50).all()

    return jsonify([
        {
            "id": a.id,
            "timestamp": str(a.timestamp),
            "source_ip": a.source_ip,
            "event_type": a.event_type,
            "severity": a.severity,
            "description": a.description,
        }
        for a in alerts
    ])


# --------------------------------------------
# Run Application
# --------------------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5001,
        debug=True
    )
