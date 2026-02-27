from flask import Flask, jsonify
from models.alert_model import db, Alert

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///alerts.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    db.create_all()


@app.route("/")
def home():
    return "Mini SIEM Dashboard Running 🔥"


@app.route("/api/alerts")
def get_alerts():
    alerts = Alert.query.order_by(Alert.id.desc()).limit(50).all()

    return jsonify([
        {
            "timestamp": a.timestamp,
            "attack": a.attack_type,
            "severity": a.severity,
            "mitre": a.mitre_id
        }
        for a in alerts
    ])


if __name__ == "__main__":
    app.run(debug=True)
