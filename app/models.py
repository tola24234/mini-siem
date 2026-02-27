from datetime import datetime
from app import db

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    count = db.Column(db.Integer, nullable=False)
    mitre_id = db.Column(db.String(50), default="N/A")
    mitre_tactic = db.Column(db.String(255), default="N/A")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # ✅ timestamp for each alert

    def __repr__(self):
        return f"<Alert {self.rule_name} | {self.severity} | {self.count}>"
