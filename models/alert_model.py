from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(db.String(50))
    source_ip = db.Column(db.String(50))
    event_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    attack_type = db.Column(db.String(100))
    mitre_id = db.Column(db.String(50))
