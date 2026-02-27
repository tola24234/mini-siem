from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(db.String)
    attack_type = db.Column(db.String)
    severity = db.Column(db.String)
    mitre_id = db.Column(db.String)
    event_log = db.Column(db.String)
