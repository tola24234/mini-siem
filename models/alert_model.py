from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """A dashboard user authenticated with a securely hashed password."""

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(db.String(50))
    source_ip = db.Column(db.String(50))
    event_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)

    attack_type = db.Column(db.String(100))
    mitre_id = db.Column(db.String(50))

    # -----------------------------
    # Threat Intelligence
    # -----------------------------
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    isp = db.Column(db.String(150))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
