import os

import pytest

# These settings must exist before the dashboard module creates its database.
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"

from dashboard.app import app as flask_app
from models.alert_model import Alert, User, db


@pytest.fixture()
def app():
    flask_app.config.update(TESTING=True)

    with flask_app.app_context():
        db.drop_all()
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def user(app):
    account = User(username="analyst")
    account.set_password("correct-horse-battery-staple")
    db.session.add(account)
    db.session.commit()
    return account


@pytest.fixture()
def alert_factory(app):
    def create_alert(**overrides):
        values = {
            "timestamp": "2026-07-21 12:00:00",
            "source_ip": "192.0.2.1",
            "event_type": "SSH Brute Force",
            "severity": "HIGH",
            "description": "Repeated failed login",
            "attack_type": "SSH Brute Force",
            "mitre_id": "T1110",
            "country": "Ethiopia",
            "city": "Addis Ababa",
            "isp": "Example ISP",
        }
        values.update(overrides)
        alert = Alert(**values)
        db.session.add(alert)
        db.session.commit()
        return alert

    return create_alert


def login(client, username="analyst", password="correct-horse-battery-staple"):
    client.get("/login")
    with client.session_transaction() as session:
        csrf_token = session["csrf_token"]
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf_token},
    )
