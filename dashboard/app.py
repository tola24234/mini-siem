# ============================================
# Mini-SIEM Dashboard Application
# ============================================

import os
import secrets
from urllib.parse import urljoin, urlparse

import click
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from sqlalchemy import func, or_

from config import Config
from models.alert_model import db, Alert, User

# --------------------------------------------
# Initialize Flask App
# --------------------------------------------

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates")
)

app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def _csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def _validate_csrf_token():
    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("csrf_token")
    if not expected_token or not submitted_token or not secrets.compare_digest(expected_token, submitted_token):
        abort(400, "Invalid CSRF token")


def _safe_next_url(target):
    if not target:
        return None
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    if redirect_url.scheme in {"http", "https"} and redirect_url.netloc == host_url.netloc:
        return target
    return None

with app.app_context():
    db.create_all()


@app.context_processor
def inject_template_helpers():
    return {"csrf_token": _csrf_token}


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        _validate_csrf_token()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user is None or not user.check_password(password):
            flash("Invalid username or password.", "danger")
            return render_template("login.html"), 401

        login_user(user)
        session.pop("csrf_token", None)
        return redirect(_safe_next_url(request.args.get("next")) or url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    _validate_csrf_token()
    logout_user()
    session.pop("csrf_token", None)
    return redirect(url_for("login"))


# --------------------------------------------
# Home Dashboard Route
# --------------------------------------------

@app.route("/")
@login_required
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
@login_required
def api_alerts():

    query = request.args.get("q", "", type=str).strip()[:100]
    alert_query = Alert.query

    if query:
        # Escape SQL LIKE metacharacters so a user search is interpreted as
        # text, not as an unbounded wildcard expression.
        escaped_query = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped_query}%"
        alert_query = alert_query.filter(or_(
            Alert.source_ip.ilike(pattern, escape="\\"),
            Alert.event_type.ilike(pattern, escape="\\"),
            Alert.attack_type.ilike(pattern, escape="\\"),
            Alert.description.ilike(pattern, escape="\\"),
            Alert.mitre_id.ilike(pattern, escape="\\"),
            Alert.country.ilike(pattern, escape="\\"),
            Alert.city.ilike(pattern, escape="\\"),
            Alert.isp.ilike(pattern, escape="\\"),
        ))

    matching_total = alert_query.count()
    alerts = alert_query.order_by(Alert.id.desc()).limit(100).all()

    return jsonify({

        "high": Alert.query.filter_by(severity="HIGH").count(),
        "medium": Alert.query.filter_by(severity="MEDIUM").count(),
        "low": Alert.query.filter_by(severity="LOW").count(),
        "total": Alert.query.count(),
        "matching_total": matching_total,
        "query": query,

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
@login_required
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

    # Alert timestamps use an ISO-like text format, whose first ten
    # characters are the calendar date in SQLite and in the current schema.
    alerts_by_day = (
        db.session.query(
            func.substr(Alert.timestamp, 1, 10).label("date"),
            func.count(Alert.id).label("count")
        )
        .filter(Alert.timestamp.isnot(None))
        .group_by(func.substr(Alert.timestamp, 1, 10))
        .order_by(func.substr(Alert.timestamp, 1, 10).desc())
        .limit(7)
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

        ],

        "alerts_by_day": [
            {"date": date, "count": count}
            for date, count in reversed(alerts_by_day)
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


@app.cli.command("create-user")
@click.argument("username")
@click.password_option(confirmation_prompt=True)
def create_user(username, password):
    """Create a dashboard user without exposing registration publicly."""
    username = username.strip()
    if not username or len(username) > 80:
        raise click.UsageError("Username must be between 1 and 80 characters.")
    if len(password) < 12:
        raise click.UsageError("Password must be at least 12 characters.")
    if User.query.filter_by(username=username).first():
        raise click.UsageError("That username already exists.")

    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    click.echo(f"Created user: {username}")


# --------------------------------------------
# Run Application
# --------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5001,
        debug=True
    )
