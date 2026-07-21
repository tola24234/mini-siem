# ============================================
# Mini-SIEM Configuration File
# ============================================

import os

# ============================================
# Project Base Directory
# ============================================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ============================================
# Core SIEM Settings
# ============================================

# Log source (change to test_auth.log for testing)
LOG_FILE = "/var/log/auth.log"

# Enable real firewall blocking
# Set False during testing
ENFORCE_BLOCKING = False

# Brute Force Detection Settings
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 60

# ============================================
# Flask Configuration
# ============================================

class Config:

    # Secret Key
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "supersecretkey"
    )

    # Database Location
    #
    # This always points to:
    # ~/mini-siem/instance/siem.db
    #
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(BASE_DIR, "instance", "siem.db")
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Browser-session hardening. Set SESSION_COOKIE_SECURE=true behind HTTPS.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
