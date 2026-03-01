# ============================================
# Mini-SIEM Configuration File
# ============================================

import os

# ============================================
# Core SIEM Settings
# ============================================

# Log source (change to test_auth.log for testing)
LOG_FILE = "/var/log/auth.log"

# Enable real firewall blocking (use False for safety)
ENFORCE_BLOCKING = False

# Brute force detection settings
BRUTE_FORCE_THRESHOLD = 5      # Failed attempts before alert
BRUTE_FORCE_WINDOW = 60        # Time window in seconds


# ============================================
# Flask & Database Configuration
# ============================================

class Config:
    # Security key (change in production)
    SECRET_KEY = os.environ.get("SECRET_KEY", "supersecretkey")

    # Use only ONE database file
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///siem.db"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
