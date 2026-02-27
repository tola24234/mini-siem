# config.py

# --- Mini-SIEM main settings ---
LOG_FILE = "/var/log/auth.log"
ENFORCE_BLOCKING = False  # True = actually block IPs
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 60

# --- Flask / Database settings ---
class Config:
    SECRET_KEY = "supersecretkey"
    SQLALCHEMY_DATABASE_URI = "sqlite:///siem.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
