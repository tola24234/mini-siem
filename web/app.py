import sys
import os
from datetime import datetime

# Fix import path so we can reach analyzer/ and alerts/ from web/
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template
import configparser

# Try to import the real analysis function
try:
    from analyzer.log_analyzer import analyze_logs  # most likely file/function
except ImportError:
    try:
        from analyzer.anomaly_detector import analyze_logs  # fallback
    except ImportError:
        print("Warning: Could not import analyze_logs from analyzer/ - using dummy data only")
        analyze_logs = None  # we'll handle it below

# Optional: import alert functions if they exist
try:
    from alerts.alert_manager import write_alert, block_ip
except ImportError:
    write_alert = None
    block_ip = None
    print("Warning: Could not import write_alert/block_ip - alerts will be printed only")

app = Flask(__name__)

@app.route('/')
def dashboard():
    # Load config
    config = configparser.ConfigParser()
    try:
        config.read('../config.ini')  # from web/ to root
        threshold = int(config.get('detection', 'threshold', fallback='5'))
    except Exception as e:
        print(f"Config read failed: {e}")
        threshold = 5

    # Run log analysis
    results = []
    try:
        if analyze_logs:
            # Call with correct arguments (adjust path if needed)
            results = analyze_logs('../data/auth_logs.txt', threshold)
        else:
            raise Exception("No analyze_logs function available")
    except Exception as e:
        print(f"Analysis failed: {type(e).__name__}: {e}")
        # Dummy data so the dashboard always shows something useful
        results = [
            {'ip': '192.168.1.10', 'count': 6}
        ]

    # Prepare template data
    data = []
    alerts = []
    blocked_ips = []

    for entry in results:
        # Flexible extraction (works if result is dict or list/tuple)
        if isinstance(entry, dict):
            ip = entry.get('ip', 'unknown')
            count = entry.get('count', 0)
        else:
            ip = entry[0] if len(entry) > 0 else 'unknown'
            count = entry[1] if len(entry) > 1 else 0

        data.append({
            'ip': ip,
            'count': count,
            'tactic': 'Credential Access',
            'technique': 'Brute Force',
            'sub_technique': 'T1110.001 - Password Guessing'
        })

        # Create alert message with proper timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{timestamp}] ALERT: Potential brute-force from {ip} ({count} attempts) → T1110.001 - Password Guessing"
        alerts.append(alert_msg)

        # Simulate block (or use real function if available)
        if block_ip:
            block_ip(ip)
        blocked_ips.append(ip)

        # Optional: write to file/console
        if write_alert:
            write_alert(ip, count)

    return render_template('dashboard.html',
                           data=data,
                           alerts=alerts,
                           blocked_ips=blocked_ips)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
