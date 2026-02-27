import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template
import configparser

# Try different possible import paths based on your folder structure
try:
    from analyzer.log_analyzer import analyze_logs  # most common name from your ls
except ImportError:
    try:
        from analyzer.anomaly_detector import analyze_logs  # fallback if name is different
    except ImportError:
        # If neither works, we'll define a dummy function below
        print("Warning: Could not import analyze_logs - using dummy data")

from alerts.alert_manager import write_alert, block_ip  # if these exist

app = Flask(__name__)

@app.route('/')
def dashboard():
    config = configparser.ConfigParser()
    config.read('../config.ini')  # from web/ → root

    threshold = int(config.get('detection', 'threshold', fallback='5'))

    # Try to run real analysis
    try:
        # Adjust function name/path if needed (check analyzer/*.py for the real function)
        results = analyze_logs('../data/auth_logs.txt', threshold)
    except (NameError, ImportError, Exception) as e:
        print(f"Analysis failed: {e}")
        # Dummy data so template shows something (remove later)
        results = [
            {'ip': '192.168.1.10', 'count': 6}
        ]

    data = []
    alerts = []
    blocked_ips = []

    for entry in results:
        ip = entry.get('ip', '192.168.1.10')
        count = entry.get('count', 6)

        data.append({
            'ip': ip,
            'count': count,
            'tactic': 'Credential Access',
            'technique': 'Brute Force',
            'sub_technique': 'T1110.001 - Password Guessing'
        })

        alert_msg = f"[{os.popen('date +%Y-%m-%d %H:%M:%S').read().strip()}] ALERT: Brute-force from {ip} ({count} attempts)"
        alerts.append(alert_msg)

        # Simulate block
        blocked_ips.append(ip)
        # if 'block_ip' in globals(): block_ip(ip)

    return render_template('dashboard.html',
                           data=data,
                           alerts=alerts,
                           blocked_ips=blocked_ips)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
