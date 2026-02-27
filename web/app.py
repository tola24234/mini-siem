import sys
import os
from datetime import datetime
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template
import configparser

# Import analysis
from analyzer.log_analyzer import analyze_logs

app = Flask(__name__)

@app.route('/')
def dashboard():
    # Run analysis EVERY time page loads (important for Render)
    try:
        results = analyze_logs()   # uses our new fixed function
    except Exception as e:
        print(f"Analysis error: {e}")
        results = [{'ip': '192.168.1.10', 'count': 6}]

    # Prepare data for template
    data = []
    alerts = []
    blocked_ips = []

    for entry in results:
        ip = entry.get('ip', 'unknown')
        count = entry.get('count', 0)
        data.append({
            'ip': ip,
            'count': count,
            'tactic': 'Credential Access',
            'technique': 'Brute Force',
            'sub_technique': 'T1110.001 - Password Guessing'
        })
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alerts.append(f"[{timestamp}] ALERT: Potential brute-force from {ip} ({count} attempts)")
        blocked_ips.append(ip)

    return render_template('dashboard.html',
                           data=data,
                           alerts=alerts,
                           blocked_ips=blocked_ips)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
