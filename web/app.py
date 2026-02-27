from flask import Flask, render_template
# Make sure these imports exist (add if missing)
from analyzer.log_analyzer import analyze_logs   # adjust path if needed, e.g. analyzer.analyzer.analyze_logs
from alerts.alert_manager import write_alert, block_ip
import configparser

app = Flask(__name__, template_folder='templates')  # ensure templates folder is found

@app.route('/')
def dashboard():
    config = configparser.ConfigParser()
    config.read('../config.ini')  # or 'config.ini' if in root
    threshold = int(config.get('detection', 'threshold', fallback='5'))

    # Run your log analysis (adjust path/function name if needed)
    try:
        results = analyze_logs('data/auth_logs.txt', threshold)  # this should return list of dicts
    except Exception as e:
        print(f"Analysis failed: {e}")
        results = []

    # Prepare data for template (adapt based on what analyze_logs returns)
    data = []
    alerts = []
    blocked_ips = []

    for item in results:
        ip = item.get('ip', 'unknown')
        count = item.get('count', 0)
        tactic = item.get('tactic', 'Credential Access')
        technique = item.get('technique', 'Brute Force')
        sub_technique = item.get('sub_technique', 'T1110.001 - Password Guessing')

        data.append({
            'ip': ip,
            'count': count,
            'tactic': tactic,
            'technique': technique,
            'sub_technique': sub_technique
        })

        # Generate alert message
        alert_msg = f"Potential brute-force from {ip} ({count} attempts) → {sub_technique}"
        alerts.append(alert_msg)

        # Simulate block
        block_ip(ip)
        blocked_ips.append(ip)

    return render_template('dashboard.html',
                           data=data,
                           alerts=alerts,
                           blocked_ips=blocked_ips)
