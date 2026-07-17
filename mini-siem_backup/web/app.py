import sys
import os

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template
from analyzer.log_analyzer import analyze_logs

app = Flask(__name__)

@app.route("/")
def dashboard():
    results = analyze_logs()

    blocked_ips = []
    alerts = []
    data = []

    for ip, info in results.items():
        data.append({
            "ip": ip,
            "count": info["count"],
            "tactic": info["mitre"]["tactic"],
            "technique": info["mitre"]["technique_id"],
            "sub_technique": info["mitre"]["sub_technique"]
        })
        blocked_ips.append(ip)
        alerts.append(f"{ip} failed {info['count']} times")

    return render_template(
        "dashboard.html",
        data=data,
        alerts=alerts,
        blocked_ips=blocked_ips
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
