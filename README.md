## Skills Demonstrated
- SIEM fundamentals (log ingestion, correlation, alerting)
- MITRE ATT&CK threat mapping
- Python security automation
- Flask web dashboards
- Linux log analysis
- Incident detection and response workflow
## 🖥️ Mini SIEM Dashboard (Web UI)


# Mini SIEM - Security Information & Event Management

Mini SIEM is a Python-based security monitoring tool that collects logs, analyzes them, and generates alerts. The dashboard shows failed login attempts and maps attacks to MITRE ATT&CK tactics.

## Features
- Log collection from `auth_logs.txt`
- Brute-force detection
- MITRE ATT&CK mapping
- Web dashboard using Flask
- Alerts generation
- Screenshots saved for reporting

## Installation (Local Python)
1. Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
This project includes a Flask-based web dashboard that visualizes detected security events.

### Features
- Displays suspicious IPs
- Shows failed login attempts
- MITRE ATT&CK mapping
- Simulated alerting & blocking

### Dashboard Screenshot
![Mini SIEM Dashboard](screenshots/dashboard.png)

---

## 🚀 How to Run the Project

### 1️⃣ Clone Repository
```bash
git clone https://github.com/tola24234/mini-siem.git
cd mini-siem/mini-siem
# Mini SIEM System

## Description
A Mini Security Information and Event Management (SIEM) system that collects,
analyzes, and alerts on suspicious SSH login activity.

## 📸 Web Dashboard

The Mini SIEM dashboard visualizes detected brute-force activity,
associated MITRE ATT&CK techniques, and blocked IPs.

You can view the dashboard here:

[Open Dashboard](screenshots/dashboard.html)
## Features
- Linux authentication log collection
- SSH brute-force detection
- Alert generation
- SOC-style dashboard

## How to Run
```bash
sudo python3 collector/log_collector.py
python3 dashboard/dashboard.py
