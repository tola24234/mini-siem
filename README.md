# Mini SIEM

![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-blue?logo=mitre&style=flat-square)
![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python&style=flat-square)
# Mini SIEM

![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-Credential%20Access-blue)

A lightweight Security Information and Event Management (SIEM) system in Python.
## Skills Demonstrated
- SIEM fundamentals (log ingestion, correlation, alerting)
- MITRE ATT&CK threat mapping
# Mini SIEM 🛡️

![Project Status](https://img.shields.io/badge/status-completed-brightgreen)

A lightweight Security Information and Event Management (SIEM) system built in Python. It collects logs, analyzes them for failed login attempts, generates alerts, maps attacks to MITRE ATT&CK tactics, and displays results in a dashboard.

---

## Features
If you want, I can write a polished README snippet including badges, screenshots, and instructions ready to send to a company.
- Collects authentication logs from `/var/log/auth.log` or custom log files.
- Detects brute-force login attempts and other suspicious activity.
- Generates real-time alerts with IP blocking simulation.
- MITRE ATT&CK mapping for detected attacks:
  - **Tactic:** Credential Access  
  - **Technique:** T1110 - Brute Force  
  - **Sub-technique:** T1110.001 - Password Guessing
- Dashboard accessible via web browser (Flask-based).
- Easily extendable with custom log analyzers and rules.

---

## Dashboard Preview

![Mini SIEM Dashboard](screenshots/dashboard.png)

---

## Installation

1. Clone the repository:
```bash
git clone https://github.com/tola24234/mini-siem.git
cd mini-siem/mini-siem
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

## 🚀 Run with Docker

You can build and run the Mini SIEM project in a Docker container:

```bash
# Build the Docker image
docker build -t mini-siem .

# Run the container (maps port 5000)
docker run -p 5000:5000 mini-siem
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
