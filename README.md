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
