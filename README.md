# Mini-SIEM

![Python](https://img.shields.io/badge/Python-%3E%3D3.10-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-%3E%3D3.0-lightgrey?style=for-the-badge&logo=flask)
![MIT License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-blue?style=for-the-badge)

A lightweight Security Information and Event Management (SIEM) system in Python.  
Mini-SIEM collects Linux authentication logs, detects brute-force SSH attacks, maps them to MITRE ATT&CK tactics, and displays alerts on a web dashboard.

---

## Features

- Collects authentication logs from `/var/log/auth.log` or custom log files.
- Detects brute-force login attempts and suspicious activity.
- Real-time alert generation with IP blocking simulation.
- MITRE ATT&CK mapping for detected attacks:
  - Tactic: Credential Access
  - Technique: T1110 – Brute Force
  - Sub-technique: T1110.001 – Password Guessing
- Web dashboard via Flask for interactive monitoring.
- Easily extendable with custom log analyzers and rules.

---

## Installation (Local Python)

```bash
# Clone the repository
git clone https://github.com/tola24234/mini-siem.git
cd mini-siem

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the dashboard
python3 dashboard/app.py
