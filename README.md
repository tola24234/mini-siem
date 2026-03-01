# 🛡️ Mini-SIEM – Lightweight Security Monitoring System

[![Docker](https://img.shields.io/badge/Docker-Enabled-blue?style=for-the-badge&logo=docker)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-%3E%3D3.10-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-%3E%3D3.0-lightgrey?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-blue?style=for-the-badge)](https://attack.mitre.org/)

A lightweight **Security Information and Event Management (SIEM)** prototype built in Python + Flask.  
Designed to showcase **detection engineering**, log analysis, threat mapping, and basic SOC workflows.

## 📌 Project Overview

Mini-SIEM monitors Linux authentication logs (e.g., `/var/log/auth.log` or custom files), detects **SSH brute-force attacks** using configurable thresholds, maps detections to the **MITRE ATT&CK** framework (T1110.001 – Password Guessing), generates real-time alerts, simulates IP blocking, and visualizes everything in a clean web dashboard.

Great for learning SIEM basics, practicing Python security tooling, or demonstrating skills in junior SOC analyst, detection engineer, or DevSecOps roles.

## 🚀 Live Demo

👉 **[https://mini-siem.onrender.com/](https://mini-siem.onrender.com/)**

⚠ **Notes**:
- Free Render tier → may sleep after ~15 min inactivity (first load: 10–30 seconds).
- Refresh the page to trigger log re-analysis on demo data.
- Currently shows **0 alerts** (clean demo logs) — add test brute-force entries locally to see detections in action.

## 🎯 Key Features

- 📂 Real-time Linux auth log monitoring & parsing
- 🔍 SSH brute-force detection (failed login threshold + time window)
- 🧠 MITRE ATT&CK mapping  
  - Tactic: Credential Access  
  - Technique: T1110 – Brute Force  
  - Sub-technique: T1110.001 – Password Guessing
- 🚨 Alert generation (console, file-based, severity levels)
- 📊 Responsive Flask web dashboard (alerts, suspicious IPs, blocked list)
- 🌐 Basic REST API endpoint for external log ingestion
- 🛑 Simulated IP blocking (easy to extend to iptables/firewalld)
- 📦 Modular architecture (collector → analyzer → engine → dashboard)
- 🐳 Docker support + deployment-ready

## 📂 Architecture

mini-siem/
├── analyzer/          # Detection rules & MITRE mapping logic
├── collector/         # Log file/tail collection & parsing
├── dashboard/         # Flask app, templates, routes
├── engine/            # Core correlation & alerting
├── models/            # Data structures (alerts, events)
├── data/              # Sample logs (auth_logs.txt)
├── alerts/            # Output alert files
├── screenshots/       # Demo images
├── config.py          # Central configuration
├── requirements.txt
├── run.sh
├── Dockerfile
├── .github/workflows/ # CI (Docker build)
└── README.md 

## ⚙️ Quick Start (Installation)

### Prerequisites
- Python 3.10+
- Git
- (Optional) Docker

### Local Setup (Recommended)

1. Clone the repo:
   ```bash
   git clone https://github.com/tola24234/mini-siem.git
   cd mini-siem
Create & activate virtual environment:
   Bash

    &nbsp;&nbsp;&nbsp;python -m venv venv &nbsp;&nbsp;&nbsp;source venv/bin/activate          # Windows: venv\Scripts\activate &nbsp;&nbsp;&nbsp;

Install dependencies:
   Bash

    &nbsp;&nbsp;&nbsp;pip install -r requirements.txt &nbsp;&nbsp;&nbsp;

Run the SIEM:
   Bash

    &nbsp;&nbsp;&nbsp;python run_mini_siem.py &nbsp;&nbsp;&nbsp;# OR &nbsp;&nbsp;&nbsp;./run.sh &nbsp;&nbsp;&nbsp;
Docker Setup
Bashdocker build -t mini-siem .
docker run -p 5000:5000 mini-siem
