# 🛡️ Mini-SIEM – Lightweight Security Monitoring System
![Docker](https://img.shields.io/badge/Docker-Enabled-blue?style=for-the-badge&logo=docker)
![Docker](https://img.shields.io/badge/Docker-Enabled-blue?style=for-the-badge&logo=docker)
![Python](https://img.shields.io/badge/Python-%3E%3D3.10-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-%3E%3D3.0-lightgrey?style=for-the-badge&logo=flask)
![MIT License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-blue?style=for-the-badge)

---

## 📌 Project Overview

Mini-SIEM is a lightweight **Security Information and Event Management (SIEM) prototype** built using Python and Flask.

It demonstrates basic **detection engineering** concepts used in Security Operations Centers (SOC).

The system monitors authentication logs, detects SSH brute-force attacks, maps threats to MITRE ATT&CK framework, and generates security alerts.

---

## 🚀 Live Demo

👉 https://mini-siem.onrender.com/

⚠ Note:
- Free Render instance may sleep after inactivity.
- First access may take a few seconds.

---

## 🎯 Features

- 📂 Linux authentication log monitoring
- 🔍 SSH brute-force attack detection
- 🧠 MITRE ATT&CK mapping
  - Tactic: Credential Access
  - Technique: T1110 – Brute Force
  - Sub-technique: T1110.001
- 🚨 Security alert generation
- 📊 Web dashboard visualization
- 🌐 REST API endpoint
- 🛑 Simulated IP blocking logic
- 📦 Modular detection architecture

---

## 📂 Project Architecture
mini-siem/
│
├── analyzer/
├── collector/
├── dashboard/
├── engine/
├── models/
├── logs/
├── config.py
├── requirements.txt
├── run.sh
└── README.md

---

## ⚙️ Installation Guide

### ✅ 1. Clone Repository

```bash
git clone https://github.com/tola24234/mini-siem.git
cd mini-siem
