# Mini SIEM System

## Description
A Mini Security Information and Event Management (SIEM) system that collects,
analyzes, and alerts on suspicious SSH login activity.

## Features
- Linux authentication log collection
- SSH brute-force detection
- Alert generation
- SOC-style dashboard

## How to Run
```bash
sudo python3 collector/log_collector.py
python3 dashboard/dashboard.py
