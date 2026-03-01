#!/bin/bash

export PYTHONPATH=.
export SECRET_KEY=your_real_secret
export DATABASE_URL=sqlite:///siem.db

python3 dashboard/app.py
