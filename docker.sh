#!/bin/bash
docker build -t mini-siem .
docker run -p 5001:5001 mini-siem
