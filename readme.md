# Insider Threat Login Pattern Detector

## 📌 Overview
This project simulates a SOC tool that detects suspicious login behavior using rule-based analysis.

## 🚀 Features
- Detects odd-hour logins
- Identifies impossible travel (location anomaly)
- Detects rapid login attempts
- Generates alert severity levels
- Calculates risk score per user
- Identifies most suspicious user
- Saves report to file

## 📁 Project Structure
insider-threat-login-detector/
│── logs.csv  
│── detector.py  
│── README.md  
│── alerts_report.txt  

## 📊 Sample Output

--- ALERTS ---

User: john | Issue: Odd hour login | Severity: Medium  
User: john | Issue: Multiple locations in short time | Severity: High  

--- SUMMARY ---

john → High: 1, Medium: 1, Low: 0  

--- RISK SCORES ---

john → Risk Score: 80 (CRITICAL)  

--- TOP THREAT USER ---

Most Suspicious User: john (Score: 80)

## ▶️ How to Run
```bash
python detector.py