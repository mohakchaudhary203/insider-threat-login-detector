# Insider Threat Login Detector

## 📌 Overview
A Python-based SOC tool that detects suspicious login behavior and potential insider threats using rule-based anomaly detection.

## 🚀 Features
- Detects odd-hour logins  
- Identifies impossible travel (multiple locations in short time)  
- Detects rapid login attempts  
- Generates alert severity (Low / Medium / High)  
- Provides user-wise summary and insights  

## 🧠 Detection Logic
- Login during unusual hours (0–6 AM)  
- Multiple locations within short time window  
- High frequency login attempts  

## 📁 Project Structure
insider-threat-login-detector/
│── detector.py  
│── logs.csv  
│── README.md  

## ▶️ How to Run
```bash
python detector.py
