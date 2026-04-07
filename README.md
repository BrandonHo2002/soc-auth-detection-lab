## Overview

This project simulates an authentication system designed to monitor and detect suspicious login activity, particularly targeting potential compromised admin accounts. It includes logging, multi-factor authentication (MFA), account lockouts, and detection of abnormal behaviors.

Detection is implemented both through custom Python scripts and through Splunk, demonstrating both foundational detection logic and real-world SIEM usage.

## Threat Model

The system focuses on identifying threats related to compromised user and admin accounts by monitoring authentication activity. This includes:

* Multiple failed login attempts (brute-force attacks)
* Failed login attempts followed by a successful login
* MFA verification failures
* Account lockouts due to repeated failures
* Suspicious login patterns

## Detection Approach

### Local Detection (Python)

Custom scripts simulate SIEM-like behavior:

* **log_summary.py**
  Parses authentication logs and identifies suspicious activity patterns

* **alert.py**
  Generates alerts when predefined thresholds or behaviors are detected

These components demonstrate how detection logic works behind the scenes.

### Splunk Detection (Primary)

Detection logic is also implemented in Splunk using SPL queries, including:

* Multiple failed login attempts
* Failed attempts followed by successful login
* Account lockouts

Splunk is used as the primary detection and monitoring tool, reflecting real-world security operations workflows.

## How It Works

* `auth.py` generates structured authentication logs
* Logs are stored in `/logs/pro_auth.log`
* Logs can be:

  * analyzed locally using Python scripts
  * ingested into Splunk for real-time detection and alerting

## Project Structure

project_root/
├── auth_project/
│   ├── auth.py
│   ├── auth_db.py
│   ├── log_summary.py
│   ├── alert.py
│   └── ...
├── config/
│   └── auth_pepper.txt
├── logs/
│   └── pro_auth.log
├── requirements.txt
└── README.md

## Limitations and Future Improvements

* Detection is currently focused on authentication events only
* No advanced behavioral analytics (e.g., user baselining)
* Splunk dashboards and alert tuning can be further expanded
* Geographic-based detection (e.g., impossible travel) is simulated and can be improved with real IP geolocation data

## Goal

This project is designed to demonstrate skills relevant to an entry-level Security Analyst role, including:

* Log analysis
* Detection engineering
* SIEM (Splunk) usage
* Authentication security best practices
