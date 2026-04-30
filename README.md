## Overview

This project simulates a secure authentication system designed to monitor and detect suspicious login activity, particularly focusing on detecting potentially compromised accounts.

Detection is implemented using Splunk as the primary SIEM tool, with custom Python scripts included for learning purposes. It includes features such as structured logging, multi-factor authentication (MFA), account lockouts, and detection of abnormal behaviours.

It simulates a Security Operations Center (SOC) workflow, where authentication logs are generated, ingested into a SIEM, and analyzed to detect potential security threats.

The project demonstrates an end-to-end detection pipeline, from log generation to SIEM-based monitoring and investigation.

## Getting Started

Follow these steps to run the project locally:

1. Initialize the database:
   ```bash
   python auth_project/init_db.py
   ```

2. Create an admin account:
   ```bash 
   python auth_project/create_admin.py
   ```
   This script creates an initial admin user required to manage other accounts.

3. Run the authentication system:
   ```bash
   python auth_project/auth.py
   ```
   Authentication logs will be generated in:
   ```
   logs/auth.log
   ```
   Interact with the system (e.g., login attempts, failed logins, MFA actions) to generate authentication events.

   These logs can then be ingested into Splunk for monitoring and detection.

## Setup Notes

Create a `config/auth_pepper.txt` file and add a secret value used for password hashing.

This file is required for the authentication system to run.

Example:

mysecretpepper123

## Threat Model

The system is designed to detect threats related to compromised user and admin accounts by monitoring authentication activity. This includes:

* Multiple failed login attempts (brute-force attacks)
* Failed login attempts followed by a successful login
* MFA verification failures
* Account lockouts due to repeated failures
* Suspicious login patterns

## Detection Approach

### Local Detection (Python)

Custom scripts are included for learning purposes to demonstrate how detection logic works, including threshold-based alerting, event correlation, and basic anomaly detection.

* **log_summary.py**  
  Monitors authentication logs in real time, performs threshold-based detection, and applies basic anomaly detection using Isolation Forest.

* **alert.py**  
  Generates alerts when suspicious behavior is detected and includes alert suppression logic to prevent duplicate alerts within a short time window.

These scripts demonstrate how detection logic can be implemented behind the scenes and were later supplemented by Splunk, which is used as the primary detection and monitoring tool to better reflect real-world SOC workflows.

### Splunk Detection (Primary)

Detection logic is primarily implemented in Splunk using SPL queries, including:

* Multiple failed login attempts
* Failed attempts followed by successful login
* Account lockouts

Splunk is used as the primary detection and monitoring tool, reflecting real-world SOC environments.

These detections are visualized in the Splunk dashboard for real-time monitoring.

## How It Works

* `init_db.py` is used to initialize the database before running the system
* `auth.py` generates structured authentication logs
* Logs are stored in `logs/auth.log`
* Logs can be:

  * analyzed locally using Python scripts
  * ingested into Splunk for real-time detection and alerting

The authentication system (`auth.py`) includes:

* Secure password hashing using bcrypt with a pepper
* Account lockout after multiple failed login attempts
* Multi-Factor Authentication (MFA) using TOTP (PyOTP)
* Role-based access control (admin vs user)
* Input validation and basic injection detection
* Structured JSON logging for all authentication events

## Log Format Example

```json
{
  "_time": "2026-04-10T12:34:56",
  "event": "LOGIN_FAIL",
  "event_id": "AUTH_002",
  "user": "admin",
  "src_ip": "192.168.1.10",
  "status": "FAILURE",
  "severity": "MEDIUM",
  "details": "wrong_password_attempt_1"
}
```

## Splunk Setup

Splunk was configured to monitor the authentication log file (`logs/auth.log`) as a data input.

A custom index was created to store authentication events, and SPL queries were used to analyze login activity and detect suspicious behavior.

## Splunk Dashboard

A Splunk dashboard was created to monitor authentication activity and detect suspicious behavior in real time.

The dashboard includes panels for:

* Failed login attempts over time
* Successful logins after multiple failures
* Account lockouts
* Top attacked users
* Top attacker IPs
* Event breakdown (LOGIN_FAIL, LOGIN_SUCCESS, MFA events, etc.)
* Suspicious input detection
* MFA activity monitoring

These visualizations simulate how a SOC analyst would monitor and investigate authentication-related threats.

The dashboard provides a quick way to identify suspicious patterns without manually running queries.

## Dashboard Screenshots

![Dashboard Overview](screenshots/dashboard_overview.png)
![Suspicious Logins](screenshots/suspicious_logins.png)
![Event Breakdown](screenshots/event_breakdown.png)


## Project Structure

```
project_root/
├── auth_project/
│   ├── auth.py
│   ├── auth_db.py
│   ├── init_db.py
│   ├── log_summary.py
│   ├── alert.py
│   └── ...
├── config/
│   └── auth_pepper.txt
├── logs/
│   └── auth.log
├── requirements.txt
└── README.md
```

## Limitations and Future Improvements

* Detection is currently focused only on authentication events
* Detection rules use simple thresholds and can be improved with more advanced logic
* Data is simulated and does not represent real attacker behavior
* No automated alerting system (e.g., notifications or integrations)
* Geographic-based detection (e.g., impossible travel) is simplified and can be improved with real IP data

## Goal

This project is designed to demonstrate practical skills relevant to an entry-level Security Analyst role, including:

* Log analysis
* Detection engineering
* SIEM (Splunk) usage
* Authentication security best practices
* Building and visualizing security detections in a SIEM dashboard
* Understanding SOC workflows and security event investigation processes
