## Overview
This project was built to demonstrate core security engineering and SOC monitoring concepts, with a focus on authentication abuse detection, logging, and alerting workflows. The codebase is structured with clear separation between authentication logic, database access, logging, and monitoring to mirror real-world application design.

It includes:
- Secure user authentication with password hashing and MFA
- Account lockout and brute-force protection
- Centralized security logging
- Real-time log monitoring and alerting
- Basic anomaly detection using machine learning

This project was built as a learning and portfolio project to support my development toward an entry-level security analyst role.

---
## Threat Model

This system is designed to detect and mitigate common authentication-based attacks, including:

- Brute-force login attempts
- Credential stuffing
- Account enumeration
- Privilege abuse (admin targeting)
- Abnormal login behavior indicative of compromised accounts

The project simulates how a SOC might monitor authentication logs and respond to suspicious activity in real time.

---
## Detection Logic

The monitoring system evaluates authentication activity using multiple signals:

- Repeated failed login attempts within a short window
- Account lockout events
- Login frequency anomalies per user
- Isolation Forest anomaly scores for behavioral deviations

Alerts are generated only when thresholds are exceeded, with repeat alerts suppressed per user to reduce alert fatigue.

---

## Features

### Authentication Security
- Password hashing using **bcrypt**
- Secret pepper stored outside the database
- Input validation and basic injection detection
- Role-based access (admin vs user)
- Database writes are restricted through an allow-listed update interface to prevent unsafe field manipulation

### MFA (Multi-Factor Authentication)
- TOTP-based MFA using **pyotp**
- QR code or manual secret setup
- MFA required for admin accounts
- Optional MFA for regular users
- Secure MFA disable flow with password confirmation

### Account Protection
- Failed login attempt tracking
- Account lockout after repeated failures
- Automatic unlock after cooldown
- Admin manual unlock capability

### Logging & Monitoring
- Centralized logging of all auth events
- Daily log analysis
- Per-user security summaries
- Threshold-based alerts (failed attempts, account lock)
- Alert cooldown to prevent flooding

### Anomaly Detection
- Isolation Forest model to detect abnormal login patterns
- Baseline training from observed behavior
- Flags suspicious deviations automatically

---

## How It Works

### auth.py
Handles:
- User registration and login workflows
- Password verification and updates
- MFA enrollment and verification
- Account locking and unlocking logic
- Writing structured security logs

Authentication logic is intentionally separated from direct database access to reduce risk and improve maintainability.

Example log events:
- `[AUTH_PROJECT_FAIL]`
- `[AUTH_PROJECT_SUCCESS]`
- `[AUTH_PROJECT_ACCOUNT_LOCKED_ACTIVE]`

---

### log_summary.py
Runs continuously to:
- Monitor today's logs in real time
- Summarize login activity per user
- Detect suspicious behavior
- Generate structured alert objects
- Send alerts to `alert.py`

---

### alert.py
Responsible for:
- Receiving alert objects from `log_summary.py`
- Enforcing per-user alert cooldowns
- Printing structured JSON alerts
- Preventing alert spam

### auth_db.py
Responsible for all database interactions, providing a clean abstraction layer between authentication logic and persistent storage.

Functions include:
- Establishing SQLite connections
- Retrieving user records
- Updating restricted user fields via allow-listing
- Creating new user records

---

## Project Structure

auth_project/
│
├── auth.py           # Authentication logic and security controls
├── auth_db.py        # Database access layer (SQLite)
├── log_summary.py    # Log monitoring and alert generation
├── alert.py          # Alert handling and cooldown logic
├── users.db          # SQLite user database
├── auth_pepper.txt   # Server-side pepper for password hashing
└── logs/
    └── pro_auth.log  # Authentication and security logs

## Running the Project

### 1. Install Dependencies
```bash
pip install bcrypt pyotp qrcode numpy scikit-learn
```

### 2. Start the Monitoring system (separate terminal)
```bash
python log_summary.py
```

### 3. Start the Authentication System
```bash
python auth.py
```

## Limitations and Future Improvements
- Log ingestion is file-based rather than streaming
- Thresholds are static and not adaptive
- Model retraining is manual
- No centralized alert storage or dashboard
