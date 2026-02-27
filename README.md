## Overview
This project was built to demonstrate monitoring authentication log events for suspicious behavior related to compromised admin users. It detects and records login activity, multi-factor authentication (MFA) failures, impossible travel, brute-force attacks, and password changes. Alerts are generated when specific conditions are met based on user activity. This project aims to support future growth toward an entry-level security analyst role.

## Threat Model

The purpose of this detection model is to identify potential threats related to compromised admin users by monitoring authentication activity. This includes tracking:
- Successful login attempts followed by MFA verification failures
- Successful logins from different geographic locations within a short time window
- Password changes performed after suspected account compromise
- Generating alerts when defined detection rules are triggered

## Detection Logic

The detection model processes authentication log events and applies multiple detection rules. Each rule evaluates user activity and generates an alert when specific criteria or suspicious patterns are identified.

## How It Works

### detect.py
Processes authentication log events and evaluates them against multiple detection rules. Each rule is responsible for identifying a specific threat pattern by correlating related events within a defined time window. When a rule’s conditions are met, an alert is generated.

- detect_login_failure: identifies failed login attempts
- detect_admin_login_outside_business_hours: detects successful admin logins occurring outside defined business hours
- detect_admin_mfa_failure_after_password_success: identifies admin accounts where a successful login is followed by an MFA verification failure
- detect_bruteforce: detects users exceeding a defined threshold of failed login attempts
- detect_impossible_travel: identifies successful logins from different geographic locations within a short time window
- detect_password_change: tracks user password change activity
- detect_password_change_after_impossible_travel: detects password changes that occur after an impossible travel event

## Project Structure

git-practice/
├── .venv/
└── detect.py

## Limitations and Future Improvements

There are several limitations and potential improvements for this project:
- The detection logic is limited to authentication-related threats and does not cover other attack types such as insider threats or broader system abuse
- Monitoring is limited to user and admin account activity, without deeper behavioral profiling
- Log events are not fully separated or filtered by user role, which could be improved to provide more granular detection logic
