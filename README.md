## Overview
This project was built to demonstrate monitoring authentication log events for suspicious behaviours of compromised admin users. It detects and records login activity, multi-factor authentication (MFA) failures, impossible travel, brute-force attacks and password changes. Alerts are generated when certain requirements are met based on users' activities. This project aims to improve future growth towards an entry-level security analyst role.

## Threat Model

The purpose of this detection model is to identify potential threats related to compromised admin users by monitoring authentication activity. This includes tracking:
- Successful logins attempts followed by MFA verfication failures
- Successful logins from different geographic locations within a short time window
- Password changes performed after suspected account compromise
- Generating alerts when defined detection rules are triggered

## Detection Logic

The detection model processes authentication log events and applies multiple detection rules. Each rule evaulates user activity and generates an alert when specific criteria or suspicious patterns are met. 

## How It Works

## detect.py
Processes authentication log events and evaluates them against multiple detection rules. Each rule is responsible for identifying a specific threat pattern by correlating related events within a defined time window. When a rule’s conditions are met, an alert is generated.

- detect_login_failure: identifies failed login attempts
- detect_admin_login_outside_business_hours: detect successful admin logins occurring outside defined business hours
- detect_admin_mfa_failure_after_password_success: identifies admin accounts where a successful login is folloed by an MFA verification failure
- detect_bruteforce: detects users exceeding a defined threshold of failed login attempts
- detect_impossible_travel: identifies successful logins from differrent geographic locations within a short time window
- detect_password_change: tracks user password change activity
- detect_password_change_after_impossible_travel: detects password changes that occur after an impossible travel event


## Project Structure

|-git-practice
  | -.venv
  | -detect.py
  
## Limitations and Future Improvements

there are some limitation and future improvement this project could have used:
- coverage of other types of threats such as inside threat, DNS tunnelling, false negatives, etc
- limited to only user and admin account monitoring
- filtering log events for different user such as regular user own log event and admin log events exclusive.
