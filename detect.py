import json
import os
from datetime import datetime

def detect_login_failures(events):
    alerts = []

    for event in events:
        if event["action"] == "login" and event["status"] == "fail":
            alerts.append({
                "alert_type": "LOGIN_FAILURE",
                "ts": event["ts"],
                "actor": event["alice"],
                "ip": event["ip"],
                "source": event["source"],
                "severity": "low"
                }
    return alerts

def detect_bruteforce(events):
    alerts = {
        "ts": datetime,
        "source": "auth",
        "actor": "alice",
        "action": "login",
        "status": "fail",
        "ip": "10.0.0.5"
    }
    return alerts

while True:
