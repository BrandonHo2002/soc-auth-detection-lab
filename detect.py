import json
import os
from datetime import datetime, timedelta


def detect_login_failures(events):
    alerts = []

    for event in events:
        if event["action"] == "login" and event["status"] == "fail":
            alerts.append(
                {
                    "alert_type": "LOGIN_FAILURE",
                    "ts": event["ts"],
                    "actor": event["actor"],
                    "ip": event["ip"],
                    "source": event["source"],
                    "severity": "low",
                }
            )
    return alerts


def detect_admin_login_outside_business_hours(
    events, business_start=9, business_end=17
):
    alerts = []

    for event in events:
        if (
            event["action"] == "login"
            and event["status"] == "success"
            and event.get("role") == "admin"
        ):
            hour = event["ts"].hour

            if hour < business_start or hour >= business_end:
                alerts.append(
                    {
                        "alert_type": "ADMIN_LOGIN_OUTSIDE_BUSINESS_HOURS",
                        "ts": event["ts"],
                        "actor": event["actor"],
                        "ip": event["ip"],
                        "source": event["source"],
                        "severity": "high",
                        "details": {
                            "business_hours": f"{business_start}:00-{business_end}:00",
                            "login_hour": hour,
                        },
                    }
                )
    return alerts


def detect_admin_mfa_failure_after_password_success(events, window_minutes=5):
    alerts = []
    admin_password_success = {}

    for event in events:
        if (
            event["action"] == "login"
            and event["status"] == "success"
            and event.get("role") == "admin"
            and event.get("auth_step") == "password"
        ):
            admin_password_success[event["actor"]] = event["ts"]

        if (
            event["action"] == "mfa"
            and event["status"] == "fail"
            and event.get("role") == "admin"
        ):
            user = event["actor"]

            if user in admin_password_success:
                time_diff = event["ts"] - admin_password_success[user]

                if time_diff.total_seconds() <= window_minutes * 60:
                    alerts.append(
                        {
                            "alert_type": "ADMIN_MFA_FAILURE_AFTER_PASSWORD_SUCCESS",
                            "ts": event["ts"],
                            "actor": user,
                            "ip": event["ip"],
                            "source": event["source"],
                            "severity": "high",
                            "details": {
                                "window_minutes": window_minutes,
                                "time_since_password_success_seconds": int(
                                    time_diff.total_seconds()
                                ),
                            },
                        }
                    )

                    del admin_password_success[user]
    return alerts


def detect_bruteforce(events, threshold=5, window_minutes=5):
    alerts = {}
    failed_logins = {}

    for event in events:
        if event["action"] == "login" and event["status"] == "fail":
            user = event["actor"]
            failed_logins.setdefault(user, []).append(event)

    for user, user_events in failed_logins.items():
        user_events.sort(key=lambda e: e["ts"])

        for i in range(len(user_events)):
            start = user_events[i]["ts"]
            end = start + timedelta(minutes=window_minutes)

            count = sum(1 for e in user_events if start <= e["ts"] <= end)

            if count >= threshold:
                alerts[user] = {
                    "alert_type": "BRUTE_FORCE",
                    "actor": user,
                    "count": count,
                    "window_minutes": window_minutes,
                    "source": "auth",
                    "severity": "medium",
                }
                break
    return list(alerts.values())


def detect_impossible_travel(events, window_minutes=60):
    alerts = []
    last_login = {}

    for event in events:
        if event["action"] != "login" or event["status"] != "success":
            continue

        user = event["actor"]
        ts = event["ts"]
        location = event.get("location")
        ip = event.get("ip")

        if not location:
            continue

        if user in last_login:
            prev = last_login[user]
            time_diff = ts - prev["ts"]

            if (
                time_diff.total_seconds() <= window_minutes * 60
                and prev["location"] != location
            ):
                alerts.append(
                    {
                        "alert_type": "IMPOSSIBLE_TRAVEL",
                        "actor": user,
                        "ts": ts,
                        "source": event["source"],
                        "severity": "high",
                        "detail": {
                            "previous_location": prev["location"],
                            "current_location": location,
                            "previous_ip": prev["ip"],
                            "current_ip": ip,
                            "time_difference_minutes": int(
                                time_diff.total_seconds() / 60
                            ),
                        },
                    }
                )
        last_login[user] = {
            "ts": ts,
            "location": location,
            "ip": ip,
        }
    return alerts


def detect_password_change(events, window_minutes=60):
    alerts = []
    last_login = {}

    for event in events:
        if event["action"] == "login" and event["status"] == "success":
            user = event["actor"]
            ts = event["ts"]
            location = event["location"]
            ip = event["ip"]
            last_login[user] = {
                "ts": ts,
                "location": location,
                "ip": ip,
            }

        elif event["action"] == "password_change" and event["status"] == "success":
            user = event["actor"]

            if user not in last_login:
                continue

            prev = last_login[user]
            time_diff = event["ts"] - prev["ts"]

            if time_diff.total_seconds() <= window_minutes * 60:
                alerts.append(
                    {
                        "alert_type": "PASSWORD_CHANGE_AFTER_LOGIN",
                        "actor": user,
                        "severity": "medium",
                        "details": {
                            "time_since_login_seconds": int(time_diff.total_seconds()),
                            "previous_ip": prev["ip"],
                            "previous_location": prev["location"],
                        },
                    }
                )
    return alerts


def detect_password_change_after_impossible_travel(
    events, impossible_travel_alerts, window_minutes=60
):
    alerts = []

    travel_by_user = {alert["actor"]: alert for alert in impossible_travel_alerts}

    for event in events:
        if event["action"] == "password_change" and event["status"] == "success":
            user = event["actor"]

            if user not in travel_by_user:
                continue

        travel_alert = travel_by_user[user]
        time_diff = event["ts"] - travel_alert["ts"]

        if time_diff.total_seconds() <= window_minutes * 60:
            alerts.append(
                {
                    "alert_type": "PASSWORD_CHANGE_AFTER_IMPOSSIBLE_TRAVEL",
                    "actor": user,
                    "severity": "critical",
                    "details": {
                        "time_since_travel_seconds": int(time_diff.total_seconds()),
                        "from_location": travel_alert.get("from_location"),
                        "to_location": travel_alert.get("to_location"),
                    },
                }
            )
    return alerts


alerts = []
alerts.extend(detect_login_failures(events))
alerts.extend(detect_bruteforce(events))
alerts.extend(detect_admin_login_outside_business_hours(events))
alerts.extend(detect_admin_mfa_failure_after_password_success(events))
impossible_travel_alerts = detect_impossible_travel(events)
alerts.extend(
    detect_password_change_after_impossible_travel(events, impossible_travel_alerts)
)

for alert in alerts:
    print(alert)
