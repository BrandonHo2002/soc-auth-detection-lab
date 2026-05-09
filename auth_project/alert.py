import json
import time

ALERT_COOLDOWN = 30
alerted_alerts = {}


def send_alert(alert):
    user = alert.get("user", "unknown")
    now = time.time()

    detection_type = alert.get("detection_type", "unknown")
    alert_key = (user, detection_type)

    last = alerted_alerts.get(alert_key, 0)
    if now - last < ALERT_COOLDOWN:
        return  # suppress duplicate alerts

    alerted_alerts[alert_key] = now

    print("\nALERT ")
    print(json.dumps(alert, indent=2))
