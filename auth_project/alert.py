import json
import time

ALERT_COOLDOWN = 30
alerted_users = {}


def send_alert(alert):
    user = alert["user"]
    now = time.time()

    last = alerted_users.get(user, 0)
    if now - last < ALERT_COOLDOWN:
        return  # suppress duplicate alerts

    alerted_users[user] = now

    print("\n ALERT ")
    print(json.dumps(alert, indent=2))
