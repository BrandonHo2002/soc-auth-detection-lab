import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import IsolationForest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs", "pro_auth.log")

WINDOW_SLEEP = 5
ALERT_COOLDOWN = 30
FAILED_THRESHOLD = 5

alerted_users = {}

model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
trained = False


def summarize_logs():
    failed = defaultdict(int)
    success = defaultdict(int)
    locked = defaultdict(int)

    if not os.path.exists(LOG_FILE):
        return [], np.array([]), failed, success, locked

    today = datetime.now().strftime("%Y-%m-%d")

    with open(LOG_FILE, "r") as f:
        for line in f:
            if not line.startswith(today):
                continue

            if "[AUTH_PROJECT_FAIL]" in line:
                user = line.split("for:")[-1].strip()
                failed[user] += 1

            elif "[AUTH_PROJECT_SUCCESS]" in line and "logged in" in line:
                user = line.split("logged in:")[-1].strip()
                success[user] += 1

            elif "Account locked" in line:
                user = line.split("Account locked;")[-1].strip()
                locked[user] += 1

    users = list(set(failed) | set(success) | set(locked))
    vectors = [[failed[u], success[u], locked[u]] for u in users]

    return users, np.array(vectors), failed, success, locked


def calculate_severity(failed, success, locked):
    if locked > 0:
        return "HIGH"
    if failed >= 5 and success == 0:
        return "HIGH"
    if failed >= 3:
        return "MEDIUM"
    return "LOW"


def emit_alert(user, failed, success, locked, severity):
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user,
        "failed_attempts": failed,
        "successful_logins": success,
        "account_locked": locked,
        "severity": severity,
        "source": "auth-log-monitor",
    }

    print("\n ALERT ")
    print(json.dumps(alert, indent=2))


print("[LOG AGENT] Monitoring started...")
print(f"[LOG AGENT] Watching: {LOG_FILE}")

while True:
    users, X, failed_map, success_map, locked_map = summarize_logs()
    now = time.time()

    # ---- Summary heartbeat ----
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Summary:")
    for user in users:
        print(
            f"  {user} → failed={failed_map[user]}, "
            f"success={success_map[user]}, locked={locked_map[user]}"
        )

    # ---- Threshold alerts ----
    for user in users:
        failed = failed_map[user]
        success = success_map[user]
        locked = locked_map[user]

        if failed >= FAILED_THRESHOLD:
            last = alerted_users.get(user, 0)
            if now - last > ALERT_COOLDOWN:
                severity = calculate_severity(failed, success, locked)
                emit_alert(user, failed, success, locked, severity)
                alerted_users[user] = now

    # ---- ML anomaly detection ----
    if len(X) > 0:
        if not trained:
            model.fit(X)
            trained = True
            print("[MODEL] Baseline trained")
        else:
            preds = model.predict(X)
            for user, pred, vec in zip(users, preds, X):
                if pred == -1:
                    failed, success, locked = vec
                    emit_alert(
                        user,
                        failed,
                        success,
                        locked,
                        "ANOMALY",
                    )

    time.sleep(WINDOW_SLEEP)
