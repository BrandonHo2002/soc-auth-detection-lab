import json
import time
from collections import defaultdict
from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import IsolationForest

LOG_FILE = "logs/pro_auth.log"
WINDOW_SLEEP = 10
ALERT_COOLDOWN = 30
FAILED_THRESHOLD = 5

last_line_processed = 0
alerted_users = {}

model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)

trained = False


def summarize_logs():
    global last_line_processed

    failed = defaultdict(int)
    success = defaultdict(int)
    locked = defaultdict(int)

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
        new_lines = lines[last_line_processed:]
        last_line_processed = len(lines)

        for line in new_lines:
            if "[AUTH_PROJECT_FAIL]" in line:
                user = line.split("for:")[-1].strip()
                failed[user] += 1
            elif "[AUTH_PROJECT_SUCCESS]" in line and "logged in" in line:
                user = line.split("logged in:")[-1].strip()
                success[user] += 1
            elif "Account locked:" in line:
                user = line.split("Account locked:")[-1].strip()
                locked[user] += 1

        feature_vectors = []
        users = list(set(failed) | set(success) | set(locked))

        for user in users:
            feature_vectors.append([failed[user], success[user], locked[user]])

        return users, np.array(feature_vectors), failed, success, locked


def calculate_severity(failed, success, locked):
    if locked > 0:
        return "HIGH"
    if failed >= 5 and success == 0:
        return "HIGH"
    if failed >= 3:
        return "MEDIUM"
    return "LOW"


def emit_json_alert(user, failed, success, locked, severity):
    print(
        f"[ALERT] {severity} | user={user} | failed={failed} | "
        f"success={success} | locked={locked}",
        flush=True,
    )

    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user,
        "failed_attempts": int(failed),
        "successful_logins": int(success),
        "account_locked": int(locked),
        "severity": severity,
        "source": "edge-auth-agent",
    }
    print(json.dumps(alert, indent=2), flush=True)


print("EDGE AGENT] Started")

while True:
    users, X, failed_map, success_map, locked_map = summarize_logs()

    current_time = time.time()

    for user in users:
        failed = failed_map[user]
        success = success_map[user]
        locked = locked_map[user]

        if failed >= FAILED_THRESHOLD:
            last_alert = alerted_users.get(user, 0)
            if current_time - last_alert > ALERT_COOLDOWN:
                severity = calculate_severity(failed, success, locked)
                emit_json_alert(user, failed, success, locked, severity)
                alerted_users[user] = current_time

    if len(X) > 0:
        if not trained:
            model.fit(X)
            trained = True
            print("[MODEL] Trained on baseline behaviour")
        else:
            preds = model.predict(X)

            for (
                user,
                pred,
                vec,
            ) in zip(users, preds, X):
                if pred == -1:
                    (
                        failed,
                        success,
                        locked,
                    ) = vec
                    last_alert = alerted_users.get(user, 0)

                    if current_time - last_alert > ALERT_COOLDOWN:
                        severity = calculate_severity(failed, success, locked)
                        emit_json_alert(user, failed, success, locked, severity)
                        alerted_users[user] = current_time

    time.sleep(WINDOW_SLEEP)
