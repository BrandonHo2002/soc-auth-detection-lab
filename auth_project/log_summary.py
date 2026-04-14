import os
import time
from collections import defaultdict
from datetime import datetime, timezone

import numpy as np
from alert import send_alert
from sklearn.ensemble import IsolationForest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs", "auth.log")

WINDOW_SLEEP = 5
FAILED_THRESHOLD = 5
threshold_alerted = set()

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

            if "[AUTH_PROJECT_LOGIN_FAIL]" in line:
                user = line.split("for:")[-1].strip()
                failed[user] += 1

            elif "[AUTH_PROJECT_LOGIN_SUCCESS]" in line:
                user = line.split("for:")[-1].strip()
                success[user] += 1

            elif "[AUTH_PROJECT_ACCOUNT_LOCK]" in line:
                user = line.split(";")[-1].strip()
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


print("[LOG AGENT] Monitoring started...")
print(f"[LOG AGENT] Watching: {LOG_FILE}")

try:
    while True:
        users, X, failed_map, success_map, locked_map = summarize_logs()

        # ---- Summary heartbeat ----
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Summary:")
        for user in users:
            print(
                f"  {user} → failed={failed_map[user]}, "
                f"success={success_map[user]}, locked={locked_map[user]}"
            )

        # ---- Threshold-based alerts ----
        now = time.time()

        for user in users:
            failed = failed_map[user]
            success = success_map[user]
            locked = locked_map[user]

            if failed >= FAILED_THRESHOLD and user not in threshold_alerted:
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "user": user,
                    "failed_attempts": int(failed),
                    "successful_logins": int(success),
                    "account_locked": int(locked),
                    "severity": calculate_severity(failed, success, locked),
                    "detection_type": "threshold",
                    "source": "auth-log-monitor",
                }
                send_alert(alert)
                threshold_alerted.add(user)

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
                        alert = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "user": user,
                            "failed_attempts": int(failed),
                            "successful_logins": int(success),
                            "account_locked": int(locked),
                            "severity": "HIGH",
                            "detection_type": "ml-isolation-forest",
                            "source": "auth-log-monitor",
                        }
                        send_alert(alert)

        time.sleep(WINDOW_SLEEP)

except KeyboardInterrupt:
    print("\n[LOG AGENT] Stopped by user")
except Exception as e:
    print("\n[LOG AGENT] Fatal error occurred")
    print(f"Error: {e}")
