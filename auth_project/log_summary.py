import os
import time
import json
from collections import defaultdict
from datetime import datetime, timezone

import numpy as np
from alert import send_alert
from sklearn.ensemble import IsolationForest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "..", "logs", "auth.log")

WINDOW_SLEEP = 5
FAILED_THRESHOLD = 5
threshold_alerted = set()
mfa_alerted = set()

model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
trained = False


def summarize_logs():
    failed = defaultdict(int)
    success = defaultdict(int)
    locked = defaultdict(int)
    mfa_fail = defaultdict(int)
    last_event = {}

    if not os.path.exists(LOG_FILE):
        return [], np.array([]), failed, success, locked, mfa_fail

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                log = json.loads(line)
            except json.JSONDecodeError:
                continue

            user = log.get("user")
            event = log.get("event")
            prev_event = last_event.get(user)

            if event == "LOGIN_SUCCESS" and prev_event == "MFA_DISABLE":
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "user": user,
                    "severity": "HIGH",
                    "detection_type": "mfa_disabled_then_login",
                    "source": "auth-log-monitor",
                }
                send_alert(alert)

            last_event[user] = event

            if not user or not event:
                continue

            if event == "LOGIN_FAIL":
                failed[user] += 1

            elif event == "LOGIN_SUCCESS":
                success[user] += 1

            elif event == "ACCOUNT_LOCK":
                locked[user] += 1

            elif event == "MFA_FAIL":
                mfa_fail[user] += 1

    users = list(set(failed) | set(success) | set(locked) | set(mfa_fail))
    vectors = [[failed[u], success[u], locked[u], mfa_fail[u]] for u in users]

    return users, np.array(vectors), failed, success, locked, mfa_fail


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
        users, X, failed_map, success_map, locked_map, mfa_fail_map = summarize_logs()

        # ---- Summary heartbeat ----
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Summary:")
        for user in users:
            print(
                f"  {user} → failed={failed_map[user]}, "
                f"success={success_map[user]}, locked={locked_map[user]}"
            )

        # ---- Threshold-based alerts ----

        for user in users:
            failed = failed_map[user]
            success = success_map[user]
            locked = locked_map[user]
            mfa_fail = mfa_fail_map[user]

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

            if mfa_fail_map[user] >= 3 and user not in mfa_alerted:
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "user": user,
                    "failed_mfa_attempts": int(mfa_fail_map[user]),
                    "severity": "HIGH",
                    "detection_type": "mfa_bruteforce",
                    "source": "auth-log-monitor",
                }
                send_alert(alert)
                mfa_alerted.add(user)

        # ---- Experimental ML-based anomaly detection using Isolation Forest for learning purposes ----
        if len(X) > 0 and len(users) > 0:
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
