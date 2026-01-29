import time
from datetime import datetime

LOG_FILE = "var/log/project_auth/pro_auth.log"
ATTACKER = "attacker1"
ATTEMPTS = 10
DELAY = 1

for i in range(ATTEMPTS):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - [AUTH_PROJECT_FAIL] Login attempt for: {ATTACKER}\n"

    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

    print(f"[ATTACK] Failed login {i + 1}/{ATTEMPTS} for {ATTACKER}")
    time.sleep(DELAY)

print("[ATTACK] Simulation complete")
