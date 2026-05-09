import json
import os
import random
import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
AUTH_LOG = os.path.join(LOG_DIR, "auth.log")

os.makedirs(LOG_DIR, exist_ok=True)

# Simulated IP for Logging/demo purposes

def generate_ip():
    if random.random() < 0.7:
        return f"192.168.1.{random.randint(2, 254)}"  # internal
    return f"{random.randint(10, 200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def log_event(event, user, src_ip=None, details=None, status=None):
    event_map = {
            "LOGIN_SUCCESS": ("SUCCESS", "LOW", "AUTH_001"),
            "LOGIN_FAIL": ("FAILURE", "MEDIUM", "AUTH_002"),
            "ACCOUNT_LOCK": ("WARNING", "HIGH", "AUTH_003"),
            "MFA_FAIL": ("FAILURE", "HIGH", "AUTH_004"),
            "MFA_SUCCESS": ("SUCCESS", "LOW", "AUTH_005"),
            "INPUT_REJECT": ("WARNING", "HIGH", "AUTH_006"),
            "USER_REGISTER": ("SUCCESS", "LOW", "AUTH_007"),
            "USER_REGISTER_FAIL": ("FAILURE", "MEDIUM", "AUTH_008"),
            "PASSWORD_CHANGE": ("SUCCESS", "LOW", "AUTH_009"),
            "ACCOUNT_UNLOCK": ("SUCCESS", "MEDIUM", "AUTH_010"),
            "MFA_DISABLE": ("WARNING", "MEDIUM", "AUTH_011"),
            "MFA_DISABLE_FAIL": ("FAILURE", "HIGH", "AUTH_012"),
            "ACCOUNT_LOCKED_ACTIVE": ("WARNING", "MEDIUM", "AUTH_013"),
            "PASSWORD_CHANGE_CANCEL": ("INFO", "LOW", "AUTH_014"),
            "ERROR": ("FAILURE", "HIGH", "AUTH_999"),
    }

    default_status, severity, event_id = event_map.get(
        event, ("INFO", "LOW", "AUTH_000")
    )

    log = {
        "_time": datetime.datetime.now().isoformat(),
        "event": event,
        "event_id": event_id,
        "user": user,
        "src_ip": src_ip or generate_ip(),
        "status": status or default_status,
        "severity": severity,
        "details": details or "",
    }

    with open(AUTH_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(log) + "\n")
