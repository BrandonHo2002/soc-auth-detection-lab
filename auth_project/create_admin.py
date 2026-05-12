import os
import sqlite3
import bcrypt
import getpass
import sys
from logger import log_event

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")
PEPPER_PATH = os.path.join(BASE_DIR, "..", "config", "auth_pepper.txt")

try:
    with open(PEPPER_PATH, "r", encoding="utf-8") as f:
        PEPPER = f.read().strip()
except FileNotFoundError:
    print("Error: Pepper file not found.")
    sys.exit(1)

def main():
    username = "admin"
    password = getpass.getpass("Enter admin password: ")
    role = "admin"

    hashed = bcrypt.hashpw((password + PEPPER).encode("utf-8"), bcrypt.gensalt())

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Check if admin exists
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            print("Admin already exists.")
        else:
            cursor.execute(
                """
                INSERT INTO users (
                    username,
                    password,
                    role,
                    failed_attempts,
                    locked,
                    lockout_until,
                    mfa_secret
                )
                VALUES (?, ?, ?, 0, 0, 0, NULL)
                """,
                (username, hashed, role),
            )
            conn.commit()
            log_event("USER_REGISTER", username, details="admin_created")
            print("your username is: admin")
            print("Successfully created admin account")


if __name__ == "__main__":
    main()
