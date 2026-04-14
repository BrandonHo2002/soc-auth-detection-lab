import os
import sqlite3
import bcrypt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "users.db")
PEPPER_PATH = os.path.join(BASE_DIR, "..", "config", "auth_pepper.txt")

with open(PEPPER_PATH, "r") as f:
    PEPPER = f.read().strip()

username = "admin"
password = input("Enter admin password: ")
role = "admin"

hashed = bcrypt.hashpw((password + PEPPER).encode("utf-8"), bcrypt.gensalt())

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Check if admin exists
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
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
    print("Successfully created admin account")

conn.close()
