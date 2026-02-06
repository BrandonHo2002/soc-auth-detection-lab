import os
import sqlite3

import bcrypt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")
PEPPER_PATH = os.path.join(BASE_DIR, "auth_pepper.txt")

with open(PEPPER_PATH, "r") as f:
    PEPPER = f.read().strip()

username = "admin"
password = "Admin@123"
role = "admin"

hashed = bcrypt.hashpw((password + PEPPER).encode("utf-8"), bcrypt.gensalt())

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute(
    """
    INSERT INTO users (username, password, role, failed_attempts, locked, lockout_until)
    VALUES (?, ?, ?, 0, 0, 0)
    """,
    (username, hashed, role),
)

conn.commit()
conn.close()

print("Successfully created admin account")
