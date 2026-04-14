import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "users.db")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password BLOB,
    failed_attempts INTEGER DEFAULT 0,
    locked INTEGER DEFAULT 0,
    lockout_until INTEGER DEFAULT 0,
    role TEXT DEFAULT 'user',
    mfa_secret TEXT
)
""")

conn.commit()
conn.close()

print("Database initialized successfully.")
