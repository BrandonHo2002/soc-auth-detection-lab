import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

def main():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL,
            failed_attempts INTEGER DEFAULT 0 NOT NULL,
            locked INTEGER DEFAULT 0 NOT NULL,
            lockout_until INTEGER DEFAULT 0 NOT NULL,
            role TEXT DEFAULT 'user' CHECK(role IN('user', 'admin')),
            mfa_secret TEXT
        )
        """)

    print("Database initialized successfully.")

if __name__ == "__main__":
    main()
