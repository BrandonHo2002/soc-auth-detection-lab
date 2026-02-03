import sqlite3

conn = sqlite3.connect("auth.db")
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
print("Database initialize succesfully.")
