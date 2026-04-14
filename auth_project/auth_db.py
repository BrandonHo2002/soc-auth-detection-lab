import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "users.db")


def db_connect():
    return sqlite3.connect(DB_PATH)


def get_user(username):
    with db_connect() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
        SELECT

        id,
        username,
        password,
        failed_attempts,
        locked,
        lockout_until,
        role,
        mfa_secret

        from users WHERE username = ?
        """,
            (username,),
        )

        user = cursor.fetchone()
    return dict(user) if user else None


def update_user_field(username, field, value):
    if field not in {
        "failed_attempts",
        "locked",
        "lockout_until",
        "role",
        "mfa_secret",
    }:
        raise ValueError("Invalid field update")
    with db_connect() as conn:
        cursor = conn.cursor()
        cursor.execute(
            f"UPDATE users SET {field} = ? WHERE username = ?", (value, username)
        )
        conn.commit()


def create_user_record(username, password_hash, role="user"):
    with db_connect() as conn:
        cursor = conn.cursor()
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
            (username, password_hash, role),
        )
        conn.commit()
        return cursor.lastrowid
