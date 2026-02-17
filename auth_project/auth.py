import datetime
import getpass
import os
import re
import sqlite3
import sys
import time

import bcrypt
import pyotp
import qrcode
from auth_db import create_user_record, db_connect, get_user, update_user_field

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
AUTH_LOG = os.path.join(LOG_DIR, "pro_auth.log")

os.makedirs(LOG_DIR, exist_ok=True)


def log_event(message):
    try:
        ts = datetime.datetime.now().isoformat(sep=" ", timespec="seconds")
        with open(AUTH_LOG, "a") as f:
            f.write(f"{ts} - {message}\n")
    except Exception as e:
        print(f"Logging failed: {e}")


def enable_mfa(username):
    record = get_user(username)

    if not record:
        print("User does not exist.")
        return

    mfa_secret = record["mfa_secret"]

    if mfa_secret:
        print("\nMFA is already enabled for this user.")
        print("Current secret is:", format_secret(mfa_secret))
        return

    print("\nChoose MFA setup method:")
    print("1. QR Code (recommended)")
    print("2. Manual secret key")

    choice = input("Select option (1 or 2): ").strip()

    if choice not in {"1", "2"}:
        print("Invalid choice")
        return

    secret = pyotp.random_base32()

    update_user_field(username, "mfa_secret", secret)

    totp = pyotp.TOTP(secret)

    if choice == "1":
        uri = totp.provisioning_uri(name=username, issuer_name="AuthProject")

        img = qrcode.make(uri)
        filename = os.path.join(BASE_DIR, f"{username}_mfa_qr.png")
        img.save(filename)

        print("\nMFA enabled using QR code.")
        print("Scan this QR code with google Authenticator:")
        print(f"Saved as {filename}")

    else:
        print("\nMFA enabled using manual secret.")
        print("Enter this key into Google Authenticator:")
        print(f"your secret key is: {format_secret(secret)}")
    print("\nMFA setup complete")


def disable_mfa(username):
    record = get_user(username)

    if not record:
        print("User not found")
        return
    if record["role"] == "admin":
        print("Admin cannot disable MFA.")
        return

    password = getpass.getpass("Re-enter your password: ")
    peppered = password + PEPPER

    stored = record["password"]
    if isinstance(stored, memoryview):
        stored = stored.tobytes()

    if not bcrypt.checkpw(peppered.encode(), stored):
        print("Password incorrect.")
        log_event(f"[AUTH_PROJECT_MFA_FAIL] MFA disable failed for: {username}")
        return

    update_user_field(username, "mfa_secret", None)
    log_event(f"[AUTH_PROJECT_MFA_DISABLE] MFA disabled for user: {username}")
    print("MFA has been disabled.")


def format_secret(secret):
    return " - ".join(secret[i : i + 4] for i in range(0, len(secret), 4))


def looks_malicious(input_string):
    patterns = [
        r"'",
        r'"',
        r"__",
        r"/\*",
        r"\*/",
        r"\bINSERT\b",
        r"\bAND\b",
        r"\bUNION\b",
        r"\bSELECT\b",
        r"\bOR\b",
        r"\bUPDATE\b",
        r"\bDELETE\b",
        r"\bDROP\b",
        r"\b1=1\b",
    ]

    test = input_string.upper()
    for pattern in patterns:
        if re.search(pattern, test):
            return True
        if not isinstance(input_string, str):
            return True
    return False


def validate_username(username):
    if not isinstance(username, str):
        return False

    username = username.strip()

    if len(username) not in range(4, 21):
        return False
    if not username.isalnum():
        return False

    has_letter = any(c.isalpha() for c in username)
    has_digit = any(c.isdigit() for c in username)

    return has_letter and has_digit


def validate_password(password):
    if not isinstance(password, str):
        return False, "Password must be a string"
    if " " in password:
        return False, "Password cannot contain spaces"
    if len(password) not in range(7, 21):
        return False, "Password must be between 8 to 20 characters long"
    if len(set(password)) == 1:
        return False, "Password cannot be made of a single repeating character"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"

    allowed_symbols = ".@$!%"
    if not any(c in allowed_symbols for c in password):
        return (
            False,
            f"Password must contain at least one special character: {allowed_symbols}",
        )

    return True, None


def load_pepper():
    try:
        pepper_path = os.path.join(BASE_DIR, "auth_pepper.txt")
        with open(pepper_path, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        print("Error: Pepper file missing!")
    except PermissionError:
        print("Error: Permission denied reading auth_pepper.txt")
    except OSError as e:
        print(f"Error reading pepper file: {e}")
    return None


PEPPER = load_pepper()
if not PEPPER:
    print("Fatal error: authentication pepper not loaded.")
    sys.exit(1)


def create_user():
    username = input("enter a new username: ").strip()
    if looks_malicious(username):
        print("Invalid username. Input rejected for security.")
        log_event(
            f"[AUTH_PROJECT_SECURITY_INPUT_REJECT] SQL injection attempt in username field: {username}"
        )
        time.sleep(1)
        return
    if not validate_username(username):
        print(
            "Invalid username! Username must be between 4-20 characters long with at least a letter and number"
        )
        time.sleep(1)
        return
    password = getpass.getpass("enter a new password: ")
    confirm = getpass.getpass("Confirm your password: ")
    if password != confirm:
        print("password do not match")
        time.sleep(1)
        return
    valid, msg = validate_password(password)
    if not valid:
        print(msg)
        time.sleep(1)
        return

    peppered = password + PEPPER
    hashed = bcrypt.hashpw(peppered.encode("utf-8"), bcrypt.gensalt())
    try:
        create_user_record(username, hashed)
        print("User created successfully!")
        log_event(f"[AUTH_PROJECT_USER_REGISTER] New user registered: {username}")
    except sqlite3.IntegrityError:
        print("Username already exists")
        log_event(
            f"[AUTH_PROJECT_USER_REGISTER_FAIL] registration failed for: {username}"
        )
        time.sleep(1)


def login_user():
    try:
        username = input("Enter username: ").strip()
        password = getpass.getpass("Enter password: ")
        if looks_malicious(username) or looks_malicious(password):
            print("Invalid input.")
            log_event(
                f"[AUTH_PROJECT_SECURITY_INPUT_REJECT] malicious input detected for: {username}"
            )
            return None, None

        record = get_user(username)

        if not record:
            print("User not found.")
            log_event(
                f"[AUTH_PROJECT_LOGIN_FAIL] Unknown user login attempt: {username}"
            )
            return None, None

        stored_password = record["password"]
        failed_attempts = record["failed_attempts"]
        locked = record["locked"]
        lockout_until = record["lockout_until"]
        role = record["role"]
        mfa_secret = record["mfa_secret"]

        if isinstance(stored_password, memoryview):
            stored_password = stored_password.tobytes()
        elif isinstance(stored_password, str):
            stored_password = stored_password.encode("utf-8")

        current_time = int(time.time())

        if locked == 1:
            if current_time < lockout_until:
                cooldown_left = lockout_until - current_time
                print(f"try again in {cooldown_left} seconds.")
                log_event(
                    f"[AUTH_PROJECT_ACCOUNT_LOCKED_ACTIVE] Account locked; {username}"
                )
                return None, None
            else:
                update_user_field(username, "locked", 0)
                update_user_field(username, "failed_attempts", 0)
                update_user_field(username, "lockout_until", 0)
                failed_attempts = 0

        peppered = password + PEPPER
        password_correct = bcrypt.checkpw(peppered.encode("utf-8"), stored_password)

        if not password_correct:
            failed_attempts += 1
            update_user_field(username, "failed_attempts", failed_attempts)
            print("Incorrect password")
            log_event(f"[AUTH_PROJECT_LOGIN_FAIL] Login failed for: {username}")
            if failed_attempts >= 3:
                lock_duration = 300
                new_lockout = current_time + lock_duration
                update_user_field(username, "locked", 1)
                update_user_field(username, "lockout_until", new_lockout)
                print(
                    f"Too many failed attempts. Account locked for: {lock_duration} seconds."
                )
                log_event(f"[AUTH_PROJECT_ACCOUNT_LOCK] Account locked; {username}")
            return None, None

        if role == "admin":
            if not mfa_secret:
                print("Admin accounts must enable MFA before login")
                return None, None
            totp = pyotp.TOTP(mfa_secret)
            code = input("Enter your 6-digit MFA code: ").strip()
            if not code.isdigit() or len(code) != 6:
                print(f"MFA format error for user: {username}")
                return None, None
            if not totp.verify(code, valid_window=1):
                log_event(f"[AUTH_PROJECT_MFA_FAIL] MFA failed for: {username}")
                print("Incorrect MFA code")
                time.sleep(1)
                return None, None
            print("MFA verified")
        elif mfa_secret:
            totp = pyotp.TOTP(mfa_secret)
            code = input("Enter your 6-digit MFA code: ").strip()

            if totp.verify(code, valid_window=1):
                print("MFA verified.")
            else:
                print("Incorrect MFA code.")
                log_event(f"[AUTH_PROJECT_MFA_FAIL] MFA failed for: {username}")
                return None, None

        update_user_field(username, "failed_attempts", 0)
        update_user_field(username, "locked", 0)
        update_user_field(username, "lockout_until", 0)

        log_event(f"[AUTH_PROJECT_LOGIN_SUCCESS] Login successful for: {username}")

        if role == "admin":
            return ("admin", username)
        else:
            return ("user", username)

    except Exception as e:
        print(f"[DEBUG] login error: {e}")
        raise


def update_password(username):
    print("\n===Update Password===")

    oldpass = getpass.getpass("Enter old password: ")

    record = get_user(username)

    if not record:
        print("User not found.")
        return

    password_hash = record["password"]

    if isinstance(password_hash, memoryview):
        password_hash = password_hash.tobytes()
    elif isinstance(password_hash, str):
        password_hash = password_hash.encode("utf-8")

    peppered = oldpass + PEPPER
    password_correct = bcrypt.checkpw(peppered.encode("utf-8"), password_hash)

    if not password_correct:
        print("Incorrect old password")
        return

    newpass = getpass.getpass("Enter new password (leave blank to cancel): ")

    if not newpass:
        log_event(
            f"[AUTH_PROJECT_PASSWORD_CHANGE_CANCEL] Password change cancelled for: {username}"
        )
        return

    valid, msg = validate_password(newpass)
    if not valid:
        print(msg)
        return

    confirm = getpass.getpass("Confirm new password")

    if newpass != confirm:
        print("Password do not match.")
        return

    peppered_new = newpass + PEPPER
    newpassword = bcrypt.hashpw(peppered_new.encode("utf-8"), bcrypt.gensalt())

    try:
        with db_connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password = ? WHERE username = ?",
                (newpassword, username),
            )
            conn.commit()

            print("Password successfully updated.")
            log_event(
                f"[AUTH_PROJECT_PASSWORD_CHANGE] Password changed for: {username}"
            )
    except Exception as e:
        log_event(f"[ERROR] update_password failed for {username}: {e}")
        print("password update failed")


def unlock_user():
    print("\n===Which user you want to unlock===")
    target_user = input("Enter the username to unlock: ")

    if looks_malicious(target_user):
        print("Invalid input.")
        log_event(f"SQL injection attempt during unlock_user: {target_user}")
        return

    user = get_user(target_user)

    if not user:
        print(f"{target_user} does not exist.")
        return

    if not user["locked"]:
        print(f"{target_user} account is not locked")
        return

    update_user_field(target_user, "failed_attempts", 0)
    update_user_field(target_user, "locked", 0)
    update_user_field(target_user, "lockout_until", 0)

    print(f"{target_user}'s account has been unlocked.")
    log_event(f"[AUTH_PROJECT_ACCOUNT_UNLOCK] Account unlocked for: {target_user}")


def login_page(username):
    while True:
        print(f"\n=== User page ({username}) ===")
        print("1. Change Password")
        print("2. Return to Login")
        print("3. Exit")
        print("4. disable MFA")
        choice = input("Enter an option: ")

        if choice == "1":
            update_password(username)
        elif choice == "2":
            return "logout"
        elif choice == "3":
            return "exit"
        elif choice == "4":
            disable_mfa(username)
        else:
            print("Invalid option. Try again.")


def admin_page(username):
    while True:
        print(f"\n=== Admin page ({username}) ===")
        print("1. Register new User")
        print("2. Change Password")
        print("3. Unlock User")
        print("4. Return to Login")
        print("5. Exit")
        choice = input("Enter an option: ")

        if choice == "1":
            create_user()
        elif choice == "2":
            update_password(username)
        elif choice == "3":
            unlock_user()
        elif choice == "4":
            return "logout"
        elif choice == "5":
            print("Goodbye!")
            return "exit"
        else:
            print("Invalid option. try again.")


def main():
    while True:
        print("\n=== Authentication System ===")
        print("\n===Login Page ===")
        print("1. Register new user")
        print("2. Login")
        print("3. Exit")
        print("4. Enable MFA")
        choice = input("Enter an option: ")

        if choice == "1":
            create_user()
        elif choice == "2":
            role, username = login_user()
            if role is None:
                continue

            if role == "admin":
                result = admin_page(username)
            else:
                result = login_page(username)

            if result == "logout":
                continue
            elif result == "exit":
                sys.exit()
        elif choice == "3":
            print("Goodbye!")
            sys.exit()
        elif choice == "4":
            user = input("Enter your username to enable MFA: ")
            enable_mfa(user)
        else:
            print("Invalid option. Try again")


if __name__ == "__main__":
    main()
