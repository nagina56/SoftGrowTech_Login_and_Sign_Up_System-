"""
╔══════════════════════════════════════════════════════════════╗
║           🔐 LOGIN & SIGNUP SYSTEM — Python Project 2        ║
║        By: Professional Python Developer                     ║
║        Features: Hashed passwords, JSON storage, Sessions   ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import os
import hashlib
import secrets
import re
from datetime import datetime


# ─────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────
DB_FILE = "users.json"          # Where all users are saved
SESSION_FILE = "session.json"   # Who is currently logged in


# ─────────────────────────────────────────────
#  UTILITY FUNCTIONS
# ─────────────────────────────────────────────

def clear():
    """Clear the terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


def divider(char="─", length=50):
    print(char * length)


def banner():
    clear()
    print("""
╔══════════════════════════════════════════════╗
║          🔐 Login and Sign Up System         ║
║       Python Project 2 — Authentication      ║
╚══════════════════════════════════════════════╝
""")


# ─────────────────────────────────────────────
#  DATABASE FUNCTIONS (JSON Storage)
# ─────────────────────────────────────────────

def load_users() -> dict:
    """Load all users from JSON file. Returns empty dict if file missing."""
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)


def save_users(users: dict):
    """Save all users back to JSON file."""
    with open(DB_FILE, "w") as f:
        json.dump(users, f, indent=4)


# ─────────────────────────────────────────────
#  PASSWORD SECURITY
# ─────────────────────────────────────────────

def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """
    Hash a password using SHA-256 + salt.
    
    What is hashing?
    → Hashing matlab: password ko ek aisi string mein badalna
      jo wapas nahi ki ja sakti. Jaise ek taala jo khulta nahi.
    
    What is salt?
    → Salt ek random string hai jo har user ka alag hota hai.
      Isse do same passwords ka hash bhi alag hoga!
    
    Returns: (hashed_password, salt)
    """
    if salt is None:
        salt = secrets.token_hex(16)   # 16 random bytes = 32 hex chars
    combined = salt + password          # salt + password milao
    hashed = hashlib.sha256(combined.encode()).hexdigest()
    return hashed, salt


def verify_password(input_password: str, stored_hash: str, salt: str) -> bool:
    """Check if entered password matches stored hash."""
    hashed, _ = hash_password(input_password, salt)
    return hashed == stored_hash


# ─────────────────────────────────────────────
#  VALIDATION FUNCTIONS
# ─────────────────────────────────────────────

def validate_username(username: str, users: dict) -> tuple[bool, str]:
    """
    Check if username is valid:
    - 3 to 20 characters
    - Only letters, numbers, underscores
    - Must not already exist
    """
    if len(username) < 3:
        return False, "❌ Username must be at least 3 characters long."
    if len(username) > 20:
        return False, "❌ Username cannot exceed 20 characters."
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "❌ Only letters, numbers, and underscores (_) allowed."
    if username.lower() in users:
        return False, "❌ Username already taken. Please choose another."
    return True, "✅ Username is valid."


def validate_password(password: str) -> tuple[bool, str]:
    """
    Check if password is strong:
    - At least 8 characters
    - At least one uppercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "❌ Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return False, "❌ Password must include at least one uppercase letter (A-Z)."
    if not re.search(r"[0-9]", password):
        return False, "❌ Password must include at least one number (0-9)."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        return False, "❌ Password must include at least one special character (!@#$ etc)."
    return True, "✅ Strong password!"


def validate_email(email: str) -> tuple[bool, str]:
    """Basic email format check."""
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w{2,}$"
    if re.match(pattern, email):
        return True, "✅ Valid email."
    return False, "❌ Invalid email format. Example: name@gmail.com"


# ─────────────────────────────────────────────
#  SESSION MANAGEMENT
# ─────────────────────────────────────────────

def save_session(username: str):
    """Save logged-in user to session file."""
    with open(SESSION_FILE, "w") as f:
        json.dump({"logged_in_user": username, "login_time": str(datetime.now())}, f)


def load_session() -> str | None:
    """Check if someone is already logged in."""
    if not os.path.exists(SESSION_FILE):
        return None
    with open(SESSION_FILE, "r") as f:
        data = json.load(f)
    return data.get("logged_in_user")


def clear_session():
    """Log out by deleting session file."""
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)


# ─────────────────────────────────────────────
#  SIGNUP FEATURE
# ─────────────────────────────────────────────

def signup():
    banner()
    print("         📝  CREATE NEW ACCOUNT\n")
    divider()

    users = load_users()

    # ── Step 1: Username ──
    while True:
        username = input("\n  Enter username : ").strip()
        valid, msg = validate_username(username, users)
        print(f"  {msg}")
        if valid:
            break

    # ── Step 2: Email ──
    while True:
        email = input("\n  Enter email    : ").strip()
        valid, msg = validate_email(email)
        print(f"  {msg}")
        if valid:
            break

    # ── Step 3: Password ──
    print("\n  Password rules:")
    print("  • At least 8 characters")
    print("  • One uppercase letter (A-Z)")
    print("  • One number (0-9)")
    print("  • One special character (!@#$ etc)\n")

    while True:
        password = input("  Enter password : ").strip()
        valid, msg = validate_password(password)
        print(f"  {msg}")
        if valid:
            break

    # ── Step 4: Confirm Password ──
    while True:
        confirm = input("\n  Confirm password : ").strip()
        if confirm == password:
            print("  ✅ Passwords match!")
            break
        print("  ❌ Passwords do not match. Try again.")

    # ── Save User ──
    hashed_pw, salt = hash_password(password)

    users[username.lower()] = {
        "username"     : username,
        "email"        : email,
        "password_hash": hashed_pw,
        "salt"         : salt,
        "created_at"   : str(datetime.now()),
        "login_count"  : 0,
        "last_login"   : None
    }

    save_users(users)

    divider()
    print(f"\n  🎉 Account created for  '{username}'!")
    print("  You can now log in.\n")
    input("  Press Enter to continue...")


# ─────────────────────────────────────────────
#  LOGIN FEATURE
# ─────────────────────────────────────────────

def login():
    banner()
    print("         🔑  LOGIN TO YOUR ACCOUNT\n")
    divider()

    users = load_users()
    max_attempts = 3

    for attempt in range(1, max_attempts + 1):
        print(f"\n  Attempt {attempt} of {max_attempts}")
        username = input("  Username : ").strip().lower()
        password = input("  Password : ").strip()

        # Check username exists
        if username not in users:
            print("\n  ❌ No account found with that username.")
            continue

        user = users[username]

        # Verify password
        if verify_password(password, user["password_hash"], user["salt"]):
            # Update login stats
            user["login_count"] += 1
            user["last_login"] = str(datetime.now())
            save_users(users)

            # Save session
            save_session(username)

            divider()
            print(f"\n  ✅ Welcome back, {user['username']}!")
            print(f"  📅 Last login  : {user['last_login']}")
            print(f"  🔢 Login count : {user['login_count']}")
            print()
            input("  Press Enter to go to dashboard...")
            return True
        else:
            remaining = max_attempts - attempt
            print(f"\n  ❌ Wrong password. {remaining} attempt(s) left.")

    # All attempts exhausted
    divider()
    print("\n  🚫 Too many failed attempts. Access denied.\n")
    input("  Press Enter to return to menu...")
    return False


# ─────────────────────────────────────────────
#  USER DASHBOARD (After Login)
# ─────────────────────────────────────────────

def dashboard(username: str):
    users = load_users()
    user = users.get(username, {})

    while True:
        banner()
        print(f"  👤  Logged in as: {user.get('username', username)}")
        divider()
        print("\n  DASHBOARD MENU\n")
        print("  [1] View My Profile")
        print("  [2] Change Password")
        print("  [3] Logout")
        divider()

        choice = input("\n  Choose: ").strip()

        if choice == "1":
            view_profile(user)
        elif choice == "2":
            change_password(username, users)
            users = load_users()
            user = users.get(username, {})
        elif choice == "3":
            clear_session()
            print("\n  👋 Logged out successfully!\n")
            input("  Press Enter to continue...")
            break
        else:
            print("  ⚠️  Invalid choice.")
            input("  Press Enter...")


def view_profile(user: dict):
    banner()
    print("  👤  MY PROFILE\n")
    divider()
    print(f"  Username    : {user.get('username')}")
    print(f"  Email       : {user.get('email')}")
    print(f"  Joined      : {user.get('created_at', 'N/A')[:19]}")
    print(f"  Last Login  : {user.get('last_login', 'N/A')}")
    print(f"  Login Count : {user.get('login_count', 0)}")
    divider()
    input("\n  Press Enter to go back...")


def change_password(username: str, users: dict):
    banner()
    print("  🔒  CHANGE PASSWORD\n")
    divider()

    user = users[username]
    old_pw = input("\n  Enter current password : ").strip()

    if not verify_password(old_pw, user["password_hash"], user["salt"]):
        print("\n  ❌ Wrong current password.")
        input("  Press Enter...")
        return

    print("\n  Enter new password:")
    while True:
        new_pw = input("  New password : ").strip()
        valid, msg = validate_password(new_pw)
        print(f"  {msg}")
        if valid:
            break

    confirm = input("  Confirm new password : ").strip()
    if confirm != new_pw:
        print("\n  ❌ Passwords don't match.")
        input("  Press Enter...")
        return

    hashed, salt = hash_password(new_pw)
    users[username]["password_hash"] = hashed
    users[username]["salt"] = salt
    save_users(users)

    print("\n  ✅ Password changed successfully!")
    input("  Press Enter...")


# ─────────────────────────────────────────────
#  ADMIN: VIEW ALL USERS
# ─────────────────────────────────────────────

def view_all_users():
    banner()
    print("  🗄️   ALL REGISTERED USERS\n")
    divider()

    users = load_users()
    if not users:
        print("  No users registered yet.")
    else:
        for i, (key, u) in enumerate(users.items(), 1):
            print(f"\n  [{i}] {u['username']}")
            print(f"      Email      : {u['email']}")
            print(f"      Joined     : {u['created_at'][:19]}")
            print(f"      Last Login : {u.get('last_login') or 'Never'}")
            print(f"      Logins     : {u['login_count']}")
    divider()
    input("\n  Press Enter to return...")


# ─────────────────────────────────────────────
#  MAIN MENU
# ─────────────────────────────────────────────

def main():
    # Check for existing session
    logged_user = load_session()
    if logged_user:
        banner()
        print(f"  🔄 Resuming session for: {logged_user}")
        print("  [1] Continue as this user")
        print("  [2] Log out and go to main menu")
        choice = input("\n  Choose: ").strip()
        if choice == "1":
            dashboard(logged_user)
        else:
            clear_session()

    # Main loop
    while True:
        banner()
        print("  MAIN MENU\n")
        print("  [1] 📝  Sign Up   — Create new account")
        print("  [2] 🔑  Login    — Access your account")
        print("  [3] 🗄️   Admin    — View all users")
        print("  [4] ❌  Exit")
        divider()

        choice = input("\n  Choose an option: ").strip()

        if choice == "1":
            signup()
        elif choice == "2":
            success = login()
            if success:
                session_user = load_session()
                if session_user:
                    dashboard(session_user)
        elif choice == "3":
            view_all_users()
        elif choice == "4":
            banner()
            print("  👋 Goodbye! Stay secure.\n")
            break
        else:
            print("\n  ⚠️  Invalid option. Please try again.")
            input("  Press Enter...")


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    main()