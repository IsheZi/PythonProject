import bcrypt
import os
import string
import time
import secrets

# File paths for storing user data, lockout info, and sessions
USER_DATA_FILE = "users.txt"
LOCKOUT_FILE = "lockout.txt"
SESSION_FILE = "sessions.txt"

# ---------------- Password Strength ----------------
def password_strength(password: str):
    """
    Evaluate the strength of a password based on length and character variety.
    Returns a tuple (strength_label, score).
    """
    score = 0
    length = len(password)

    # Check for character types
    upper_case = any(c.isupper() for c in password)
    lower_case = any(c.islower() for c in password)
    special = any(c in string.punctuation for c in password)
    digits = any(c.isdigit() for c in password)

    characters = [upper_case, lower_case, special, digits]

    # Add points for length
    if length > 8: score += 1
    if length > 12: score += 1
    if length > 17: score += 1
    if length > 20: score += 1

    # Add points for character variety
    score += sum(characters) - 1

    # Return strength label
    if score < 4:
        return "Weak", score
    elif score == 4:
        return "Okay", score
    elif 4 < score < 6:
        return "Good", score
    else:
        return "Strong", score

# ---------------- Hashing & Verification ----------------
def hash_password(plain_text_password: str) -> str:
    """Hash a plaintext password using bcrypt with automatic salt."""
    password_bytes = plain_text_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password.decode('utf-8')

def verify_password(plain_text_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    password_bytes = plain_text_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

# ---------------- User Management ----------------
def user_exists(username: str) -> bool:
    """Check if a username already exists in the user database."""
    if not os.path.exists(USER_DATA_FILE):
        return False
    with open(USER_DATA_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if parts[0] == username:
                return True
    return False

def register_user(username: str, password: str, role: str = "user") -> bool:
    """Register a new user with a role."""
    if user_exists(username):
        print(f"Error: Username '{username}' already exists.")
        return False
    hashed_password = hash_password(password)
    with open(USER_DATA_FILE, "a") as f:
        f.write(f"{username},{hashed_password},{role}\n")
    print(f"Success: User '{username}' registered with role '{role}'!")
    return True

# ---------------- Account Lockout ----------------
def is_locked(username: str) -> bool:
    """Check if a user account is locked (5 minutes)."""
    if not os.path.exists(LOCKOUT_FILE):
        return False
    with open(LOCKOUT_FILE, "r") as f:
        for line in f:
            user, timestamp = line.strip().split(",")
            if user == username:
                if time.time() - float(timestamp) < 300:
                    return True
    return False

def lock_account(username: str):
    """Lock a user account after failed attempts."""
    with open(LOCKOUT_FILE, "a") as f:
        f.write(f"{username},{time.time()}\n")
    print(f"Account '{username}' locked for 5 minutes due to failed attempts.")

# ---------------- Login ----------------
def login_user(username: str, password: str):
    """
    Authenticate a user and return their role if successful.
    Implements account lockout after 3 failed attempts.
    """
    if not os.path.exists(USER_DATA_FILE):
        print("Error: No users registered yet.")
        return False

    if is_locked(username):
        print("Error: Account is locked. Try again later.")
        return False

    failed_attempts = 0
    with open(USER_DATA_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) == 3:
                user, stored_hash, role = parts
            else:
                user, stored_hash = parts
                role = "user"

            if user == username:
                if verify_password(password, stored_hash):
                    print(f"Success: Welcome, {username}! Your role is '{role}'.")
                    token = create_session(username)
                    print(f"Session token: {token}")
                    return role
                else:
                    failed_attempts += 1
                    if failed_attempts >= 3:
                        lock_account(username)
                    print("Error: Invalid password.")
                    return False
    print("Error: Username not found.")
    return False

# ---------------- Session Management ----------------
def create_session(username: str) -> str:
    """Create a session token for a logged-in user."""
    token = secrets.token_hex(16)
    with open(SESSION_FILE, "a") as f:
        f.write(f"{username},{token},{time.time()}\n")
    return token

# ---------------- Admin Functions ----------------
def view_all_users():
    """Admin-only function to list all registered users and roles."""
    if not os.path.exists(USER_DATA_FILE):
        print("No users registered yet.")
        return
    print("\n--- Registered Users ---")
    with open(USER_DATA_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) == 3:
                user, _, role = parts
            else:
                user, _ = parts
                role = "user"
            print(f"Username: {user}, Role: {role}")
    print("------------------------")

# ---------------- Menus ----------------
def display_menu():
    """Display the main menu options."""
    print("\n" + "="*50)
    print(" MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print(" Secure Authentication System")
    print("="*50)
    print("\n [1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-"*50)

def display_admin_menu():
    """Display extra options for admins."""
    print("\n--- ADMIN MENU ---")
    print("[A1] View all users")
    print("[A2] Logout to main menu")
    print("------------------")

def main():
    """Main program loop for user interaction."""
    print("\nWelcome to the Week 7 Authentication System!")
    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()
        if choice == '1':
            username = input("Enter a username: ").strip()
            password = input("Enter a password: ").strip()
            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue
            role = input("Enter role (user/admin/analyst): ").strip().lower()
            if role not in ["user", "admin", "analyst"]:
                role = "user"
            register_user(username, password, role)
        elif choice == '2':
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()
            role = login_user(username, password)
            if role == "admin":
                # Admin gets extra menu
                while True:
                    display_admin_menu()
                    admin_choice = input("Select an admin option: ").strip().lower()
                    if admin_choice == "a1":
                        view_all_users()
                    elif admin_choice == "a2":
                        print("Logging out of admin menu...")
                        break
                    else:
                        print("Invalid admin option.")
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Error: Invalid option.")

if __name__ == "__main__":
    main()