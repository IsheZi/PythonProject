import bcrypt
import os

USER_DATA_FILE = "users.txt"
def password_strength(password):
    score = 0
    length = len(password)

    upper_case = any(c.isupper() for c in password)
    lower_case = any(c.islower() for c in password)
    special = any(c in string.punctuation for c in password)
    digits = any(c.isdigit() for c in password)

    characters = [upper_case, lower_case, special, digits]

    if length > 8:
        score += 1
    if length > 12:
        score += 1
    if length > 17:
        score += 1
    if length > 20:
        score += 1

    score += sum(characters) - 1

    if score < 4:
        return "Weak", score
    elif score == 4:
        return "Okay", score
    elif 4 < score < 6:
        return "Good", score
    else:
        return "Strong", score

def hash_password(plain_text_password: str) -> str:
    # Encode password to bytes
    password_bytes = plain_text_password.encode('utf-8')
    # Generate salt and hash
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    # Decode back to string for storage
    return hashed_password.decode('utf-8')

def verify_password(plain_text_password: str, hashed_password: str) -> bool:
    password_bytes = plain_text_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

def user_exists(username: str) -> bool:
    if not os.path.exists(USER_DATA_FILE):
        return False
    with open(USER_DATA_FILE, "r") as f:
        for line in f:
            user, _ = line.strip().split(",", 1)
            if user == username:
                return True
    return False

def register_user(username: str, password: str) -> bool:
    if user_exists(username):
        print(f"Error: Username '{username}' already exists.")
        return False
    hashed_password = hash_password(password)
    with open(USER_DATA_FILE, "a") as f:
        f.write(f"{username},{hashed_password}\n")
    print(f"Success: User '{username}' registered successfully!")
    return True

def login_user(username: str, password: str) -> bool:
    if not os.path.exists(USER_DATA_FILE):
        print("Error: No users registered yet.")
        return False
    with open(USER_DATA_FILE, "r") as f:
        for line in f:
            user, stored_hash = line.strip().split(",", 1)
            if user == username:
                if verify_password(password, stored_hash):
                    print(f"Success: Welcome, {username}!")
                    return True
                else:
                    print("Error: Invalid password.")
                    return False
    print("Error: Username not found.")
    return False
def display_menu():
    print("\n" + "="*50)
    print(" MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print(" Secure Authentication System")
    print("="*50)
    print("\n [1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-"*50)

def main():
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
            register_user(username, password)
        elif choice == '2':
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()
            login_user(username, password)
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Error: Invalid option.")

if __name__ == "__main__":
    main()
