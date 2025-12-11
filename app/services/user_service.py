import bcrypt
from pathlib import Path
from app.data.db import connect_database

def migrate_users_from_file(filepath=Path("DATA") / "users.txt"):
    """
    Migrate users from users.txt to the database.
    - Each line in users.txt has the format: username,password_hash,role
    - Uses INSERT OR IGNORE to avoid duplicates.
    """
    conn = connect_database()
    cursor = conn.cursor()
    migrated_count = 0

    if not filepath.exists():
        print(f"No users.txt found at {filepath}")
        return 0

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) != 3:
                continue
            username, password_hash, role = parts
            cursor.execute(
                "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role)
            )
            migrated_count += 1

    conn.commit()
    conn.close()
    print(f"Migrated {migrated_count} users from file")
    return migrated_count


def register_user(username, password, role="user"):
    """
    Register a new user with bcrypt hashing.
    - Checks if username already exists.
    - Hashes password securely before storing.
    """
    conn = connect_database()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return False, f"Username '{username}' already exists."

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    cursor.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, password_hash, role)
    )
    conn.commit()
    conn.close()
    return True, f"User '{username}' registered successfully."


def login_user(username, password):
    """
    Authenticate user by verifying password against stored hash.
    - Retrieves stored hash from database.
    - Compares with bcrypt.checkpw().
    """
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return False, "User not found."

    stored_hash = user[2]
    if bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
        return True, "Login successful!"
    return False, "Incorrect password."