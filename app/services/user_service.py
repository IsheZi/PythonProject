import bcrypt
import secrets
from pathlib import Path
from app.data.db import connect_database
from app.data.users import get_user_by_username, insert_user

USERS_TXT = Path("DATA") / "users.txt"

# ---------------- Migration ----------------
def migrate_users_from_file() -> int:
    """Migrate users from Week 7 users.txt => users table.
       Expected line format: username,hashed_password[,role]"""
    if not USERS_TXT.exists():
        return 0

    conn = connect_database()
    cur = conn.cursor()
    migrated = 0

    with USERS_TXT.open("r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(",", 2)
            if len(parts) < 2:
                continue
            username = parts[0].strip()
            password_hash = parts[1].strip()
            role = parts[2].strip() if len(parts) == 3 else "user"

            cur.execute("""
                INSERT OR IGNORE INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
            """, (username, password_hash, role))
            migrated += cur.rowcount

    conn.commit()
    conn.close()
    return migrated

# ---------------- Registration ----------------
def register_user(username: str, password: str, role: str = "user") -> tuple[bool, str]:
    """Register a new user with bcrypt hashing."""
    if get_user_by_username(username):
        return False, f"Username '{username}' already exists."

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    insert_user(username, password_hash, role)
    return True, f"User '{username}' registered successfully!"

# ---------------- Login ----------------
def login_user(username: str, password: str) -> tuple[bool, str]:
    """Authenticate user against stored bcrypt hash."""
    user = get_user_by_username(username)
    if not user:
        return False, "Username not found."

    stored_hash = user[2]  # password_hash column
    if bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
        token = create_session_db(username)
        return True, f"Login successful. Session token: {token}"
    return False, "Invalid password."

# ---------------- Session Management ----------------
def create_session_db(username: str) -> str:
    """Create a session token and store it in the database."""
    token = secrets.token_hex(16)
    conn = connect_database()
    cur = conn.cursor()
    # Ensure sessions table exists
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            token TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        INSERT INTO sessions (username, token) VALUES (?, ?)
    """, (username, token))
    conn.commit()
    conn.close()
    return token