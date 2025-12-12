from app.data.db import connect_database

# ---------------- Schema Creation ----------------
def create_all_tables():
    """Create all required tables if they do not exist."""
    conn = connect_database()
    cur = conn.cursor()

    # Users table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Cyber incidents table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cyber_incidents (
        incident_id INTEGER PRIMARY KEY,
        timestamp TEXT,
        severity TEXT,
        category TEXT,
        status TEXT,
        description TEXT
    );
    """)

    # Datasets metadata table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS datasets_metadata (
        dataset_id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        rows INTEGER,
        columns INTEGER,
        uploaded_by TEXT,
        upload_date TEXT
    );
    """)

    # IT tickets table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS it_tickets (
        ticket_id INTEGER PRIMARY KEY,
        priority TEXT,
        description TEXT,
        status TEXT,
        assigned_to TEXT,
        created_at TEXT,
        resolution_time_hours INTEGER
    );
    """)

    # Sessions table (optional, for DB-backed login sessions)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        token TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    conn.close()

# ---------------- Users CRUD ----------------
def get_user_by_username(username: str):
    """Return user row tuple or None."""
    conn = connect_database()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row

def insert_user(username: str, password_hash: str, role: str = "user"):
    """Insert new user."""
    conn = connect_database()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, password_hash, role)
    )
    conn.commit()
    conn.close()

def update_user_role(username: str, new_role: str) -> int:
    """Update user role; return affected rows."""
    conn = connect_database()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET role = ? WHERE username = ?",
        (new_role, username)
    )
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count

def delete_user(username: str) -> int:
    """Delete user; return affected rows."""
    conn = connect_database()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count