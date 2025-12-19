from app.data.db_helpers import connect_database, ensure_tables

def get_user_by_username(username: str):
    """Return user row tuple or None."""
    conn = connect_database()
    ensure_tables(conn)  # ✅ make sure tables exist
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row

def get_user_role(username: str) -> str:
    conn = connect_database()
    ensure_tables(conn)  # ✅ ensure tables exist
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else "analyst"  # default role if not found

def insert_user(username: str, password_hash: str, role: str = "user"):
    """Insert new user."""
    conn = connect_database()
    ensure_tables(conn)  # ✅ ensure tables exist
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
    ensure_tables(conn)  # ✅ ensure tables exist
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
    ensure_tables(conn)  # ✅ ensure tables exist
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count