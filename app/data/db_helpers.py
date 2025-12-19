import sqlite3
import csv
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[2] / 'DATA' / 'intelligence_platform.db'

def connect_database(db_path: Path = DB_PATH):
    """Connect to SQLite (creates DATA folder and DB file if missing)."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(str(db_path))

def ensure_tables(conn):
    """Create all required tables if they don't exist."""
    cur = conn.cursor()

    # users
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # cyber_incidents
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cyber_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            incident_type TEXT,
            severity TEXT,
            status TEXT,
            description TEXT,
            reported_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # datasets_metadata
    cur.execute("""
        CREATE TABLE IF NOT EXISTS datasets_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dataset_name TEXT NOT NULL,
            category TEXT,
            source TEXT,
            last_updated TEXT,
            record_count INTEGER,
            file_size_mb REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # it_tickets
    cur.execute("""
        CREATE TABLE IF NOT EXISTS it_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT UNIQUE NOT NULL,
            priority TEXT,
            status TEXT,
            category TEXT,
            subject TEXT NOT NULL,
            description TEXT,
            created_date TEXT,
            resolved_date TEXT,
            assigned_to TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()

def migrate_users_from_file(filepath: Path = DB_PATH.parent / 'users.txt') -> int:
    """Migrate Week 7 users from users.txt into the SQLite users table."""
    inserted = 0
    if not filepath.exists():
        return 0

    conn = connect_database()
    cur = conn.cursor()

    with filepath.open('r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue

            username = row[0].strip()
            password_hash = (row[1].strip() if len(row) > 1 else '')
            role = (row[2].strip() if len(row) > 2 else 'user')

            if not username or not password_hash:
                continue

            try:
                cur.execute(
                    'INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                    (username, password_hash, role),
                )
                if cur.rowcount and cur.rowcount > 0:
                    inserted += 1
            except Exception:
                pass

    conn.commit()
    conn.close()
    return inserted

def seed_admin(conn):
    """Insert a default admin user if not present."""
    cur = conn.cursor()
    cur.execute("""
        INSERT OR IGNORE INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
    """, ("admin", "admin123", "admin"))
    conn.commit()