import sqlite3
from pathlib import Path

DB_PATH = Path("DATA") / "intelligence_platform.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def connect_database(db_path=DB_PATH):
    """Connect to SQLite database.
     Creates the file if it doesn’t exist.
    """
    return sqlite3.connect(str(db_path))