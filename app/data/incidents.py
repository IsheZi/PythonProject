import pandas as pd
from app.data.db_helpers import connect_database, ensure_tables

def get_all_incidents(conn=None):
    """Return all incidents as a DataFrame."""
    if conn is None:
        conn = connect_database()
    ensure_tables(conn)  # ✅ ensure schema exists
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cyber_incidents ORDER BY id DESC")
    rows = cursor.fetchall()
    df = pd.DataFrame(rows, columns=[desc[0] for desc in cursor.description])
    return df

def insert_incident(conn, date, incident_type, severity, status, description, reported_by):
    """Insert a new incident row."""
    ensure_tables(conn)  # ✅ ensure schema exists
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO cyber_incidents (date, incident_type, severity, status, description, reported_by)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (date, incident_type, severity, status, description, reported_by)
    )
    conn.commit()

def update_incident_status(incident_id: int, new_status: str) -> int:
    """Update status of an incident by ID."""
    conn = connect_database()
    ensure_tables(conn)
    cur = conn.cursor()
    cur.execute(
        "UPDATE cyber_incidents SET status = ? WHERE id = ?",
        (new_status, incident_id)
    )
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count

def delete_incident(incident_id: int) -> int:
    """Delete incident by ID."""
    conn = connect_database()
    ensure_tables(conn)
    cur = conn.cursor()
    cur.execute("DELETE FROM cyber_incidents WHERE id = ?", (incident_id,))
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count