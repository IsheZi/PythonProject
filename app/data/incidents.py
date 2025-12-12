import pandas as pd
from app.data.db import connect_database

def insert_incident(incident_id: int, timestamp: str, severity: str,
                    category: str, status: str, description: str) -> int:
    """Insert a new cyber incident; returns incident_id (PK)."""
    conn = connect_database()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO cyber_incidents (incident_id, timestamp, severity, category, status, description)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (incident_id, timestamp, severity, category, status, description))
    conn.commit()
    conn.close()
    return incident_id

def get_all_incidents_df():
    """Return all incidents as a pandas DataFrame."""
    conn = connect_database()
    df = pd.read_sql_query(
        "SELECT * FROM cyber_incidents ORDER BY incident_id DESC",
        conn
    )
    conn.close()
    return df

def update_incident_status(incident_id: int, new_status: str) -> int:
    """Update status; return affected rows."""
    conn = connect_database()
    cur = conn.cursor()
    cur.execute(
        "UPDATE cyber_incidents SET status = ? WHERE incident_id = ?",
        (new_status, incident_id)
    )
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count

def delete_incident(incident_id: int) -> int:
    """Delete incident; return affected rows."""
    conn = connect_database()
    cur = conn.cursor()
    cur.execute("DELETE FROM cyber_incidents WHERE incident_id = ?", (incident_id,))
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count