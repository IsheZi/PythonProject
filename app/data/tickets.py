import pandas as pd
from app.data.db import connect_database

def insert_ticket(ticket_id: int, priority: str, description: str, status: str,
                  assigned_to: str, created_at: str, resolution_time_hours: int) -> int:
    """Insert IT ticket; returns ticket_id (PK)."""
    conn = connect_database()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO it_tickets (ticket_id, priority, description, status, assigned_to, created_at, resolution_time_hours)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (ticket_id, priority, description, status, assigned_to, created_at, resolution_time_hours))
    conn.commit()
    conn.close()
    return ticket_id

def get_all_tickets_df():
    """Return all tickets as DataFrame."""
    conn = connect_database()
    df = pd.read_sql_query(
        "SELECT * FROM it_tickets ORDER BY ticket_id ASC",
        conn
    )
    conn.close()
    return df

def update_ticket_status(ticket_id: int, new_status: str) -> int:
    """Update ticket status; return affected rows."""
    conn = connect_database()
    cur = conn.cursor()
    cur.execute(
        "UPDATE it_tickets SET status = ? WHERE ticket_id = ?",
        (new_status, ticket_id)
    )
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count

def delete_ticket(ticket_id: int) -> int:
    """Delete ticket; return affected rows."""
    conn = connect_database()
    cur = conn.cursor()
    cur.execute("DELETE FROM it_tickets WHERE ticket_id = ?", (ticket_id,))
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count