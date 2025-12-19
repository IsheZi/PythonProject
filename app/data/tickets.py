import pandas as pd
from app.data.db_helpers import connect_database, ensure_tables

def get_all_tickets(conn=None):
    """Return all tickets as a DataFrame."""
    if conn is None:
        conn = connect_database()
    ensure_tables(conn)  # ✅ ensure schema exists
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM it_tickets ORDER BY id ASC")
    rows = cursor.fetchall()
    df = pd.DataFrame(rows, columns=[desc[0] for desc in cursor.description])
    return df

def insert_ticket(conn, ticket_id, priority, status, category, subject, description,
                  created_date=None, resolved_date=None, assigned_to=None):
    """Insert a new ticket row."""
    ensure_tables(conn)  # ✅ ensure schema exists
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO it_tickets (ticket_id, priority, status, category, subject, description, created_date, resolved_date, assigned_to)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (ticket_id, priority, status, category, subject, description, created_date, resolved_date, assigned_to)
    )
    conn.commit()

def update_ticket_status(ticket_id: str, new_status: str) -> int:
    """Update ticket status by ticket_id; return affected rows."""
    conn = connect_database()
    ensure_tables(conn)
    cur = conn.cursor()
    cur.execute(
        "UPDATE it_tickets SET status = ? WHERE ticket_id = ?",
        (new_status, ticket_id)
    )
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count

def delete_ticket(ticket_id: str) -> int:
    """Delete ticket by ticket_id; return affected rows."""
    conn = connect_database()
    ensure_tables(conn)
    cur = conn.cursor()
    cur.execute("DELETE FROM it_tickets WHERE ticket_id = ?", (ticket_id,))
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count