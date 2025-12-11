from app.data.db import connect_database

def insert_ticket(title, priority, status="open", created_date=None):
    """Insert new IT ticket."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO it_tickets (title, priority, status, created_date) VALUES (?, ?, ?, ?)",
        (title, priority, status, created_date)
    )
    conn.commit()
    conn.close()

def get_all_tickets():
    """Retrieve all IT tickets."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM it_tickets")
    tickets = cursor.fetchall()
    conn.close()
    return tickets

def update_ticket_status(ticket_id, new_status):
    """Update ticket status."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE it_tickets SET status = ? WHERE id = ?",
        (new_status, ticket_id)
    )
    conn.commit()
    conn.close()

def delete_ticket_by_id(ticket_id):
    """Delete ticket by ID."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM it_tickets WHERE id = ?",
        (ticket_id,)
    )
    conn.commit()
    conn.close()