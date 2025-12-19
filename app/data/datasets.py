import pandas as pd
from app.data.db_helpers import connect_database, ensure_tables

def get_all_datasets(conn=None):
    """Return all datasets as a DataFrame."""
    if conn is None:
        conn = connect_database()
    ensure_tables(conn)  # ✅ ensure schema exists
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM datasets_metadata ORDER BY id ASC")
    rows = cursor.fetchall()
    df = pd.DataFrame(rows, columns=[desc[0] for desc in cursor.description])
    return df

def insert_dataset(conn, name, source, category, size, record_count=0, last_updated=None):
    """Insert a new dataset row."""
    ensure_tables(conn)  # ✅ ensure schema exists
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO datasets_metadata (dataset_name, source, category, file_size_mb, record_count, last_updated)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (name, source, category, size, record_count, last_updated)
    )
    conn.commit()

def update_dataset_name(dataset_id: int, new_name: str) -> int:
    """Update dataset name; return affected rows."""
    conn = connect_database()
    ensure_tables(conn)
    cur = conn.cursor()
    cur.execute(
        "UPDATE datasets_metadata SET dataset_name = ? WHERE id = ?",
        (new_name, dataset_id)
    )
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count

def delete_dataset(dataset_id: int) -> int:
    """Delete dataset metadata; return affected rows."""
    conn = connect_database()
    ensure_tables(conn)
    cur = conn.cursor()
    cur.execute("DELETE FROM datasets_metadata WHERE id = ?", (dataset_id,))
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count