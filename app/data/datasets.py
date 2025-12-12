import pandas as pd
from app.data.db import connect_database

def insert_dataset(dataset_id: int, name: str, rows: int, columns: int,
                   uploaded_by: str, upload_date: str) -> int:
    """Insert dataset metadata; returns dataset_id (PK)."""
    conn = connect_database()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO datasets_metadata (dataset_id, name, rows, columns, uploaded_by, upload_date)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (dataset_id, name, rows, columns, uploaded_by, upload_date))
    conn.commit()
    conn.close()
    return dataset_id

def get_all_datasets_df():
    """Return all datasets as DataFrame."""
    conn = connect_database()
    df = pd.read_sql_query(
        "SELECT * FROM datasets_metadata ORDER BY dataset_id ASC",
        conn
    )
    conn.close()
    return df

def update_dataset_name(dataset_id: int, new_name: str) -> int:
    """Update dataset name; return affected rows."""
    conn = connect_database()
    cur = conn.cursor()
    cur.execute(
        "UPDATE datasets_metadata SET name = ? WHERE dataset_id = ?",
        (new_name, dataset_id)
    )
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count

def delete_dataset(dataset_id: int) -> int:
    """Delete dataset metadata; return affected rows."""
    conn = connect_database()
    cur = conn.cursor()
    cur.execute("DELETE FROM datasets_metadata WHERE dataset_id = ?", (dataset_id,))
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count