import pandas as pd
from pathlib import Path
from app.data.db import connect_database
from app.data.schema import create_all_tables

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "DATA"

def seed_incidents_from_csv(filepath=DATA_DIR / "cyber_incidents.csv"):
    conn = connect_database()
    create_all_tables()
    df = pd.read_csv(filepath)
    cur = conn.cursor()
    count = 0
    for _, row in df.iterrows():
        cur.execute("""
            INSERT OR IGNORE INTO cyber_incidents (id, date, incident_type, severity, status, description, reported_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            row["incident_id"],
            row["timestamp"],
            row["category"],       # maps to incident_type
            row["severity"],
            row["status"],
            row["description"],
            "system"
        ))
        count += cur.rowcount
    conn.commit()
    conn.close()
    print(f"✅ Seeded {count} cyber incidents.")

def seed_datasets_from_csv(filepath=DATA_DIR / "datasets_metadata.csv"):
    conn = connect_database()
    create_all_tables()
    df = pd.read_csv(filepath)
    cur = conn.cursor()
    count = 0
    for _, row in df.iterrows():
        cur.execute("""
            INSERT OR IGNORE INTO datasets_metadata (id, dataset_name, category, source, record_count, last_updated, file_size_mb)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            row["dataset_id"],
            row["name"],
            "General",             # default category
            row["uploaded_by"],    # maps to source
            row["rows"],           # record_count
            row["upload_date"],    # last_updated
            row["columns"]         # file_size_mb (approximate)
        ))
        count += cur.rowcount
    conn.commit()
    conn.close()
    print(f"✅ Seeded {count} datasets.")

def seed_tickets_from_csv(filepath=DATA_DIR / "it_tickets.csv"):
    conn = connect_database()
    create_all_tables()
    df = pd.read_csv(filepath)
    cur = conn.cursor()
    count = 0
    for _, row in df.iterrows():
        cur.execute("""
            INSERT OR IGNORE INTO it_tickets (ticket_id, priority, status, subject, description, assigned_to, created_date, resolved_date, category)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            row["ticket_id"],
            row["priority"],
            row["status"],
            "IT Issue",            # subject placeholder
            row["description"],
            row["assigned_to"],
            row["created_at"],
            None,                  # resolved_date not in CSV
            "General"
        ))
        count += cur.rowcount
    conn.commit()
    conn.close()
    print(f"✅ Seeded {count} IT tickets.")

if __name__ == "__main__":
    seed_incidents_from_csv()
    seed_datasets_from_csv()
    seed_tickets_from_csv()
    print("✅ Database seeding complete.")