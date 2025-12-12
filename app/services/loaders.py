from pathlib import Path
import pandas as pd
from app.data.db import connect_database

# Point to your actual DATA folder
DATA_DIR = Path("DATA")

def load_csv_to_table(csv_filename: str, table_name: str) -> int:
    csv_path = DATA_DIR / csv_filename
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        print(f"Warning: {csv_filename} is missing or empty. Skipping load.")
        return 0

    df = pd.read_csv(csv_path)
    if df.empty:
        print(f"Warning: {csv_filename} has no rows. Skipping load.")
        return 0

    conn = connect_database()
    cur = conn.cursor()

    # Clear the table before loading to avoid UNIQUE constraint errors
    cur.execute(f"DELETE FROM {table_name}")
    conn.commit()

    # Load fresh data
    df.to_sql(table_name, conn, if_exists="append", index=False)
    conn.close()
    return len(df)

def load_all_csv_data():
    return {
        "cyber_incidents": load_csv_to_table("cyber_incidents.csv", "cyber_incidents"),
        "datasets_metadata": load_csv_to_table("datasets_metadata.csv", "datasets_metadata"),
        "it_tickets": load_csv_to_table("it_tickets.csv", "it_tickets"),
    }