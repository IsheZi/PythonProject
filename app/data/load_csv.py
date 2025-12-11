import pandas as pd
from pathlib import Path
from app.data.db import connect_database

def load_csv_to_table(csv_path, table_name):
    """
    Load a CSV file into a database table using pandas.
    - Reads the CSV into a DataFrame.
    - Uses DataFrame.to_sql() to insert all rows.
    - if_exists='append' ensures new data is added without deleting old rows.
    """
    conn = connect_database()
    csv_file = Path(csv_path)

    if not csv_file.exists():
        print(f"CSV file not found: {csv_file}")
        conn.close()
        return 0

    # Read CSV into DataFrame
    df = pd.read_csv(csv_file)

    # Bulk insert into table
    df.to_sql(table_name, conn, if_exists='append', index=False)

    row_count = len(df)
    conn.close()
    print(f"✓ Loaded {row_count} rows into {table_name}")
    return row_count


def load_all_csv_data():
    """
    Load all domain CSV files into their respective tables.
    """
    total_rows = 0
    total_rows += load_csv_to_table("DATA/cyber_incidents.csv", "cyber_incidents")
    total_rows += load_csv_to_table("DATA/datasets_metadata.csv", "datasets_metadata")
    total_rows += load_csv_to_table("DATA/it_tickets.csv", "it_tickets")
    print(f"✓ Total rows loaded: {total_rows}")
    return total_rows