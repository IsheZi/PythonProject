import sqlite3

# Path to your database
db_path = r"C:\Users\Isheanesu Zijenah\PycharmProjects\PythonProject\CW2_M00956545_CST1510\DATA\intelligence_platform.db"

conn = sqlite3.connect(db_path)
cur = conn.cursor()

tables = ["cyber_incidents", "datasets_metadata", "it_tickets"]

for table in tables:
    try:
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        count = cur.fetchone()[0]
        print(f"{table}: {count} rows")
    except Exception as e:
        print(f"Error checking {table}: {e}")

conn.close()