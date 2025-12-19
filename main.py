from CW2_M00956545_CST1510.app import create_all_tables
from CW2_M00956545_CST1510.app import (
    register_user,
    login_user,
    migrate_users_from_file
)
from CW2_M00956545_CST1510.app import load_all_csv_data
from CW2_M00956545_CST1510.app import (
    insert_incident,
    get_all_incidents_df,
    update_incident_status,
    delete_incident
)
from CW2_M00956545_CST1510.app import (
    insert_dataset,
    get_all_datasets_df,
    update_dataset_name,
    delete_dataset
)
from CW2_M00956545_CST1510.app import (
    insert_ticket,
    get_all_tickets_df,
    update_ticket_status,
    delete_ticket
)

def setup_database_complete():
    print("\n" + "=" * 60)
    print("STARTING: COMPLETE DATABASE SETUP")
    print("=" * 60)

    # 1. Create tables
    print("\n[1/4] Creating database tables...")
    create_all_tables()

    # 2. Migrate users from users.txt
    print("\n[2/4] Migrating users from users.txt...")
    migrated = migrate_users_from_file()
    print(f"  Migrated {migrated} user(s).")

    # 3. Load CSV data
    print("\n[3/4] Loading CSV data...")
    results = load_all_csv_data()
    for table, count in results.items():
        print(f"  {table}: loaded {count} rows")

    # 4. Verify with counts
    print("\n[4/4] Verifying data snapshots...")
    print("  Incidents sample:", len(get_all_incidents_df()))
    print("  Datasets sample:", len(get_all_datasets_df()))
    print("  Tickets sample:", len(get_all_tickets_df()))

def demo_auth_and_sessions():
    print("\n" + "=" * 60)
    print("DEMO: AUTHENTICATION & SESSIONS")
    print("=" * 60)

    # Register a new user
    ok, msg = register_user("bob", "SecurePass123!", "analyst")
    print("Register:", msg)

    # Login user
    ok, msg = login_user("bob", "SecurePass123!")
    print("Login:", msg)

def demo_crud_actions():
    print("\n" + "=" * 60)
    print("DEMO: CRUD OPERATIONS")
    print("=" * 60)

    # Incident insert
    new_id = 999999
    insert_incident(
        incident_id=new_id,
        timestamp="2025-01-01 12:00:00.000000",
        severity="High",
        category="Phishing",
        status="Open",
        description="Suspicious email detected"
    )
    print(f"Inserted incident {new_id}")

    # Update statu7 and 8
    changed = update_incident_status(new_id, "Resolved")
    print(f"Updated incident status rows: {changed}")

    # Delete
    deleted = delete_incident(new_id)
    print(f"Deleted incident rows: {deleted}")

    # Dataset insert/update/delete demo
    insert_dataset(12345, "Test Dataset", 100, 5, "alice", "2025-01-01")
    print("Datasets total:", len(get_all_datasets_df()))
    update_dataset_name(12345, "Updated Dataset Name")
    delete_dataset(12345)

    # Ticket insert/update/delete demo
    insert_ticket(54321, "High", "System outage", "Open", "bob", "2025-01-01", 12)
    print("Tickets total:", len(get_all_tickets_df()))
    update_ticket_status(54321, "Closed")
    delete_ticket(54321)

if __name__ == "__main__":
    setup_database_complete()
    demo_auth_and_sessions()
    demo_crud_actions()