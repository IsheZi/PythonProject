# Demo script to test schema, user migration, authentication, CSV loading, and incidents CRUD

from app.data.db import connect_database
from app.data.schema import create_all_tables
from app.services.user_service import migrate_users_from_file, register_user, login_user
from app.data.load_csv import load_all_csv_data
from app.data.incidents import insert_incident, get_all_incidents, update_incident_status, delete_incident
from app.data.tickets import insert_ticket, get_all_tickets, update_ticket_status, delete_ticket_by_id
from prettytable import PrettyTable
from app.data.datasets import insert_dataset, get_all_datasets, update_dataset_category, delete_dataset_by_id



def print_incidents_table(incidents):
    table = PrettyTable()
    table.field_names = ["ID", "Date", "Type", "Severity", "Status", "Description", "Reported By"]
    for row in incidents:
        table.add_row(row)
    print(table)

def print_tickets_table(tickets):
    table = PrettyTable()
    table.field_names = ["ID", "Title", "Priority", "Status", "Created Date"]
    for row in tickets:
        table.add_row(row)
    print(table)

def print_datasets_table(datasets):
    table = PrettyTable()
    table.field_names = ["ID", "Name", "Source", "Category", "Size"]
    for row in datasets:
        table.add_row(row)
    print(table)


def demo_tickets():
    # Insert a test ticket
    insert_ticket("VPN not working", "High", "open", "2025-12-11")
    print("✓ Ticket inserted")

    # Read all tickets
    tickets = get_all_tickets()
    print_tickets_table(tickets)

    # Update status
    rows = update_ticket_status(1, "resolved")
    print(f"Updated {rows} row(s)")

    # Delete ticket
    rows = delete_ticket_by_id(1)
    print(f"Deleted {rows} row(s)")

def demo_datasets():
        # Insert a test dataset
        insert_dataset("Threat Intel Feed", "External", "Cybersecurity", "500MB")
        print("✓ Dataset inserted")

        # Read all datasets
        datasets = get_all_datasets()
        print_datasets_table(datasets)

        # Update category
        rows = update_dataset_category(1, "Updated Category")
        print(f"Updated {rows} row(s)")

        # Delete dataset
        rows = delete_dataset_by_id(1)
        print(f"Deleted {rows} row(s)")

def main():
    #  Setup database
    conn = connect_database()
    create_all_tables(conn)
    conn.close()

    #  Migrate users from file (users.txt → database)
    migrated = migrate_users_from_file()
    print(f"Migrated {migrated} users from users.txt")

    # Register a NEW test user (avoid conflict with migrated ones)
    success, msg = register_user("bob", "TestPass456!", "analyst")
    print(msg)

    #  Login with the new user
    success, msg = login_user("bob", "TestPass456!")
    print(msg)

    #  Load CSV data into domain tables
    load_all_csv_data()

     # Incident CRUD demo
    incident_id = insert_incident(
        "2025-12-08", "Phishing", "High", "Open",
        "Suspicious email detected", "bob"
    )
    print(f"Inserted incident #{incident_id}")

    incidents = get_all_incidents()
    print_incidents_table(incidents)

    rows = update_incident_status(incident_id, "Resolved")
    print(f"Updated {rows} row(s)")

    rows = delete_incident(incident_id)
    print(f"Deleted {rows} row(s)")

    # Ticket CRUD demo
    demo_tickets()

    # Dataset CRUD demo
    demo_datasets()


if __name__ == "__main__":
    main()