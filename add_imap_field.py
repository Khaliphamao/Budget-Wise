import sqlite3

# Connect to the database
conn = sqlite3.connect('instance/budgetwise.db')
cursor = conn.cursor()

# Check if column already exists
cursor.execute("PRAGMA table_info(users)")
columns = [column[1] for column in cursor.fetchall()]

if 'imap_server' not in columns:
    # Add the imap_server column to the users table
    cursor.execute("ALTER TABLE users ADD COLUMN imap_server TEXT")
    conn.commit()
    print("Added imap_server column to users table")
else:
    print("imap_server column already exists")

# Close the connection
conn.close()

print("Database migration completed successfully!") 