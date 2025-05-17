import sqlite3

# Connect to (or create) the database
conn = sqlite3.connect("users.db")

# Create a cursor object
cursor = conn.cursor()

# Create the users table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
''')

# Commit and close the connection
conn.commit()
conn.close()

print("Database and users table created successfully.")
