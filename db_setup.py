import os
import sqlite3

def create_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    
    # Create profiles table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            name TEXT,
            email TEXT,
            phone TEXT,
            location TEXT,
            skills TEXT,
            experience TEXT,
            education TEXT,
            achievements TEXT,
            certifications TEXT,
            links TEXT,
            profile_photo TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("Database and tables created successfully!")

if __name__ == '__main__':
    print("Checking if database exists:", os.path.exists("users.db"))
    create_db()
