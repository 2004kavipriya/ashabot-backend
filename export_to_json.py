import sqlite3
import json

DB_NAME = 'user.db'

# Connect to the database
conn = sqlite3.connect(DB_NAME)
cursor = conn.cursor()

# Fetch all records from the users table
cursor.execute("SELECT * FROM users")
rows = cursor.fetchall()

# Convert the rows into a list of dictionaries (JSON format)
users_list = []
for row in rows:
    user_dict = {
        'id': row[0],
        'username': row[1],
        'password': row[2]
    }
    users_list.append(user_dict)

# Convert the list to a JSON string
json_data = json.dumps(users_list, indent=4)

# Output the JSON data (you can write it to a file or print it)
print(json_data)

# Optionally, save the JSON data to a file
with open('users.json', 'w') as json_file:
    json.dump(users_list, json_file, indent=4)

# Close the database connection
conn.close()
