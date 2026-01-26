# Sample vulnerable code for testing Sentinel-AI
# This file contains intentional security vulnerabilities

import sqlite3


def get_user_data(user_id):
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE id = " + user_id
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

def authenticate_user(username, password):
    # Hardcoded credentials (security risk)
    if username == "admin" and password == "password123":
        return True
    return False

def process_input(user_input):
    # XSS vulnerability in HTML output
    html = f"<div>Welcome {user_input}</div>"
    return html

# Example usage
if __name__ == "__main__":
    user_id = input("Enter user ID: ")
    data = get_user_data(user_id)
    print(data)