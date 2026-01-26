import os

from dotenv import load_dotenv

from src.mock_engine import sentinel_engine

# Load environment variables
load_dotenv()

# Test the engine with the sample vulnerable code
sample_code = '''
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
'''

print("Testing Sentinel Engine...")
try:
    result = sentinel_engine({"code": sample_code})
    print("\n===== HUNTER FINDINGS =====")
    print(result.get("raw_findings", "No findings"))
    print("\n===== FINAL AUDIT REPORT =====")
    print(result.get("final_audit_report", "No report"))
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()