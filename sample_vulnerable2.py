# Sample vulnerable Python code (Alternative) for testing Sentinel-AI
# This file contains different types of security vulnerabilities

import os
import subprocess
import pickle
import hashlib

def weak_hash_password(password):
    """Weak password hashing using MD5"""
    # Vulnerable: Using weak hashing algorithm
    return hashlib.md5(password.encode()).hexdigest()

def execute_command(user_command):
    """Command injection vulnerability"""
    # Vulnerable: Direct execution of user input
    result = subprocess.run(user_command, shell=True, capture_output=True, text=True)
    return result.stdout

def load_user_data(filename):
    """Deserialization vulnerability"""
    # Vulnerable: Loading pickled data without validation
    with open(filename, 'rb') as f:
        data = pickle.load(f)  # This can execute arbitrary code
    return data

def insecure_random_token():
    """Using predictable random for security purposes"""
    import random
    # Vulnerable: Using random instead of secrets for security tokens
    return str(random.randint(100000, 999999))

def check_file_access(filepath, user_id):
    """Path traversal vulnerability"""
    # Vulnerable: Insufficient validation of file paths
    full_path = os.path.join("/var/data/", str(user_id), filepath)

    if os.path.exists(full_path):
        with open(full_path, 'r') as f:
            return f.read()
    return None

def authenticate_user(username, password):
    """Timing attack vulnerability"""
    # Vulnerable: String comparison that can be exploited with timing attacks
    stored_password = get_stored_password(username)
    if stored_password and len(password) == len(stored_password):
        for i in range(len(password)):
            if password[i] != stored_password[i]:
                return False
        return True
    return False

def get_stored_password(username):
    """Mock function - in real app this would query database"""
    # This would be vulnerable if not properly implemented
    return "password123"  # Hardcoded for demo

# Example usage that demonstrates multiple vulnerabilities
if __name__ == "__main__":
    # Test command injection
    cmd = input("Enter command to execute: ")
    output = execute_command(cmd)
    print("Command output:", output)

    # Test insecure random
    token = insecure_random_token()
    print("Your token:", token)

    # Test weak hashing
    hashed = weak_hash_password("mypassword")
    print("Hashed password:", hashed)