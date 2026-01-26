// Sample vulnerable C++ code for testing Sentinel-AI
// This file contains intentional security vulnerabilities

#include <iostream>
#include <string>
#include <fstream>
#include <cstdlib>
#include <mysql/mysql.h>

using namespace std;

// Hardcoded credentials (security risk)
const char* DB_HOST = "localhost";
const char* DB_USER = "root";
const char* DB_PASS = "password123";
const char* DB_NAME = "mydb";

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Usage: " << argv[0] << " <user_id>" << endl;
        return 1;
    }

    string userId = argv[1];
    MYSQL* conn;
    MYSQL_RES* res;
    MYSQL_ROW row;

    // Initialize MySQL connection
    conn = mysql_init(NULL);

    if (!mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, 0, NULL, 0)) {
        cerr << "Connection failed: " << mysql_error(conn) << endl;
        return 1;
    }

    // SQL Injection vulnerability: Direct string concatenation
    string query = "SELECT * FROM users WHERE id = " + userId;

    if (mysql_query(conn, query.c_str())) {
        cerr << "Query failed: " << mysql_error(conn) << endl;
        mysql_close(conn);
        return 1;
    }

    res = mysql_use_result(conn);

    // Process results
    while ((row = mysql_fetch_row(res)) != NULL) {
        cout << "User: " << row[0] << endl;
    }

    mysql_free_result(res);
    mysql_close(conn);

    return 0;
}

// Command injection vulnerability
void pingHost(const string& host) {
    // Vulnerable: User input passed directly to system command
    string command = "ping -c 4 " + host;
    system(command.c_str());
}

// Path traversal vulnerability
void readFile(const string& filename) {
    // Vulnerable: User input used directly in file path
    string filepath = "/var/www/files/" + filename;

    ifstream file(filepath.c_str());
    if (file.is_open()) {
        string line;
        while (getline(file, line)) {
            cout << line << endl;
        }
        file.close();
    }
}