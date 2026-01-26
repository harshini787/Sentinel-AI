// Sample vulnerable JavaScript code for testing Sentinel-AI
// This file contains intentional security vulnerabilities

const express = require('express');
const mysql = require('mysql');
const app = express();

// SQL Injection vulnerability
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // Vulnerable: Direct string concatenation in SQL query
    const query = "SELECT * FROM users WHERE id = " + userId;

    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password123', // Hardcoded credentials
        database: 'mydb'
    });

    connection.query(query, (error, results) => {
        if (error) throw error;
        res.json(results);
    });
});

// XSS vulnerability
app.get('/welcome', (req, res) => {
    const name = req.query.name;
    // Vulnerable: User input directly inserted into HTML
    const html = `<h1>Welcome ${name}!</h1>`;
    res.send(html);
});

// Command injection vulnerability
app.get('/ping/:host', (req, res) => {
    const host = req.params.host;
    const { exec } = require('child_process');
    // Vulnerable: User input passed to system command
    exec(`ping ${host}`, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});