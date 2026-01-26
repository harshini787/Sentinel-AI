// Sample vulnerable Java code for testing Sentinel-AI
// This file contains intentional security vulnerabilities

import java.sql.*;
import java.io.*;
import javax.servlet.http.*;

public class VulnerableServlet extends HttpServlet {

    // Hardcoded database credentials
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "password123";

    // SQL Injection vulnerability
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String userId = request.getParameter("id");
        Connection conn = null;
        Statement stmt = null;

        try {
            Class.forName("com.mysql.jdbc.Driver");
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);

            // Vulnerable: Direct string concatenation in SQL query
            String sql = "SELECT * FROM users WHERE id = " + userId;
            stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);

            // Process results...
            while(rs.next()) {
                // Process each row
            }

        } catch(Exception e) {
            e.printStackTrace();
        } finally {
            try { if(stmt != null) stmt.close(); } catch(Exception e) {}
            try { if(conn != null) conn.close(); } catch(Exception e) {}
        }
    }

    // Path traversal vulnerability
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String filename = request.getParameter("file");

        // Vulnerable: User input used directly in file path
        File file = new File("/var/www/files/" + filename);

        if(file.exists()) {
            // Read and serve file
            FileInputStream fis = new FileInputStream(file);
            // ... serve file content
        }
    }
}