-- Sample vulnerable SQL code for testing Sentinel-AI
-- This file contains intentional security vulnerabilities

-- Hardcoded credentials in comments (still a risk)
-- Database: mydb
-- Username: admin
-- Password: password123

-- Table creation with weak constraints
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE,
    password VARCHAR(255), -- Should be hashed
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user'
);

-- Inserting test data with weak passwords
INSERT INTO users (username, password, email, role) VALUES
('admin', 'password123', 'admin@example.com', 'admin'),
('user1', '123456', 'user1@example.com', 'user'),
('user2', 'qwerty', 'user2@example.com', 'user');

-- Vulnerable stored procedure with dynamic SQL
DELIMITER //
CREATE PROCEDURE get_user_data(IN user_id INT)
BEGIN
    -- This is vulnerable to SQL injection if called with dynamic input
    SET @sql = CONCAT('SELECT * FROM users WHERE id = ', user_id);
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END //
DELIMITER ;

-- Another vulnerable procedure
DELIMITER //
CREATE PROCEDURE search_users(IN search_term VARCHAR(100))
BEGIN
    -- Vulnerable to SQL injection
    SET @sql = CONCAT('SELECT username, email FROM users WHERE username LIKE "%', search_term, '%"');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END //
DELIMITER ;

-- Granting excessive privileges
GRANT ALL PRIVILEGES ON mydb.* TO 'webapp'@'localhost' IDENTIFIED BY 'weakpassword';

-- Creating a view that exposes sensitive data
CREATE VIEW user_details AS
SELECT id, username, email, role FROM users;
-- This view exposes all user information without access controls

FLUSH PRIVILEGES;