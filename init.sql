CREATE TABLE IF NOT EXISTS data_collection (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    os_info TEXT,
    services TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vuln_scan (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    vuln_type VARCHAR(100),
    payload TEXT,
    status ENUM('pending', 'confirmed', 'false_positive') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vuln_validation (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT,
    validation_result TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES vuln_scan(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_operations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(255) NOT NULL,
    user VARCHAR(100),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
