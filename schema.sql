-- TrustGuard AI Database Schema
-- Compatible with MySQL 8.0+

CREATE DATABASE IF NOT EXISTS trustguard_db;
USE trustguard_db;

-- 1. Users Table (Authentication & Accounts)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    is_admin TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_users_username (username),
    INDEX idx_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Scans Table (Scan History & Analytics)
-- user_id is NULLABLE to support guest scans without violating foreign key constraints
CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    scan_type ENUM('text', 'email', 'url', 'screenshot', 'job_offer') NOT NULL,
    input_snippet VARCHAR(255) NOT NULL,
    risk_score INT NOT NULL,
    risk_level ENUM('Low Risk', 'Suspicious', 'High Risk') NOT NULL,
    confidence_score DECIMAL(4,2) NOT NULL DEFAULT 0.00,
    detected_flags TEXT NOT NULL,
    recommendations TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scans_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE SET NULL,
    INDEX idx_scans_user (user_id),
    INDEX idx_scans_created (created_at),
    INDEX idx_scans_level (risk_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Community Reports Table (Community Scam Reporting & Moderation)
CREATE TABLE IF NOT EXISTS community_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    category VARCHAR(50) NOT NULL,
    scam_type VARCHAR(30) NOT NULL DEFAULT 'text',
    evidence_snippet TEXT NOT NULL,
    description TEXT NOT NULL,
    indicators TEXT NULL,
    status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_reports_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE SET NULL,
    INDEX idx_reports_status (status),
    INDEX idx_reports_category (category),
    INDEX idx_reports_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

