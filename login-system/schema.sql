

CREATE DATABASE IF NOT EXISTS login_system
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE login_system;

-- ── Users ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(20)  NOT NULL UNIQUE,
    email         VARCHAR(255) NOT NULL UNIQUE,
    password      VARCHAR(255) NOT NULL,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login    DATETIME,
    is_active     TINYINT(1)   NOT NULL DEFAULT 1
);

-- ── Failed login attempts  (brute-force protection) ────────────
CREATE TABLE IF NOT EXISTS login_attempts (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(20)  NOT NULL,
    ip_address    VARCHAR(45)  NOT NULL,
    attempted_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username_time (username, attempted_at),
    INDEX idx_ip_time       (ip_address, attempted_at)
);

-- ── Audit / access log ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT,
    event         VARCHAR(50)  NOT NULL,   -- e.g. LOGIN_SUCCESS, LOGIN_FAIL, LOGOUT, PASSWORD_RESET
    ip_address    VARCHAR(45)  NOT NULL,
    user_agent    VARCHAR(512),
    detail        VARCHAR(255),            -- optional extra context
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_event (user_id, event),
    INDEX idx_created    (created_at)
);

-- ── Password reset tokens ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS password_resets (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT          NOT NULL,
    token         VARCHAR(64)  NOT NULL UNIQUE,
    expires_at    DATETIME     NOT NULL,
    used          TINYINT(1)   NOT NULL DEFAULT 0,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token      (token),
    INDEX idx_expires    (expires_at)
);