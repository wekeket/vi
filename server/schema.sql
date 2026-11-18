-- Office Visitor Management System schema.
-- The server runs this automatically on start, but you can also import it
-- manually (phpMyAdmin / mysql CLI). It contains NO data: the first
-- administrator is created from the app's first-run setup screen.

CREATE DATABASE IF NOT EXISTS vms CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE vms;

CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(120) NOT NULL,
  username      VARCHAR(50)  NOT NULL UNIQUE,
  password_hash VARCHAR(100) NOT NULL,
  role          ENUM('admin','staff') NOT NULL DEFAULT 'staff',
  active        TINYINT(1)   NOT NULL DEFAULT 1,
  created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS visits (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(120) NOT NULL,
  contact     VARCHAR(40)  NOT NULL,
  purpose     VARCHAR(255) NOT NULL,
  host        VARCHAR(160) NOT NULL,
  time_in     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  time_out    DATETIME(3)  NULL,
  archived    TINYINT(1)   NOT NULL DEFAULT 0,
  created_by  INT UNSIGNED NULL,
  CONSTRAINT fk_visits_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_visits_time_in (time_in),
  INDEX idx_visits_open (time_out, archived)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS activity_logs (
  id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id    INT UNSIGNED NULL,
  username   VARCHAR(50)  NOT NULL DEFAULT 'system',
  action     VARCHAR(255) NOT NULL,
  created_at DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_logs_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_logs_created (created_at)
) ENGINE=InnoDB;
