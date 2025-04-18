-- Drop existing tables if they exist
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS users;

-- Create users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone VARCHAR(15),
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    gmail_token TEXT,
    gmail_refresh_token TEXT,
    gmail_token_expiry DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    imap_server TEXT
);

-- Create transactions table
CREATE TABLE transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount FLOAT NOT NULL,
    description TEXT,
    category VARCHAR(50),
    transaction_type VARCHAR(10) NOT NULL,  -- 'income' or 'expense'
    transaction_date DATE,
    email_id VARCHAR(100),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Create index for faster queries
CREATE INDEX idx_user_id ON transactions (user_id);
CREATE INDEX idx_email_id ON transactions (email_id);
CREATE INDEX idx_transaction_date ON transactions (transaction_date); 