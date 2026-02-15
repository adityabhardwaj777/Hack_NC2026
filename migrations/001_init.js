/**
 * Initial migration - creates all tables
 */

const path = require('path');
const fs = require('fs');

async function run(db) {
  const sqliteMode = !process.env.DATABASE_URL;

  const users = sqliteMode
    ? `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        refresh_token TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`
    : `CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        refresh_token TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`;

  const accounts = sqliteMode
    ? `CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        account_type TEXT NOT NULL,
        account_number TEXT UNIQUE NOT NULL,
        balance REAL DEFAULT 0.00,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )`
    : `CREATE TABLE IF NOT EXISTS accounts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        account_type VARCHAR(50) NOT NULL,
        account_number VARCHAR(20) UNIQUE NOT NULL,
        balance DECIMAL(15,2) DEFAULT 0.00,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`;

  const transactions = sqliteMode
    ? `CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER NOT NULL,
        to_account_id INTEGER,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        description TEXT,
        category TEXT,
        merchant TEXT,
        fraud_score INTEGER DEFAULT 0,
        fraud_status TEXT DEFAULT 'safe',
        fraud_reasons TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (account_id) REFERENCES accounts(id)
      )`
    : `CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        account_id INTEGER NOT NULL REFERENCES accounts(id),
        to_account_id INTEGER REFERENCES accounts(id),
        type VARCHAR(50) NOT NULL,
        amount DECIMAL(15,2) NOT NULL,
        description TEXT,
        category VARCHAR(100),
        merchant VARCHAR(255),
        fraud_score INTEGER DEFAULT 0,
        fraud_status VARCHAR(20) DEFAULT 'safe',
        fraud_reasons TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`;

  const budgets = sqliteMode
    ? `CREATE TABLE IF NOT EXISTS budgets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        limit_amount REAL NOT NULL,
        spent_amount REAL DEFAULT 0.00,
        month TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )`
    : `CREATE TABLE IF NOT EXISTS budgets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        category VARCHAR(100) NOT NULL,
        limit_amount DECIMAL(15,2) NOT NULL,
        spent_amount DECIMAL(15,2) DEFAULT 0.00,
        month VARCHAR(7) NOT NULL
      )`;

  const security_alerts = sqliteMode
    ? `CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        transaction_id INTEGER,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        message TEXT NOT NULL,
        resolved INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (transaction_id) REFERENCES transactions(id)
      )`
    : `CREATE TABLE IF NOT EXISTS security_alerts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        transaction_id INTEGER REFERENCES transactions(id),
        alert_type VARCHAR(100) NOT NULL,
        severity VARCHAR(20) NOT NULL,
        message TEXT NOT NULL,
        resolved BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`;

  const audit_log = sqliteMode
    ? `CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        resource TEXT,
        resource_id INTEGER,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`
    : `CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action VARCHAR(100) NOT NULL,
        resource VARCHAR(100),
        resource_id INTEGER,
        details TEXT,
        ip_address VARCHAR(45),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`;

  const tables = [users, accounts, transactions, budgets, security_alerts, audit_log];
  for (const stmt of tables) {
    if (db.run) {
      await db.run(stmt);
    } else {
      await db.query(stmt);
    }
  }

  // Create indexes
  const indexes = [
    'CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_transactions_account_id ON transactions(account_id)',
    'CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at)',
    'CREATE INDEX IF NOT EXISTS idx_budgets_user_month ON budgets(user_id, month)',
    'CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)',
  ];
  for (const idx of indexes) {
    try {
      if (db.run) await db.run(idx);
      else await db.query(idx);
    } catch (e) {
      // Index may already exist
    }
  }

  return true;
}

module.exports = { run };
