/**
 * Enterprise features: Loans, P2P, Crypto, Ledger, Contracts, Risk
 */

async function run(db) {
  const isPostgres = !!process.env.DATABASE_URL;

  const tables = [
    // Loans with risk modeling
    isPostgres
      ? `CREATE TABLE IF NOT EXISTS loans (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id),
          amount DECIMAL(15,2) NOT NULL,
          term_months INTEGER NOT NULL,
          interest_rate DECIMAL(5,2) DEFAULT 0,
          risk_score INTEGER DEFAULT 0,
          risk_factors TEXT,
          status VARCHAR(20) DEFAULT 'pending',
          purpose VARCHAR(255),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`
      : `CREATE TABLE IF NOT EXISTS loans (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          amount REAL NOT NULL,
          term_months INTEGER NOT NULL,
          interest_rate REAL DEFAULT 0,
          risk_score INTEGER DEFAULT 0,
          risk_factors TEXT,
          status TEXT DEFAULT 'pending',
          purpose TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )`,

    // P2P transfers (Zelle-like)
    isPostgres
      ? `CREATE TABLE IF NOT EXISTS p2p_transfers (
          id SERIAL PRIMARY KEY,
          sender_user_id INTEGER NOT NULL REFERENCES users(id),
          receiver_user_id INTEGER NOT NULL REFERENCES users(id),
          sender_account_id INTEGER NOT NULL REFERENCES accounts(id),
          amount DECIMAL(15,2) NOT NULL,
          memo TEXT,
          status VARCHAR(20) DEFAULT 'completed',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`
      : `CREATE TABLE IF NOT EXISTS p2p_transfers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          sender_user_id INTEGER NOT NULL,
          receiver_user_id INTEGER NOT NULL,
          sender_account_id INTEGER NOT NULL,
          amount REAL NOT NULL,
          memo TEXT,
          status TEXT DEFAULT 'completed',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (sender_user_id) REFERENCES users(id),
          FOREIGN KEY (receiver_user_id) REFERENCES users(id),
          FOREIGN KEY (sender_account_id) REFERENCES accounts(id)
        )`,

    // Crypto wallets
    isPostgres
      ? `CREATE TABLE IF NOT EXISTS crypto_wallets (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id),
          symbol VARCHAR(10) NOT NULL,
          balance DECIMAL(20,8) DEFAULT 0,
          wallet_address VARCHAR(100),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(user_id, symbol)
        )`
      : `CREATE TABLE IF NOT EXISTS crypto_wallets (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          symbol TEXT NOT NULL,
          balance REAL DEFAULT 0,
          wallet_address TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(user_id, symbol),
          FOREIGN KEY (user_id) REFERENCES users(id)
        )`,

    // Crypto transactions
    isPostgres
      ? `CREATE TABLE IF NOT EXISTS crypto_transactions (
          id SERIAL PRIMARY KEY,
          wallet_id INTEGER NOT NULL REFERENCES crypto_wallets(id),
          type VARCHAR(20) NOT NULL,
          amount DECIMAL(20,8) NOT NULL,
          tx_hash VARCHAR(66),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`
      : `CREATE TABLE IF NOT EXISTS crypto_transactions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          wallet_id INTEGER NOT NULL,
          type TEXT NOT NULL,
          amount REAL NOT NULL,
          tx_hash TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (wallet_id) REFERENCES crypto_wallets(id)
        )`,

    // Immutable ledger (blockchain-style)
    isPostgres
      ? `CREATE TABLE IF NOT EXISTS ledger_entries (
          id SERIAL PRIMARY KEY,
          tx_type VARCHAR(50) NOT NULL,
          tx_id INTEGER NOT NULL,
          entry_hash VARCHAR(64) NOT NULL,
          prev_hash VARCHAR(64),
          payload TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`
      : `CREATE TABLE IF NOT EXISTS ledger_entries (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          tx_type TEXT NOT NULL,
          tx_id INTEGER NOT NULL,
          entry_hash TEXT NOT NULL,
          prev_hash TEXT,
          payload TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,

    // Recurring contracts (smart contract-like)
    isPostgres
      ? `CREATE TABLE IF NOT EXISTS recurring_contracts (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id),
          account_id INTEGER NOT NULL REFERENCES accounts(id),
          payee VARCHAR(255) NOT NULL,
          amount DECIMAL(15,2) NOT NULL,
          frequency VARCHAR(20) NOT NULL,
          next_due DATE NOT NULL,
          active BOOLEAN DEFAULT true,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`
      : `CREATE TABLE IF NOT EXISTS recurring_contracts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          account_id INTEGER NOT NULL,
          payee TEXT NOT NULL,
          amount REAL NOT NULL,
          frequency TEXT NOT NULL,
          next_due TEXT NOT NULL,
          active INTEGER DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id),
          FOREIGN KEY (account_id) REFERENCES accounts(id)
        )`,

    // Budget goals
    isPostgres
      ? `CREATE TABLE IF NOT EXISTS budget_goals (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id),
          goal_name VARCHAR(255) NOT NULL,
          target_amount DECIMAL(15,2) NOT NULL,
          current_amount DECIMAL(15,2) DEFAULT 0,
          deadline DATE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`
      : `CREATE TABLE IF NOT EXISTS budget_goals (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          goal_name TEXT NOT NULL,
          target_amount REAL NOT NULL,
          current_amount REAL DEFAULT 0,
          deadline TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )`,

    // User risk scores
    isPostgres
      ? `CREATE TABLE IF NOT EXISTS user_risk_scores (
          id SERIAL PRIMARY KEY,
          user_id INTEGER UNIQUE NOT NULL REFERENCES users(id),
          score INTEGER DEFAULT 0,
          factors TEXT,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`
      : `CREATE TABLE IF NOT EXISTS user_risk_scores (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER UNIQUE NOT NULL,
          score INTEGER DEFAULT 0,
          factors TEXT,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )`,

    // Bank reserves (monitoring)
    isPostgres
      ? `CREATE TABLE IF NOT EXISTS bank_reserves (
          id SERIAL PRIMARY KEY,
          total_deposits DECIMAL(20,2) DEFAULT 0,
          reserve_ratio DECIMAL(5,2) DEFAULT 10,
          reserve_amount DECIMAL(20,2) DEFAULT 0,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`
      : `CREATE TABLE IF NOT EXISTS bank_reserves (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          total_deposits REAL DEFAULT 0,
          reserve_ratio REAL DEFAULT 10,
          reserve_amount REAL DEFAULT 0,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,
  ];

  for (const stmt of tables) {
    await db.run(stmt);
  }

  // Seed bank reserves
  try {
    await db.run('INSERT INTO bank_reserves (total_deposits, reserve_ratio, reserve_amount) SELECT 0, 10, 0 WHERE NOT EXISTS (SELECT 1 FROM bank_reserves LIMIT 1)');
  } catch (_) {}

  return true;
}

module.exports = { run };
