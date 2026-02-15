require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');

const db = require('./config/database');
const config = require('./config/env');

const app = express();
const PORT = config.PORT;

// ==================== Production Security Middleware ====================
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: config.CORS_ORIGIN }));
app.use(bodyParser.json());
app.use(express.static('public'));

const apiLimiter = rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_MAX,
  message: { error: 'Too many requests, try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', apiLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many auth attempts, try again in 15 minutes' },
});
app.use('/api/auth/', authLimiter);

// ==================== Error Handler ====================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: config.isProd ? 'Internal server error' : err.message });
});

// ==================== Validation Schemas (Zod) ====================
const registerSchema = z.object({
  username: z.string().min(2).max(50).trim(),
  email: z.string().email().toLowerCase(),
  password: z.string().min(8).max(128),
});

const loginSchema = z.object({
  email: z.string().email().toLowerCase(),
  password: z.string().min(1),
});

// ==================== Helpers ====================
function validatePositiveNumber(value) {
  const num = Number(value);
  return Number.isFinite(num) && num > 0;
}

function currentMonthYYYYMM() {
  return new Date().toISOString().slice(0, 7);
}

async function assertAccountOwnedByUser(accountId, userId) {
  const row = await db.queryOne('SELECT id FROM accounts WHERE id = ? AND user_id = ?', [accountId, userId]);
  return !!row;
}

async function auditLog(userId, action, resource, resourceId, details, req) {
  const ip = req?.ip || req?.connection?.remoteAddress;
  const ua = req?.get?.('user-agent') || '';
  try {
    await db.run(
      'INSERT INTO audit_log (user_id, action, resource, resource_id, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [userId || null, action, resource || null, resourceId || null, typeof details === 'string' ? details : JSON.stringify(details || {}), ip, ua]
    );
  } catch (e) {
    console.error('Audit log failed:', e);
  }
}

// ==================== Auth Middleware ====================
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing Authorization header' });

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ error: 'Bad Authorization format. Use: Bearer <token>' });
  }

  const token = parts[1];
  jwt.verify(token, config.JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ error: 'Invalid/expired token' });
    req.user = payload;
    next();
  });
}

// ==================== Fraud Detection ====================
function analyzeFraud(transaction) {
  let riskScore = 0;
  const reasons = [];
  const merchantLower = (transaction.merchant || '').toLowerCase();

  const suspiciousKeywords = ['dark web', 'unknown', 'crypto exchange', 'suspicious', 'unauthorized'];
  for (const keyword of suspiciousKeywords) {
    if (merchantLower.includes(keyword)) {
      riskScore += 70;
      reasons.push(`High-risk merchant detected: ${keyword}`);
      break;
    }
  }

  if (transaction.amount > 5000) {
    riskScore += 40;
    reasons.push(`Large transaction amount: $${transaction.amount.toFixed(2)}`);
  } else if (transaction.amount > 2000) {
    riskScore += 20;
    reasons.push('Elevated transaction amount');
  }

  let status = 'safe';
  if (riskScore >= 70) status = 'blocked';
  else if (riskScore >= 40) status = 'flagged';

  return {
    riskScore: Math.min(riskScore, 100),
    status,
    reasons: reasons.length > 0 ? reasons : ['Normal transaction pattern'],
  };
}

// Ledger hash (blockchain-style immutability)
function createLedgerHash(payload, prevHash = '') {
  return crypto.createHash('sha256').update(prevHash + JSON.stringify(payload)).digest('hex');
}

// Loan risk model (simplified)
function calculateLoanRisk(amount, termMonths, userRiskScore = 300) {
  let score = 0;
  const factors = [];
  if (amount > 50000) { score += 30; factors.push('High loan amount'); }
  else if (amount > 20000) { score += 15; factors.push('Moderate loan amount'); }
  if (termMonths > 60) { score += 20; factors.push('Long term'); }
  else if (termMonths > 36) { score += 10; factors.push('Extended term'); }
  if (userRiskScore > 600) score += 20;
  else if (userRiskScore < 400) score -= 10;
  factors.push(`Base risk: ${Math.min(100, Math.max(0, score))}%`);
  return { riskScore: Math.min(100, Math.max(0, score)), factors };
}

// Compute user risk score (0-850, credit-like)
async function computeUserRiskScore(userId) {
  const tx = await db.query('SELECT COUNT(*) as c, COALESCE(SUM(CASE WHEN fraud_status = ? THEN 1 ELSE 0 END), 0) as blocked FROM transactions t JOIN accounts a ON t.account_id = a.id WHERE a.user_id = ?', ['blocked', userId]);
  const acc = await db.query('SELECT COALESCE(SUM(balance), 0) as total FROM accounts WHERE user_id = ?', [userId]);
  const totalBalance = Number(acc.rows[0]?.total || 0);
  const blockedCount = Number(tx.rows[0]?.blocked || 0);
  let score = 650; // Base
  if (totalBalance > 10000) score += 50;
  else if (totalBalance > 5000) score += 25;
  if (blockedCount > 0) score -= blockedCount * 50;
  return Math.min(850, Math.max(300, score));
}

// ==================== Initialize Database ====================
async function initializeDatabase() {
  const isPostgres = db.DB_TYPE === 'postgres';

  const usersTable = isPostgres
    ? `CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        refresh_token TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    : `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        refresh_token TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`;

  const accountsTable = isPostgres
    ? `CREATE TABLE IF NOT EXISTS accounts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        account_type VARCHAR(50) NOT NULL,
        account_number VARCHAR(20) UNIQUE NOT NULL,
        balance DECIMAL(15,2) DEFAULT 0.00,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    : `CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        account_type TEXT NOT NULL,
        account_number TEXT UNIQUE NOT NULL,
        balance REAL DEFAULT 0.00,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )`;

  const transactionsTable = isPostgres
    ? `CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        account_id INTEGER NOT NULL REFERENCES accounts(id),
        to_account_id INTEGER REFERENCES accounts(id),
        type VARCHAR(50) NOT NULL,
        amount DECIMAL(15,2) NOT NULL,
        description TEXT,
        category VARCHAR(100),
        merchant TEXT,
        fraud_score INTEGER DEFAULT 0,
        fraud_status VARCHAR(20) DEFAULT 'safe',
        fraud_reasons TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    : `CREATE TABLE IF NOT EXISTS transactions (
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
      )`;

  const budgetsTable = isPostgres
    ? `CREATE TABLE IF NOT EXISTS budgets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        category VARCHAR(100) NOT NULL,
        limit_amount DECIMAL(15,2) NOT NULL,
        spent_amount DECIMAL(15,2) DEFAULT 0.00,
        month VARCHAR(7) NOT NULL
      )`
    : `CREATE TABLE IF NOT EXISTS budgets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        limit_amount REAL NOT NULL,
        spent_amount REAL DEFAULT 0.00,
        month TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )`;

  const securityAlertsTable = isPostgres
    ? `CREATE TABLE IF NOT EXISTS security_alerts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        transaction_id INTEGER REFERENCES transactions(id),
        alert_type VARCHAR(100) NOT NULL,
        severity VARCHAR(20) NOT NULL,
        message TEXT NOT NULL,
        resolved BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    : `CREATE TABLE IF NOT EXISTS security_alerts (
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
      )`;

  const auditLogTable = isPostgres
    ? `CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action VARCHAR(100) NOT NULL,
        resource VARCHAR(100),
        resource_id INTEGER,
        details TEXT,
        ip_address VARCHAR(45),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    : `CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        resource TEXT,
        resource_id INTEGER,
        details TEXT,
        ip_address VARCHAR(45),
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`;

  for (const stmt of [usersTable, accountsTable, transactionsTable, budgetsTable, securityAlertsTable, auditLogTable]) {
    await db.run(stmt);
  }
  // Enterprise features migration
  try {
    const enterpriseMigration = require('./migrations/002_enterprise');
    await enterpriseMigration.run(db);
    console.log('✅ Enterprise tables initialized');
  } catch (e) {
    console.warn('Enterprise migration:', e.message);
  }
  console.log('✅ Database tables initialized');
}

// ==================== Auth Routes ====================

app.post('/api/auth/register', async (req, res) => {
  try {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.errors?.[0]?.message || 'Invalid input' });
    }
    const { username, email, password } = parsed.data;

    const password_hash = await bcrypt.hash(password, config.BCRYPT_ROUNDS || 12);

    try {
      const r = await db.run(
        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
        [username, email, password_hash]
      );
      const userId = r.lastID;

      const checkingNumber = String(Math.floor(1000000000 + Math.random() * 9000000000));
      const savingsNumber = String(Math.floor(1000000000 + Math.random() * 9000000000));

      await db.run(
        'INSERT INTO accounts (user_id, account_type, account_number, balance) VALUES (?, ?, ?, ?)',
        [userId, 'checking', checkingNumber, 2500.0]
      );
      await db.run(
        'INSERT INTO accounts (user_id, account_type, account_number, balance) VALUES (?, ?, ?, ?)',
        [userId, 'savings', savingsNumber, 5000.0]
      );

      const month = currentMonthYYYYMM();
      const seed = [
        ['groceries', 600],
        ['utilities', 300],
        ['entertainment', 400],
        ['dining', 500],
        ['transport', 400],
        ['shopping', 800],
      ];
      for (const [category, limit] of seed) {
        await db.run(
          'INSERT INTO budgets (user_id, category, limit_amount, spent_amount, month) VALUES (?, ?, ?, 0, ?)',
          [userId, category, limit, month]
        );
      }

      const token = jwt.sign({ userId }, config.JWT_SECRET, { expiresIn: config.JWT_EXPIRES_IN || '1h' });
      await auditLog(userId, 'REGISTER', 'user', userId, { email }, req);
      res.json({ success: true, token, userId });
    } catch (err) {
      if (err.code === 'SQLITE_CONSTRAINT' || err.constraint) {
        return res.status(400).json({ error: 'Username or email already exists' });
      }
      throw err;
    }
  } catch (e) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const { email, password } = parsed.data;

    const user = await db.queryOne('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user.id }, config.JWT_SECRET, { expiresIn: config.JWT_EXPIRES_IN || '1h' });
    await auditLog(user.id, 'LOGIN', 'user', user.id, {}, req);
    res.json({ token, userId: user.id });
  } catch (e) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// ==================== API Routes ====================

app.get('/api/accounts/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  if (Number(userId) !== Number(req.user.userId)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const rows = await db.query('SELECT * FROM accounts WHERE user_id = ?', [userId]);
  res.json(rows.rows);
});

app.get('/api/user/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  if (Number(userId) !== Number(req.user.userId)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const user = await db.queryOne('SELECT id, username, email, created_at FROM users WHERE id = ?', [userId]);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// Transfer between accounts (NEW)
app.post('/api/transactions/transfer', authenticate, async (req, res) => {
  const { fromAccountId, toAccountId, amount, description } = req.body || {};

  if (!fromAccountId || !toAccountId || !validatePositiveNumber(amount)) {
    return res.status(400).json({ error: 'fromAccountId, toAccountId, and positive amount required' });
  }

  if (Number(fromAccountId) === Number(toAccountId)) {
    return res.status(400).json({ error: 'Cannot transfer to same account' });
  }

  try {
    const fromOwned = await assertAccountOwnedByUser(fromAccountId, req.user.userId);
    const toOwned = await assertAccountOwnedByUser(toAccountId, req.user.userId);
    if (!fromOwned || !toOwned) return res.status(403).json({ error: 'Account not yours' });

    const amountNum = Number(amount);
    const fromAcc = await db.queryOne('SELECT id, balance FROM accounts WHERE id = ?', [fromAccountId]);
    const toAcc = await db.queryOne('SELECT id FROM accounts WHERE id = ?', [toAccountId]);
    if (!fromAcc || !toAcc) return res.status(404).json({ error: 'Account not found' });
    if (Number(fromAcc.balance) < amountNum) return res.status(400).json({ error: 'Insufficient funds' });

    const desc = description || 'Transfer between accounts';
    await db.run('UPDATE accounts SET balance = balance - ? WHERE id = ?', [amountNum, fromAccountId]);
    await db.run('UPDATE accounts SET balance = balance + ? WHERE id = ?', [amountNum, toAccountId]);
    await db.run(
      'INSERT INTO transactions (account_id, to_account_id, type, amount, description, category, fraud_status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [fromAccountId, toAccountId, 'transfer', -amountNum, desc, 'transfer', 'safe']
    );
    await db.run(
      'INSERT INTO transactions (account_id, to_account_id, type, amount, description, category, fraud_status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [toAccountId, fromAccountId, 'transfer', amountNum, desc, 'transfer', 'safe']
    );

    await auditLog(req.user.userId, 'TRANSFER', 'transaction', null, { fromAccountId, toAccountId, amount: amountNum }, req);
    res.json({ success: true, message: 'Transfer successful' });
  } catch (e) {
    res.status(500).json({ error: 'Transfer failed' });
  }
});

app.post('/api/transactions/deposit', authenticate, async (req, res) => {
  const { accountId, amount, description } = req.body || {};

  if (!accountId || !validatePositiveNumber(amount)) {
    return res.status(400).json({ error: 'accountId and positive amount required' });
  }

  try {
    const owned = await assertAccountOwnedByUser(accountId, req.user.userId);
    if (!owned) return res.status(403).json({ error: 'Forbidden' });

    const amountNum = Number(amount);
    await db.run('UPDATE accounts SET balance = balance + ? WHERE id = ?', [amountNum, accountId]);
    const r = await db.run(
      "INSERT INTO transactions (account_id, type, amount, description, category, fraud_status) VALUES (?, 'deposit', ?, ?, 'income', 'safe')",
      [accountId, amountNum, description || 'Deposit']
    );

    await auditLog(req.user.userId, 'DEPOSIT', 'transaction', r.lastID, { accountId, amount: amountNum }, req);
    res.json({ success: true, transactionId: r.lastID, message: 'Deposit successful' });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/transactions/payment', authenticate, async (req, res) => {
  const { accountId, amount, merchant, category } = req.body || {};

  if (!accountId || !validatePositiveNumber(amount) || !merchant) {
    return res.status(400).json({ error: 'accountId, merchant, and positive amount required' });
  }

  try {
    const owned = await assertAccountOwnedByUser(accountId, req.user.userId);
    if (!owned) return res.status(403).json({ error: 'Forbidden' });

    const amountNum = Number(amount);
    const fraudAnalysis = analyzeFraud({ amount: amountNum, merchant });

    if (fraudAnalysis.status === 'blocked') {
      await db.run(
        'INSERT INTO transactions (account_id, type, amount, merchant, category, fraud_score, fraud_status, fraud_reasons) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [accountId, 'payment', amountNum, merchant, category || 'general', fraudAnalysis.riskScore, 'blocked', JSON.stringify(fraudAnalysis.reasons)]
      );
      await auditLog(req.user.userId, 'PAYMENT_BLOCKED', 'transaction', null, { merchant, amount: amountNum, fraud: fraudAnalysis }, req);
      return res.json({
        success: false,
        blocked: true,
        fraud: fraudAnalysis,
        message: 'Transaction blocked due to fraud detection',
      });
    }

    const r = await db.run(
      'UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?',
      [amountNum, accountId, amountNum]
    );
    if (r.changes === 0) return res.status(400).json({ error: 'Insufficient funds' });

    const txR = await db.run(
      'INSERT INTO transactions (account_id, type, amount, merchant, category, fraud_score, fraud_status, fraud_reasons) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [accountId, 'payment', amountNum, merchant, category || 'general', fraudAnalysis.riskScore, fraudAnalysis.status, JSON.stringify(fraudAnalysis.reasons)]
    );

    await auditLog(req.user.userId, 'PAYMENT', 'transaction', txR.lastID, { merchant, amount: amountNum }, req);
    res.json({
      success: true,
      transactionId: txR.lastID,
      fraud: fraudAnalysis,
      message: fraudAnalysis.status === 'flagged' ? 'Transaction flagged for review' : 'Payment successful',
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/transactions/:accountId', authenticate, async (req, res) => {
  const { accountId } = req.params;

  try {
    const owned = await assertAccountOwnedByUser(accountId, req.user.userId);
    if (!owned) return res.status(403).json({ error: 'Forbidden' });

    const rows = await db.query(
      'SELECT * FROM transactions WHERE account_id = ? ORDER BY created_at DESC',
      [accountId]
    );
    res.json(rows.rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all transactions for user (across accounts)
app.get('/api/transactions/user/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  if (Number(userId) !== Number(req.user.userId)) return res.status(403).json({ error: 'Forbidden' });

  const rows = await db.query(
    `SELECT t.*, a.account_type, a.account_number FROM transactions t
     JOIN accounts a ON t.account_id = a.id
     WHERE a.user_id = ? ORDER BY t.created_at DESC LIMIT 100`,
    [userId]
  );
  res.json(rows.rows);
});

app.get('/api/budget/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  if (Number(userId) !== Number(req.user.userId)) return res.status(403).json({ error: 'Forbidden' });

  const currentMonth = currentMonthYYYYMM();
  const rows = await db.query('SELECT * FROM budgets WHERE user_id = ? AND month = ?', [userId, currentMonth]);
  res.json(rows.rows);
});

app.post('/api/budget/update', authenticate, async (req, res) => {
  const { userId, category, amount } = req.body || {};

  if (!userId || !category || !validatePositiveNumber(amount)) {
    return res.status(400).json({ error: 'userId, category, positive amount required' });
  }

  if (Number(userId) !== Number(req.user.userId)) return res.status(403).json({ error: 'Forbidden' });

  const currentMonth = currentMonthYYYYMM();
  await db.run(
    'UPDATE budgets SET spent_amount = spent_amount + ? WHERE user_id = ? AND category = ? AND month = ?',
    [Number(amount), userId, category, currentMonth]
  );
  res.json({ success: true });
});

app.get('/api/security/stats/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  if (Number(userId) !== Number(req.user.userId)) return res.status(403).json({ error: 'Forbidden' });

  const rows = await db.query(
    `SELECT
        COUNT(*) as total_blocked,
        COALESCE(SUM(CASE WHEN fraud_status = 'blocked' THEN amount ELSE 0 END), 0) as money_protected
     FROM transactions t
     JOIN accounts a ON t.account_id = a.id
     WHERE a.user_id = ? AND fraud_status = 'blocked'`,
    [userId]
  );
  res.json(rows.rows[0] || { total_blocked: 0, money_protected: 0 });
});

// ==================== P2P PAYMENTS (Zelle-like) ====================
app.post('/api/p2p/send', authenticate, async (req, res) => {
  const { toEmail, fromAccountId, amount, memo } = req.body || {};
  if (!toEmail || !fromAccountId || !validatePositiveNumber(amount)) {
    return res.status(400).json({ error: 'toEmail, fromAccountId, amount required' });
  }
  try {
    const owned = await assertAccountOwnedByUser(fromAccountId, req.user.userId);
    if (!owned) return res.status(403).json({ error: 'Forbidden' });
    const receiver = await db.queryOne('SELECT id FROM users WHERE email = ?', [toEmail.trim().toLowerCase()]);
    if (!receiver) return res.status(404).json({ error: 'Recipient not found' });
    if (receiver.id === req.user.userId) return res.status(400).json({ error: 'Cannot send to yourself' });
    const amountNum = Number(amount);
    const senderAcc = await db.queryOne('SELECT id, balance FROM accounts WHERE id = ?', [fromAccountId]);
    if (!senderAcc || Number(senderAcc.balance) < amountNum) return res.status(400).json({ error: 'Insufficient funds' });
    const receiverChecking = await db.queryOne('SELECT id FROM accounts WHERE user_id = ? AND account_type = ?', [receiver.id, 'checking']);
    if (!receiverChecking) return res.status(400).json({ error: 'Recipient has no checking account' });

    await db.run('UPDATE accounts SET balance = balance - ? WHERE id = ?', [amountNum, fromAccountId]);
    await db.run('UPDATE accounts SET balance = balance + ? WHERE id = ?', [amountNum, receiverChecking.id]);
    await db.run('INSERT INTO p2p_transfers (sender_user_id, receiver_user_id, sender_account_id, amount, memo) VALUES (?, ?, ?, ?, ?)', [req.user.userId, receiver.id, fromAccountId, amountNum, memo || '']);
    await db.run('INSERT INTO transactions (account_id, type, amount, description, category, fraud_status) VALUES (?, ?, ?, ?, ?, ?)', [fromAccountId, 'p2p', -amountNum, `P2P to ${toEmail}`, 'transfer', 'safe']);
    await db.run('INSERT INTO transactions (account_id, type, amount, description, category, fraud_status) VALUES (?, ?, ?, ?, ?, ?)', [receiverChecking.id, 'p2p', amountNum, `P2P from user`, 'transfer', 'safe']);
    await auditLog(req.user.userId, 'P2P_SEND', 'p2p_transfer', null, { toEmail, amount: amountNum }, req);
    res.json({ success: true, message: 'P2P transfer complete' });
  } catch (e) { res.status(500).json({ error: 'P2P failed' }); }
});

app.get('/api/p2p/history/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  if (Number(userId) !== Number(req.user.userId)) return res.status(403).json({ error: 'Forbidden' });
  const rows = await db.query(`SELECT p.*, u1.username as sender_name, u2.username as receiver_name, u1.email as sender_email, u2.email as receiver_email FROM p2p_transfers p
    JOIN users u1 ON p.sender_user_id = u1.id JOIN users u2 ON p.receiver_user_id = u2.id
    WHERE p.sender_user_id = ? OR p.receiver_user_id = ? ORDER BY p.created_at DESC LIMIT 50`, [userId, userId]);
  res.json(rows.rows);
});

// ==================== LOANS (Risk Modeling) ====================
app.post('/api/loans/apply', authenticate, async (req, res) => {
  const { amount, termMonths, purpose } = req.body || {};
  if (!validatePositiveNumber(amount) || !termMonths || termMonths < 1 || termMonths > 360) {
    return res.status(400).json({ error: 'Valid amount and term (1-360 months) required' });
  }
  try {
    const userRisk = await computeUserRiskScore(req.user.userId);
    const risk = calculateLoanRisk(Number(amount), Number(termMonths), userRisk);
    const interestRate = 5 + (risk.riskScore / 100) * 15; // 5-20% based on risk
    await db.run('INSERT INTO loans (user_id, amount, term_months, interest_rate, risk_score, risk_factors, status, purpose) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [req.user.userId, Number(amount), Number(termMonths), interestRate, risk.riskScore, JSON.stringify(risk.factors), 'pending', purpose || 'general']);
    await auditLog(req.user.userId, 'LOAN_APPLY', 'loan', null, { amount, termMonths, riskScore: risk.riskScore }, req);
    res.json({ success: true, riskScore: risk.riskScore, interestRate, factors: risk.factors, message: 'Application submitted' });
  } catch (e) { res.status(500).json({ error: 'Loan application failed' }); }
});

app.get('/api/loans/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  if (Number(userId) !== Number(req.user.userId)) return res.status(403).json({ error: 'Forbidden' });
  const rows = await db.query('SELECT * FROM loans WHERE user_id = ? ORDER BY created_at DESC', [userId]);
  res.json(rows.rows);
});

// ==================== CRYPTO WALLETS ====================
const CRYPTO_SYMBOLS = ['BTC', 'ETH', 'USDC'];
app.get('/api/crypto/wallets/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  if (Number(userId) !== Number(req.user.userId)) return res.status(403).json({ error: 'Forbidden' });
  let rows = await db.query('SELECT * FROM crypto_wallets WHERE user_id = ?', [userId]);
  if (!rows.rows.length) {
    for (const sym of CRYPTO_SYMBOLS) {
      await db.run('INSERT INTO crypto_wallets (user_id, symbol, balance, wallet_address) VALUES (?, ?, 0, ?)', [userId, sym, '0x' + crypto.randomBytes(20).toString('hex')]);
    }
    rows = await db.query('SELECT * FROM crypto_wallets WHERE user_id = ?', [userId]);
  }
  res.json(rows.rows);
});

app.post('/api/crypto/buy', authenticate, async (req, res) => {
  const { userId, walletId, amount, fromAccountId } = req.body || {};
  if (Number(userId) !== Number(req.user.userId)) return res.status(403).json({ error: 'Forbidden' });
  if (!walletId || !validatePositiveNumber(amount) || !fromAccountId) return res.status(400).json({ error: 'walletId, amount, fromAccountId required' });
  try {
    const owned = await assertAccountOwnedByUser(fromAccountId, req.user.userId);
    if (!owned) return res.status(403).json({ error: 'Forbidden' });
    const wallet = await db.queryOne('SELECT * FROM crypto_wallets WHERE id = ? AND user_id = ?', [walletId, userId]);
    if (!wallet) return res.status(404).json({ error: 'Wallet not found' });
    const amountNum = Number(amount);
    const usdAmount = amountNum * (wallet.symbol === 'BTC' ? 50000 : wallet.symbol === 'ETH' ? 3000 : 1);
    const acc = await db.queryOne('SELECT balance FROM accounts WHERE id = ?', [fromAccountId]);
    if (!acc || Number(acc.balance) < usdAmount) return res.status(400).json({ error: 'Insufficient USD balance' });

    await db.run('UPDATE accounts SET balance = balance - ? WHERE id = ?', [usdAmount, fromAccountId]);
    await db.run('UPDATE crypto_wallets SET balance = balance + ? WHERE id = ?', [amountNum, walletId]);
    await db.run('INSERT INTO crypto_transactions (wallet_id, type, amount, tx_hash) VALUES (?, ?, ?, ?)', [walletId, 'buy', amountNum, crypto.randomBytes(32).toString('hex')]);
    await auditLog(userId, 'CRYPTO_BUY', 'crypto_wallet', walletId, { symbol: wallet.symbol, amount: amountNum }, req);
    res.json({ success: true, newBalance: Number(wallet.balance) + amountNum });
  } catch (e) { res.status(500).json({ error: 'Buy failed' }); }
});

app.post('/api/crypto/sell', authenticate, async (req, res) => {
  const { userId, walletId, amount, toAccountId } = req.body || {};
  if (Number(userId) !== Number(req.user.userId)) return res.status(403).json({ error: 'Forbidden' });
  if (!walletId || !validatePositiveNumber(amount) || !toAccountId) return res.status(400).json({ error: 'walletId, amount, toAccountId required' });
  try {
    const owned = await assertAccountOwnedByUser(toAccountId, req.user.userId);
    if (!owned) return res.status(403).json({ error: 'Forbidden' });
    const wallet = await db.queryOne('SELECT * FROM crypto_wallets WHERE id = ? AND user_id = ?', [walletId, userId]);
    if (!wallet || Number(wallet.balance) < Number(amount)) return res.status(400).json({ error: 'Insufficient crypto balance' });
    const amountNum = Number(amount);
    const usdAmount = amountNum * (wallet.symbol === 'BTC' ? 50000 : wallet.symbol === 'ETH' ? 3000 : 1);

    await db.run('UPDATE crypto_wallets SET balance = balance - ? WHERE id = ?', [amountNum, walletId]);
    await db.run('UPDATE accounts SET balance = balance + ? WHERE id = ?', [usdAmount, toAccountId]);
    await db.run('INSERT INTO crypto_transactions (wallet_id, type, amount, tx_hash) VALUES (?, ?, ?, ?)', [walletId, 'sell', -amountNum, crypto.randomBytes(32).toString('hex')]);
    await auditLog(userId, 'CRYPTO_SELL', 'crypto_wallet', walletId, { symbol: wallet.symbol, amount: amountNum }, req);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Sell failed' }); }
});

// ==================== LEDGER (Blockchain-style) ====================
app.get('/api/ledger/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  if (Number(userId) !== Number(req.user.userId)) return res.status(403).json({ error: 'Forbidden' });
  try {
    const rows = await db.query(`SELECT t.id, t.type, t.amount, t.description, t.created_at, a.account_type
      FROM transactions t JOIN accounts a ON t.account_id = a.id WHERE a.user_id = ? ORDER BY t.created_at DESC LIMIT 100`, [userId]);
    const entries = rows.rows.map((r, i) => ({ ...r, entryHash: createLedgerHash(r), index: rows.rows.length - i }));
    res.json(entries);
  } catch (e) { res.json([]); }
});

// ==================== RECURRING CONTRACTS (Smart Contract-like) ====================
app.post('/api/contracts/create', authenticate, async (req, res) => {
  const { accountId, payee, amount, frequency } = req.body || {};
  if (!accountId || !payee || !validatePositiveNumber(amount) || !frequency) return res.status(400).json({ error: 'accountId, payee, amount, frequency required' });
  if (!['weekly', 'monthly', 'yearly'].includes(frequency)) return res.status(400).json({ error: 'frequency: weekly, monthly, yearly' });
  try {
    const owned = await assertAccountOwnedByUser(accountId, req.user.userId);
    if (!owned) return res.status(403).json({ error: 'Forbidden' });
    const d = new Date();
    if (frequency === 'weekly') d.setDate(d.getDate() + 7);
    else if (frequency === 'monthly') d.setMonth(d.getMonth() + 1);
    else d.setFullYear(d.getFullYear() + 1);
    const nextDue = d.toISOString().slice(0, 10);
    await db.run('INSERT INTO recurring_contracts (user_id, account_id, payee, amount, frequency, next_due) VALUES (?, ?, ?, ?, ?, ?)', [req.user.userId, accountId, payee, Number(amount), frequency, nextDue]);
    res.json({ success: true, nextDue });
  } catch (e) { res.status(500).json({ error: 'Contract creation failed' }); }
});

app.get('/api/contracts/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  if (Number(userId) !== Number(req.user.userId)) return res.status(403).json({ error: 'Forbidden' });
  const rows = await db.query('SELECT * FROM recurring_contracts WHERE user_id = ? AND active = 1 ORDER BY next_due', [userId]);
  res.json(rows.rows);
});

// ==================== BUDGET GOALS ====================
app.post('/api/budget/goals', authenticate, async (req, res) => {
  const { userId, goalName, targetAmount, deadline } = req.body || {};
  if (Number(userId) !== Number(req.user.userId)) return res.status(403).json({ error: 'Forbidden' });
  if (!goalName || !validatePositiveNumber(targetAmount)) return res.status(400).json({ error: 'goalName, targetAmount required' });
  try {
    const r = await db.run('INSERT INTO budget_goals (user_id, goal_name, target_amount, deadline) VALUES (?, ?, ?, ?)', [userId, goalName, Number(targetAmount), deadline || null]);
    res.json({ success: true, id: r.lastID });
  } catch (e) { res.status(500).json({ error: 'Goal creation failed' }); }
});

app.get('/api/budget/goals/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  if (Number(userId) !== Number(req.user.userId)) return res.status(403).json({ error: 'Forbidden' });
  const rows = await db.query('SELECT * FROM budget_goals WHERE user_id = ? ORDER BY deadline', [userId]);
  res.json(rows.rows);
});

// ==================== RISK SCORE ====================
app.get('/api/risk/score/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  if (Number(userId) !== Number(req.user.userId)) return res.status(403).json({ error: 'Forbidden' });
  const score = await computeUserRiskScore(userId);
  try {
    await db.run('DELETE FROM user_risk_scores WHERE user_id = ?', [userId]);
    await db.run('INSERT INTO user_risk_scores (user_id, score, factors) VALUES (?, ?, ?)', [userId, score, JSON.stringify({ computed: true })]);
  } catch (_) {}
  res.json({ score, tier: score >= 720 ? 'excellent' : score >= 670 ? 'good' : score >= 580 ? 'fair' : 'poor' });
});

// ==================== BANK RESERVES (Stability Monitor) ====================
app.get('/api/reserves', authenticate, async (req, res) => {
  const deposits = await db.query('SELECT COALESCE(SUM(balance), 0) as total FROM accounts WHERE account_type IN (?, ?)', ['checking', 'savings']);
  const total = Number(deposits.rows[0]?.total || 0);
  const ratio = 10;
  const reserve = total * (ratio / 100);
  res.json({ totalDeposits: total, reserveRatio: ratio, reserveAmount: reserve, status: reserve > 0 ? 'healthy' : 'critical' });
});

// ==================== FINANCIAL LITERACY CONTENT ====================
app.get('/api/literacy/modules', (req, res) => {
  res.json([
    { id: 1, title: 'Budgeting Basics', topics: ['50/30/20 rule', 'Tracking expenses', 'Emergency fund'] },
    { id: 2, title: 'Credit & Debt', topics: ['Credit scores', 'Interest rates', 'Debt payoff strategies'] },
    { id: 3, title: 'Investing 101', topics: ['Stocks vs bonds', 'Diversification', 'Compound interest'] },
    { id: 4, title: 'Crypto & Digital Assets', topics: ['What is blockchain', 'Wallets', 'Risks'] },
  ]);
});

// ==================== Health Check (production-ready) ====================
app.get('/api/health', async (req, res) => {
  let dbStatus = 'unknown';
  try {
    const r = await db.queryOne('SELECT 1 as ok');
    dbStatus = r ? 'connected' : 'error';
  } catch (e) {
    dbStatus = 'error';
  }
  res.json({
    status: dbStatus === 'connected' ? 'ok' : 'degraded',
    database: dbStatus,
    version: process.env.npm_package_version || '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

// ==================== Start Server ====================
async function start() {
  try {
    await db.connect();
    console.log(`✅ Connected to ${db.DB_TYPE} database`);
    await initializeDatabase();

    app.listen(PORT, () => {
      console.log(`
╔══════════════════════════════════════════════╗
║   🏦 SecureBank API Server                  ║
║   Port: ${PORT}                                ║
║   Database: ${db.DB_TYPE.padEnd(10)}                     ║
║   Environment: ${(config.NODE_ENV || 'development').padEnd(10)}             ║
║   Status: ✅ Running                         ║
╚══════════════════════════════════════════════╝
      `);
    });
  } catch (err) {
    console.error('Failed to start:', err);
    process.exit(1);
  }
}

start();

process.on('SIGINT', async () => {
  await db.close();
  console.log('Database connection closed');
  process.exit(0);
});
