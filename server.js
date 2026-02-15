const path = require('path');
const fs = require('fs');

// Load .env from project directory (same folder as server.js)
const envPath = path.join(__dirname, '.env');
const envExamplePath = path.join(__dirname, '.env.example');
if (!fs.existsSync(envPath) && fs.existsSync(envExamplePath)) {
    fs.copyFileSync(envExamplePath, envPath);
    console.log('📄 Created .env from .env.example - add your GEMINI_API_KEY to .env');
}
try {
    require('dotenv').config({ path: envPath });
} catch (e) { /* dotenv optional */ }

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const initSqlJs = require('sql.js');

const JWT_SECRET = process.env.JWT_SECRET || 'securebank-dev-secret-change-in-production';

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'securebank.db');

// API Keys (from .env - keep secure!) - trim to avoid whitespace issues
const MASSIVE_API_KEY = (process.env.MASSIVE_API_KEY || '').trim();
const FREECRYPTOAPI_KEY = (process.env.FREECRYPTOAPI_KEY || '').trim();
const GEMINI_API_KEY = (process.env.GEMINI_API_KEY || '').trim();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(express.static('.')); // Serve root (index.html, chatbot.html)

// Database (sql.js - pure JS, no native build)
let sqlDb = null;
const db = {
    run: function(sql, params, callback) {
        if (typeof params === 'function') { callback = params; params = []; }
        try {
            sqlDb.run(sql, params || []);
            const r = sqlDb.exec('SELECT last_insert_rowid() as id, changes() as c');
            const lastID = (r[0]?.values?.[0]?.[0] ?? 0) | 0;
            const changes = (r[0]?.values?.[0]?.[1] ?? 0) | 0;
            if (callback) callback.call({ lastID, changes }, null);
        } catch (e) {
            if (callback) callback.call({ lastID: 0, changes: 0 }, e);
        }
    },
    get: function(sql, params, callback) {
        if (typeof params === 'function') { callback = params; params = []; }
        try {
            const stmt = sqlDb.prepare(sql);
            stmt.bind(params || []);
            const row = stmt.step() ? stmt.getAsObject() : null;
            stmt.free();
            callback(null, row);
        } catch (e) {
            callback(e, null);
        }
    },
    all: function(sql, params, callback) {
        if (typeof params === 'function') { callback = params; params = []; }
        try {
            const stmt = sqlDb.prepare(sql);
            stmt.bind(params || []);
            const rows = [];
            while (stmt.step()) rows.push(stmt.getAsObject());
            stmt.free();
            callback(null, rows);
        } catch (e) {
            callback(e, null);
        }
    },
    close: function(callback) {
        try {
            if (sqlDb) {
                const data = sqlDb.export();
                fs.writeFileSync(DB_PATH, Buffer.from(data));
                sqlDb.close();
                sqlDb = null;
            }
            if (callback) callback(null);
        } catch (e) {
            if (callback) callback(e);
        }
    }
};

// Create tables
function initializeDatabase() {
    try {
        sqlDb.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            account_type TEXT DEFAULT 'regular',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        try { sqlDb.run('ALTER TABLE users ADD COLUMN account_type TEXT DEFAULT \'regular\''); } catch (e) { /* column may exist */ }
        sqlDb.run(`
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                account_type TEXT NOT NULL,
                account_number TEXT UNIQUE NOT NULL,
                balance REAL DEFAULT 0.00,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);
        sqlDb.run(`
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
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
            )
        `);
        sqlDb.run(`
            CREATE TABLE IF NOT EXISTS budgets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                limit_amount REAL NOT NULL,
                spent_amount REAL DEFAULT 0.00,
                month TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);
        sqlDb.run(`
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                transaction_id INTEGER,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                resolved BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (transaction_id) REFERENCES transactions(id)
            )
        `);
        sqlDb.run(`
            CREATE TABLE IF NOT EXISTS stock_watchlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                symbol TEXT NOT NULL,
                name TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, symbol),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);
        sqlDb.run(`
            CREATE TABLE IF NOT EXISTS crypto_watchlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                symbol TEXT NOT NULL,
                name TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, symbol),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);
        sqlDb.run(`
            CREATE TABLE IF NOT EXISTS user_progress (
                user_id INTEGER PRIMARY KEY,
                progress_json TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);
        sqlDb.run(`
            CREATE TABLE IF NOT EXISTS live_sim_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                symbols TEXT NOT NULL,
                allocations TEXT NOT NULL,
                start_prices TEXT NOT NULL,
                start_date TEXT NOT NULL,
                total_invested REAL NOT NULL,
                last_report_date TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Database tables initialized');
    } catch (e) {
        console.error('Database init error:', e);
    }
}

// ==================== FRAUD DETECTION LOGIC ====================

function analyzeFraud(transaction) {
    let riskScore = 0;
    const reasons = [];

    // Suspicious merchant patterns
    const suspiciousKeywords = ['dark web', 'unknown', 'crypto exchange', 'suspicious', 'unauthorized'];
    const merchantLower = (transaction.merchant || '').toLowerCase();
    
    for (const keyword of suspiciousKeywords) {
        if (merchantLower.includes(keyword)) {
            riskScore += 70;
            reasons.push(`High-risk merchant detected: ${keyword}`);
            break;
        }
    }

    // Large transaction check
    if (transaction.amount > 5000) {
        riskScore += 40;
        reasons.push(`Large transaction amount: $${transaction.amount.toFixed(2)}`);
    } else if (transaction.amount > 2000) {
        riskScore += 20;
        reasons.push('Elevated transaction amount');
    }

    // Determine status
    let status = 'safe';
    if (riskScore >= 70) {
        status = 'blocked';
    } else if (riskScore >= 40) {
        status = 'flagged';
    }

    return {
        riskScore: Math.min(riskScore, 100),
        status,
        reasons: reasons.length > 0 ? reasons : ['Normal transaction pattern']
    };
}

// ==================== AUTH MIDDLEWARE ====================

function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : req.body?.token || req.query?.token;
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (e) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// ==================== API ROUTES ====================

// Register
app.post('/api/auth/register', (req, res) => {
    const { username, email, password, accountType } = req.body || {};
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Username, email, and password required' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    const accType = accountType === 'manager' ? 'manager' : 'regular';
    const hash = bcrypt.hashSync(password, 10);
    const accountNumber = () => String(Math.floor(1000000000000000 + Math.random() * 9000000000000000)).slice(-4);
    db.run(
        'INSERT INTO users (username, email, password_hash, account_type) VALUES (?, ?, ?, ?)',
        [username.trim(), email.trim().toLowerCase(), hash, accType],
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Username or email already exists' });
                return res.status(500).json({ error: err.message });
            }
            const userId = this.lastID;
            db.run('INSERT INTO accounts (user_id, account_type, account_number, balance) VALUES (?, ?, ?, ?)', [userId, 'checking', accountNumber(), 0]);
            db.run('INSERT INTO accounts (user_id, account_type, account_number, balance) VALUES (?, ?, ?, ?)', [userId, 'savings', accountNumber(), 0]);
            const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
            res.json({ success: true, token, userId, username });
        }
    );
});

// Login
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }
        db.get('SELECT id, username, password_hash, account_type FROM users WHERE email = ?', [email.trim().toLowerCase()], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(401).json({ error: 'Invalid email or password' });
        if (!bcrypt.compareSync(password, row.password_hash)) return res.status(401).json({ error: 'Invalid email or password' });
        const token = jwt.sign({ userId: row.id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token, userId: row.id, username: row.username, accountType: row.account_type || 'regular' });
    });
});

// Get current user (optional - for frontend to verify token)
app.get('/api/auth/me', authMiddleware, (req, res) => {
    db.get('SELECT id, username, email, account_type FROM users WHERE id = ?', [req.userId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'User not found' });
        res.json({ userId: row.id, username: row.username, email: row.email, accountType: row.account_type || 'regular' });
    });
});

// Save/load user progress (accounts, transactions, budget)
app.get('/api/progress', authMiddleware, (req, res) => {
    db.get('SELECT progress_json FROM user_progress WHERE user_id = ?', [req.userId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        const progress = row?.progress_json ? JSON.parse(row.progress_json) : null;
        res.json({ progress });
    });
});

app.put('/api/progress', authMiddleware, (req, res) => {
    const { progress } = req.body || {};
    if (!progress) return res.status(400).json({ error: 'progress required' });
    const json = typeof progress === 'string' ? progress : JSON.stringify(progress);
    db.run(
        'INSERT OR REPLACE INTO user_progress (user_id, progress_json, updated_at) VALUES (?, ?, datetime("now"))',
        [req.userId, json],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

// Get user accounts
app.get('/api/accounts/:userId', (req, res) => {
    const { userId } = req.params;
    
    db.all(
        'SELECT * FROM accounts WHERE user_id = ?',
        [userId],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json(rows);
        }
    );
});

// Create deposit transaction
app.post('/api/transactions/deposit', (req, res) => {
    const { accountId, amount, description } = req.body;

    // Update account balance
    db.run(
        'UPDATE accounts SET balance = balance + ? WHERE id = ?',
        [amount, accountId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            // Create transaction record
            db.run(
                `INSERT INTO transactions (account_id, type, amount, description, category, fraud_status) 
                 VALUES (?, 'deposit', ?, ?, 'income', 'safe')`,
                [accountId, amount, description],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }
                    res.json({ 
                        success: true, 
                        transactionId: this.lastID,
                        message: 'Deposit successful'
                    });
                }
            );
        }
    );
});

// Create payment transaction with fraud check
app.post('/api/transactions/payment', (req, res) => {
    const { accountId, amount, merchant, category } = req.body;

    // Fraud analysis
    const fraudAnalysis = analyzeFraud({ amount, merchant });

    if (fraudAnalysis.status === 'blocked') {
        // Log blocked transaction but don't process
        db.run(
            `INSERT INTO transactions (account_id, type, amount, merchant, category, fraud_score, fraud_status, fraud_reasons) 
             VALUES (?, 'payment', ?, ?, ?, ?, 'blocked', ?)`,
            [accountId, amount, merchant, category, fraudAnalysis.riskScore, JSON.stringify(fraudAnalysis.reasons)],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                
                res.json({ 
                    success: false,
                    blocked: true,
                    fraud: fraudAnalysis,
                    message: 'Transaction blocked due to fraud detection'
                });
            }
        );
        return;
    }

    // Process transaction
    db.run(
        'UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?',
        [amount, accountId, amount],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            
            if (this.changes === 0) {
                return res.status(400).json({ error: 'Insufficient funds' });
            }

            // Create transaction record
            db.run(
                `INSERT INTO transactions (account_id, type, amount, merchant, category, fraud_score, fraud_status, fraud_reasons) 
                 VALUES (?, 'payment', ?, ?, ?, ?, ?, ?)`,
                [accountId, amount, merchant, category, fraudAnalysis.riskScore, fraudAnalysis.status, JSON.stringify(fraudAnalysis.reasons)],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }
                    res.json({ 
                        success: true,
                        transactionId: this.lastID,
                        fraud: fraudAnalysis,
                        message: fraudAnalysis.status === 'flagged' ? 'Transaction flagged for review' : 'Payment successful'
                    });
                }
            );
        }
    );
});

// Get transactions for an account
app.get('/api/transactions/:accountId', (req, res) => {
    const { accountId } = req.params;
    
    db.all(
        'SELECT * FROM transactions WHERE account_id = ? ORDER BY created_at DESC',
        [accountId],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json(rows);
        }
    );
});

// Get budget for user
app.get('/api/budget/:userId', (req, res) => {
    const { userId } = req.params;
    const currentMonth = new Date().toISOString().slice(0, 7); // YYYY-MM
    
    db.all(
        'SELECT * FROM budgets WHERE user_id = ? AND month = ?',
        [userId, currentMonth],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json(rows);
        }
    );
});

// Update budget spending
app.post('/api/budget/update', (req, res) => {
    const { userId, category, amount } = req.body;
    const currentMonth = new Date().toISOString().slice(0, 7);
    
    db.run(
        'UPDATE budgets SET spent_amount = spent_amount + ? WHERE user_id = ? AND category = ? AND month = ?',
        [amount, userId, category, currentMonth],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ success: true });
        }
    );
});

// Get security stats
app.get('/api/security/stats/:userId', (req, res) => {
    const { userId } = req.params;
    
    db.all(
        `SELECT 
            COUNT(*) as total_blocked,
            SUM(CASE WHEN fraud_status = 'blocked' THEN amount ELSE 0 END) as money_protected
         FROM transactions t
         JOIN accounts a ON t.account_id = a.id
         WHERE a.user_id = ? AND fraud_status = 'blocked'`,
        [userId],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json(rows[0] || { total_blocked: 0, money_protected: 0 });
        }
    );
});

// Stock watchlist
app.get('/api/watchlist/stocks/:userId', (req, res) => {
    db.all('SELECT * FROM stock_watchlist WHERE user_id = ? ORDER BY created_at DESC', [req.params.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});
app.post('/api/watchlist/stocks', authMiddleware, (req, res) => {
    const { symbol, name } = req.body || {};
    if (!symbol) return res.status(400).json({ error: 'Symbol required' });
    db.run('INSERT OR IGNORE INTO stock_watchlist (user_id, symbol, name) VALUES (?, ?, ?)', [req.userId, symbol.toUpperCase(), name || null], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: this.lastID });
    });
});
app.delete('/api/watchlist/stocks/:id', authMiddleware, (req, res) => {
    db.run('DELETE FROM stock_watchlist WHERE id = ? AND user_id = ?', [req.params.id, req.userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Crypto watchlist
app.get('/api/watchlist/crypto/:userId', (req, res) => {
    db.all('SELECT * FROM crypto_watchlist WHERE user_id = ? ORDER BY created_at DESC', [req.params.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});
app.post('/api/watchlist/crypto', authMiddleware, (req, res) => {
    const { symbol, name } = req.body || {};
    if (!symbol) return res.status(400).json({ error: 'Symbol required' });
    db.run('INSERT OR IGNORE INTO crypto_watchlist (user_id, symbol, name) VALUES (?, ?, ?)', [req.userId, symbol.toUpperCase(), name || null], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: this.lastID });
    });
});
app.delete('/api/watchlist/crypto/:id', authMiddleware, (req, res) => {
    db.run('DELETE FROM crypto_watchlist WHERE id = ? AND user_id = ?', [req.params.id, req.userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'SecureBank API is running' });
});

// ==================== STOCK DATA HELPERS (MASSIVE/Polygon + Yahoo fallback) ====================
async function fetchMassiveStock(symbol) {
    if (!MASSIVE_API_KEY) return null;
    const bases = ['https://api.massive.com', 'https://api.polygon.io'];
    for (const base of bases) {
        try {
            const url = `${base}/v2/last/trade/${encodeURIComponent(symbol)}?apiKey=${encodeURIComponent(MASSIVE_API_KEY)}`;
            const res = await fetch(url, { headers: { 'Accept': 'application/json' } });
            if (res.ok) {
                const data = await res.json();
                const result = data?.results;
                if (result) {
                    const price = result.p ?? result.price;
                    if (price != null) return { price, changePercent: null };
                }
            }
            const quoteUrl = `${base}/v2/last/nbbo/${encodeURIComponent(symbol)}?apiKey=${encodeURIComponent(MASSIVE_API_KEY)}`;
            const quoteRes = await fetch(quoteUrl, { headers: { 'Accept': 'application/json' } });
            if (quoteRes.ok) {
                const qData = await quoteRes.json();
                const q = qData?.results;
                if (q && (q.P != null || q.p != null)) {
                    const ask = q.P ?? q.ask_price;
                    const bid = q.p ?? q.bid_price;
                    const price = (ask != null && bid != null) ? (Number(ask) + Number(bid)) / 2 : (ask ?? bid);
                    if (price != null) return { price, changePercent: null };
                }
            }
        } catch (e) { /* try next base */ }
    }
    return null;
}

async function fetchYahooStockFallback(symbol) {
    try {
        const period2 = Math.floor(Date.now() / 1000);
        const period1 = period2 - 86400;
        const res = await fetch(
            `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(symbol)}?interval=1d&period1=${period1}&period2=${period2}`
        );
        if (!res.ok) return null;
        const data = await res.json();
        const result = data?.chart?.result?.[0];
        const meta = result?.meta;
        const quote = result?.indicators?.quote?.[0];
        const close = quote?.close?.filter(Boolean);
        const price = close?.pop() ?? meta?.regularMarketPrice;
        const prevClose = meta?.previousClose ?? close?.[close.length - 2];
        const changePercent = price != null && prevClose ? ((price - prevClose) / prevClose) * 100 : null;
        if (price != null) return { price, changePercent };
    } catch (e) { /* ignore */ }
    return null;
}

async function fetchStock(symbol) {
    const massive = await fetchMassiveStock(symbol);
    if (massive?.price != null) return massive;
    return await fetchYahooStockFallback(symbol);
}

// ==================== LIVE STOCK QUOTES ====================

app.get('/api/stock-quote', async (req, res) => {
    const { symbol } = req.query;
    if (!symbol) return res.status(400).json({ error: 'Symbol required' });
    const sym = String(symbol).toUpperCase().slice(0, 6);
    try {
        const data = await fetchStock(sym);
        if (!data?.price) return res.status(404).json({ error: 'No data for symbol' });
        res.json({ symbol: sym, price: data.price, changePercent: data.changePercent });
    } catch (e) {
        res.status(500).json({ error: e.message || 'Failed to fetch quote' });
    }
});

app.get('/api/stock-quotes', async (req, res) => {
    const { symbols } = req.query;
    if (!symbols) return res.status(400).json({ error: 'symbols required (comma-separated)' });
    const list = String(symbols).split(',').map(s => s.trim().toUpperCase().slice(0, 6)).filter(Boolean).slice(0, 10);
    if (list.length === 0) return res.status(400).json({ error: 'No valid symbols' });
    const results = [];
    for (const sym of list) {
        try {
            const data = await fetchStock(sym);
            results.push({ symbol: sym, price: data?.price, changePercent: data?.changePercent ?? null });
        } catch (e) {
            results.push({ symbol: sym, error: e.message });
        }
    }
    res.json(results);
});

// Stock facts - market performance data using MASSIVE (Polygon) when available
app.get('/api/stock-facts', async (req, res) => {
    const { symbols } = req.query;
    if (!symbols) return res.status(400).json({ error: 'symbols required (comma-separated)' });
    const list = String(symbols).split(',').map(s => s.trim().toUpperCase().slice(0, 6)).filter(Boolean).slice(0, 10);
    if (list.length === 0) return res.status(400).json({ error: 'No valid symbols' });
    const facts = [];
    let dataSource = 'Yahoo Finance';
    for (const sym of list) {
        try {
            const data = await fetchStock(sym);
            if (!data?.price) continue;
            const change = data.changePercent ?? 0;
            const dir = change >= 0 ? 'up' : 'down';
            facts.push({
                symbol: sym,
                price: data.price,
                changePercent: change,
                fact: `${sym} is ${dir} ${Math.abs(change).toFixed(2)}% today. Current price: $${Number(data.price).toFixed(2)}`
            });
            if (MASSIVE_API_KEY) dataSource = 'MASSIVE/Polygon';
        } catch (e) {
            facts.push({ symbol: sym, fact: `${sym}: Unable to fetch data`, error: e.message });
        }
    }
    const gainers = facts.filter(f => f.changePercent != null && f.changePercent > 0).sort((a, b) => (b.changePercent || 0) - (a.changePercent || 0));
    const losers = facts.filter(f => f.changePercent != null && f.changePercent < 0).sort((a, b) => (a.changePercent || 0) - (b.changePercent || 0));
    res.json({
        dataSource,
        symbols: list,
        facts,
        summary: {
            topGainer: gainers[0] ? `${gainers[0].symbol} +${gainers[0].changePercent?.toFixed(2)}%` : null,
            topLoser: losers[0] ? `${losers[0].symbol} ${losers[0].changePercent?.toFixed(2)}%` : null,
            avgChange: facts.filter(f => f.changePercent != null).length
                ? (facts.reduce((s, f) => s + (f.changePercent || 0), 0) / facts.filter(f => f.changePercent != null).length).toFixed(2) + '%'
                : null
        }
    });
});

// ==================== LIVE SIM SESSIONS (persist to DB) ====================

app.post('/api/live-sim/save', (req, res) => {
    const { sessionId, symbols, allocations, startPrices, startDate, totalInvested } = req.body || {};
    if (!sessionId || !symbols?.length || !allocations) return res.status(400).json({ error: 'sessionId, symbols, allocations required' });
    const today = new Date().toISOString().slice(0, 10);
    db.run(
        `INSERT OR REPLACE INTO live_sim_sessions (session_id, symbols, allocations, start_prices, start_date, total_invested, last_report_date)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [sessionId, JSON.stringify(symbols), JSON.stringify(allocations), JSON.stringify(startPrices || {}), startDate || today, totalInvested || 0, today],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: this.lastID });
        }
    );
});

app.get('/api/live-sim/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    db.get('SELECT * FROM live_sim_sessions WHERE session_id = ?', [sessionId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'Session not found' });
        res.json({
            sessionId: row.session_id,
            symbols: JSON.parse(row.symbols || '[]'),
            allocations: JSON.parse(row.allocations || '{}'),
            startPrices: JSON.parse(row.start_prices || '{}'),
            startDate: row.start_date,
            totalInvested: row.total_invested,
            lastReportDate: row.last_report_date
        });
    });
});

app.put('/api/live-sim/:sessionId/report', (req, res) => {
    const { sessionId } = req.params;
    const today = new Date().toISOString().slice(0, 10);
    db.run('UPDATE live_sim_sessions SET last_report_date = ? WHERE session_id = ?', [today, sessionId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ==================== HISTORICAL STOCK DATA (Yahoo Finance) ====================
// Jan 1 2023 00:00 UTC
const JAN_2023 = 1672531200;

app.get('/api/stock-history', async (req, res) => {
    const { symbol } = req.query;
    if (!symbol) return res.status(400).json({ error: 'Symbol required' });
    const sym = String(symbol).toUpperCase().slice(0, 6);
    const period2 = Math.floor(Date.now() / 1000);
    try {
        const url = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(sym)}?interval=1d&period1=${JAN_2023}&period2=${period2}`;
        const r = await fetch(url, { headers: { 'User-Agent': 'SecureBank/1.0' } });
        if (!r.ok) return res.status(502).json({ error: 'Failed to fetch data' });
        const data = await r.json();
        const result = data?.chart?.result?.[0];
        if (!result) return res.status(404).json({ error: 'No data for symbol' });
        const meta = result.meta || {};
        const quote = result.indicators?.quote?.[0];
        const timestamps = result.timestamp || [];
        const closes = quote?.close || [];
        const prices = timestamps.map((t, i) => ({ date: new Date(t * 1000).toISOString().slice(0, 10), price: closes[i] })).filter(p => p.price != null);
        const firstPrice = prices[0]?.price;
        const lastPrice = prices[prices.length - 1]?.price;
        const changePct = firstPrice && lastPrice ? ((lastPrice - firstPrice) / firstPrice) * 100 : null;
        res.json({
            symbol: meta.symbol || sym,
            currency: meta.currency || 'USD',
            firstPrice,
            lastPrice,
            changePct,
            prices
        });
    } catch (e) {
        console.error('Stock history error:', e.message);
        res.status(500).json({ error: e.message || 'Failed to fetch historical data' });
    }
});

app.get('/api/stock-history-batch', async (req, res) => {
    const { symbols } = req.query;
    if (!symbols) return res.status(400).json({ error: 'symbols required (comma-separated)' });
    const list = String(symbols).split(',').map(s => s.trim().toUpperCase().slice(0, 6)).filter(Boolean).slice(0, 25);
    if (list.length === 0) return res.status(400).json({ error: 'No valid symbols' });
    const period2 = Math.floor(Date.now() / 1000);
    const results = [];
    for (const sym of list) {
        try {
            const url = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(sym)}?interval=1d&period1=${JAN_2023}&period2=${period2}`;
            const r = await fetch(url, { headers: { 'User-Agent': 'SecureBank/1.0' } });
            if (!r.ok) { results.push({ symbol: sym, error: 'Failed' }); continue; }
            const data = await r.json();
            const result = data?.chart?.result?.[0];
            if (!result) { results.push({ symbol: sym, error: 'No data' }); continue; }
            const quote = result.indicators?.quote?.[0];
            const timestamps = result.timestamp || [];
            const closes = quote?.close || [];
            const prices = timestamps.map((t, i) => ({ date: new Date(t * 1000).toISOString().slice(0, 10), price: closes[i] })).filter(p => p.price != null);
            const firstPrice = prices[0]?.price;
            const lastPrice = prices[prices.length - 1]?.price;
            const changePct = firstPrice && lastPrice ? ((lastPrice - firstPrice) / firstPrice) * 100 : null;
            results.push({ symbol: sym, firstPrice, lastPrice, changePct, prices });
        } catch (e) {
            results.push({ symbol: sym, error: e.message });
        }
    }
    res.json(results);
});

// ==================== AI CHATBOT (Yahoo Finance + CoinGecko + Gemini) ====================

const STOCK_TICKERS = /(?:^|\s)([A-Z]{1,5})(?:\s|$|[,.!?])/g;
const CRYPTO_NAMES = /\b(bitcoin|ethereum|bnb|solana|cardano|xrp|dogecoin|polygon|avalanche|polkadot|chainlink|litecoin|uniswap|tron|shiba)\b/gi;

async function fetchFreeCryptoApiCrypto(symbols) {
    const key = FREECRYPTOAPI_KEY;
    const list = Array.isArray(symbols) ? symbols : [symbols];
    const results = [];

    // Try FreeCryptoAPI if key is set
    if (key) {
        try {
            for (const sym of list) {
                const url = `https://api.freecryptoapi.com/v1/getData?symbol=${encodeURIComponent(sym)}&api_key=${encodeURIComponent(key)}`;
                const res = await fetch(url, {
                    headers: { 'X-Api-Key': key }
                });
                if (res.ok) {
                    const data = await res.json();
                    const price = data?.price ?? data?.last ?? data?.close;
                    if (price != null) {
                        results.push({ symbol: data?.symbol || sym, price, change_24h: data?.change_24h ?? data?.change_24h_percent ?? 0 });
                    }
                }
            }
        } catch (e) { /* fall through */ }
    }

    if (results.length) return results;

    // Fallback: CoinGecko (free, no key required for basic usage)
    const geckoIds = { BTC: 'bitcoin', ETH: 'ethereum', BNB: 'binancecoin', SOL: 'solana', ADA: 'cardano', XRP: 'ripple', DOGE: 'dogecoin', MATIC: 'matic-network', AVAX: 'avalanche-2', DOT: 'polkadot', LINK: 'chainlink', LTC: 'litecoin', UNI: 'uniswap', TRX: 'tron', SHIB: 'shiba-inu' };
    try {
        const ids = list.map(s => geckoIds[s] || s.toLowerCase()).filter(Boolean).slice(0, 5).join(',');
        if (!ids) return null;
        const res = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd&include_24hr_change=true`);
        if (!res.ok) return null;
        const data = await res.json();
        for (const [id, info] of Object.entries(data)) {
            const sym = list.find(s => (geckoIds[s] || s.toLowerCase()) === id) || id.toUpperCase();
            if (info?.usd != null) results.push({ symbol: sym.length <= 5 ? sym : id, price: info.usd, change_24h: info.usd_24h_change ?? 0 });
        }
    } catch (e) { /* ignore */ }
    return results.length ? results : null;
}

async function callGemini(prompt, history = []) {
    if (!GEMINI_API_KEY) return { error: 'GEMINI_API_KEY is not set in .env' };
    try {
        // Build contents: Gemini expects alternating user/model, simple format
        const contents = [];
        for (const h of history) {
            const role = h.role === 'user' ? 'user' : 'model';
            const text = h.parts?.[0]?.text || (typeof h.parts?.[0] === 'string' ? h.parts[0] : '');
            if (text) contents.push({ role, parts: [{ text: String(text) }] });
        }
        contents.push({ role: 'user', parts: [{ text: String(prompt) }] });

        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents,
                generationConfig: {
                    temperature: 0.7,
                    maxOutputTokens: 1024,
                    topP: 0.95
                }
            })
        });

        const data = await res.json().catch(() => ({}));

        if (!res.ok) {
            const errMsg = data?.error?.message || data?.error?.details?.[0]?.message || JSON.stringify(data) || 'Unknown error';
            console.error('Gemini API error:', res.status, errMsg);
            if (res.status === 400 && /key|api.?key|invalid/i.test(String(errMsg))) {
                return { error: 'Invalid API key. Check GEMINI_API_KEY in .env and create a new key at https://aistudio.google.com/apikey' };
            }
            if (res.status === 403) {
                return { error: 'API key permission denied. Enable Generative Language API or check restrictions.' };
            }
            if (res.status === 429) {
                return { error: 'Rate limit exceeded. Wait a moment and try again.' };
            }
            if (res.status === 503 || /FAILED_PRECONDITION|not available/i.test(String(errMsg))) {
                return { error: 'Gemini may not be available in your region. Try enabling billing at Google AI Studio.' };
            }
            return { error: `Gemini API error: ${errMsg}` };
        }

        const candidate = data?.candidates?.[0];
        const text = candidate?.content?.parts?.[0]?.text;

        if (!text && candidate?.finishReason === 'SAFETY') {
            return { error: 'Response was blocked by safety filters. Try rephrasing your question.' };
        }
        if (!text) {
            return { error: 'Empty response from Gemini. Try again or rephrase your question.' };
        }
        return { text };
    } catch (e) {
        console.error('Gemini error:', e.message);
        return { error: e.message || 'Network error. Check your internet connection.' };
    }
}

app.post('/api/chatbot', async (req, res) => {
    const { message, history = [] } = req.body || {};
    if (!message || typeof message !== 'string') {
        return res.status(400).json({ error: 'Message is required' });
    }

    if (!GEMINI_API_KEY) {
        return res.status(503).json({
            error: 'Gemini API key not configured. Add GEMINI_API_KEY to .env'
        });
    }

    const msg = message.trim().toLowerCase();
    const marketContext = [];
    const seenStocks = new Set();
    const seenCrypto = new Set();

    // Load reference database (finance_reference.json) - no API keys, local file only
    let financeRef = { stocks: {}, crypto: {} };
    try {
        const refPath = path.join(__dirname, 'finance_reference.json');
        if (fs.existsSync(refPath)) {
            financeRef = JSON.parse(fs.readFileSync(refPath, 'utf8'));
        }
    } catch (e) { /* use empty ref */ }
    for (const [name, ticker] of Object.entries(financeRef.stocks || {})) {
        if (msg.includes(name)) seenStocks.add(ticker);
    }

    // Detect stock tickers (e.g. AAPL, MSFT, TSLA) - exclude common words and single letters
    const tickerBlacklist = new Set(['A','I','S','THE','AND','FOR','ARE','BUT','NOT','YOU','ALL','CAN','HAD','HER','WAS','ONE','OUR','OUT','HAS','HIS','HOW','ITS','MAY','NEW','NOW','OLD','SEE','WAY','WHO','DID','GET','LET','PUT','SAY','SHE','TOO','USE','WHAT','WHEN','WITH','PRICE','STOCK','CRYPTO','DATA','HELP','INFO','LINK','FROM','ABOUT','THAN','THEM','THEN','THEY','THIS','WILL','YOUR','HAVE','MORE','SOME','COME','BEEN','INTO','ONLY','OVER','SUCH','THAT','THEY','WERE','WHICH','WOULD']);
    const tickerRe = /\b([A-Z]{2,5})\b/g;
    const upper = message.toUpperCase();
    let tickerMatch;
    while ((tickerMatch = tickerRe.exec(upper)) !== null) {
        const sym = tickerMatch[1];
        if (!tickerBlacklist.has(sym) && !seenStocks.has(sym)) {
            seenStocks.add(sym);
        }
    }
    const stockSymbols = [...seenStocks].slice(0, 5);

    // Fetch stock data
    for (const sym of stockSymbols) {
        const data = await fetchStock(sym);
        if (data?.price != null) {
            const price = typeof data.price === 'number' ? data.price : data.price?.regularMarketPrice;
            const change = data.changePercent ?? data.price?.regularMarketChangePercent ?? 0;
            const dir = change >= 0 ? 'up' : 'down';
            marketContext.push(`[STOCK] ${sym}: $${Number(price).toFixed(2)} (${dir} ${Math.abs(Number(change)).toFixed(2)}%)`);
        }
    }

    // Detect crypto from reference database
    for (const [name, symbol] of Object.entries(financeRef.crypto || {})) {
        if (msg.includes(name) && !seenCrypto.has(symbol)) seenCrypto.add(symbol);
    }
    if ((msg.includes('crypto') || msg.includes('cryptocurrency')) && seenCrypto.size === 0) {
        seenCrypto.add('BTC');
        seenCrypto.add('ETH');
    }
    const cryptoSymbols = [...seenCrypto].slice(0, 5);

    if (cryptoSymbols.length) {
        const data = await fetchFreeCryptoApiCrypto(cryptoSymbols);
        if (data) {
            const items = Array.isArray(data) ? data : (data.data ?? [data]);
            for (const item of items) {
                const sym = item?.symbol ?? item?.id;
                const price = item?.price ?? item?.last ?? item?.close;
                const ch = item?.change_24h ?? item?.change_24h_percent ?? item?.changePercent ?? 0;
                if (price != null && sym) {
                    const dir = ch >= 0 ? 'up' : 'down';
                    marketContext.push(`[CRYPTO] ${sym}: $${Number(price).toLocaleString(undefined, { minimumFractionDigits: 2 })} (24h ${dir} ${Math.abs(Number(ch)).toFixed(2)}%)`);
                }
            }
            if (!Array.isArray(data) && !Array.isArray(data?.data) && data?.symbol) {
                const price = data?.price ?? data?.last;
                if (price != null) {
                    const ch = data?.change_24h ?? data?.change_24h_percent ?? 0;
                    const dir = ch >= 0 ? 'up' : 'down';
                    marketContext.push(`[CRYPTO] ${data.symbol}: $${Number(price).toLocaleString(undefined, { minimumFractionDigits: 2 })} (24h ${dir} ${Math.abs(Number(ch)).toFixed(2)}%)`);
                }
            }
        }
    }

    const contextBlock = marketContext.length
        ? `\n\nReal-time market data (use this when answering):\n${marketContext.join('\n')}\n`
        : '';

    const systemPrompt = `You are a friendly finance AI assistant for SecureBank. Only say things like "I'm doing great!" when the user explicitly greets you or asks how you are (e.g. "how are you", "hi", "hello"). When they ask about stocks, crypto, or prices, answer the question directly—do not add greeting phrases.

Answer questions about stocks, crypto, and personal finance clearly and accurately.
${contextBlock}
If the user asks about specific stocks or crypto and real-time data is provided above, include those prices and changes in your answer.
If no real-time data is available for a symbol they asked about, say so and suggest they try common tickers like AAPL, MSFT, BTC, or ETH.
Keep responses concise but informative. Use markdown for formatting (bold, lists, code) when helpful.`;

    const fullPrompt = `${systemPrompt}\n\nUser question: ${message}`;

    const result = await callGemini(fullPrompt, history);

    if (result.error) {
        return res.status(502).json({ error: result.error });
    }

    const meta = marketContext.length ? 'Includes real-time data from Massive & FreeCryptoAPI' : '';
    res.json({ reply: result.text, meta });
});

// Start server (async init for sql.js)
async function startServer() {
    try {
        const SQL = await initSqlJs();
        if (fs.existsSync(DB_PATH)) {
            const buf = fs.readFileSync(DB_PATH);
            sqlDb = new SQL.Database(buf);
        } else {
            sqlDb = new SQL.Database();
        }
        console.log('✅ Connected to SQLite database (sql.js)');
        initializeDatabase();

        app.listen(PORT, () => {
            console.log(`
╔══════════════════════════════════════╗
║   🏦 SecureBank API Server          ║
║   Port: ${PORT}                         ║
║   Database: SQLite (sql.js)         ║
║   Status: ✅ Running                 ║
╚══════════════════════════════════════╝
            `);
            if (!GEMINI_API_KEY) {
                console.log('⚠️  AI Chatbot: Add GEMINI_API_KEY to .env and restart');
                console.log('   Get key: https://aistudio.google.com/apikey\n');
            }
        });
    } catch (err) {
        console.error('Failed to start server:', err);
        process.exit(1);
    }
}

startServer();

// Graceful shutdown
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
        } else {
            console.log('Database connection closed');
        }
        process.exit(0);
    });
});