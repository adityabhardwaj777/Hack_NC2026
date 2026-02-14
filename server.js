const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public')); // Serve static files

// Initialize SQLite Database
const db = new sqlite3.Database('./securebank.db', (err) => {
    if (err) {
        console.error('Error opening database:', err);
    } else {
        console.log('✅ Connected to SQLite database');
        initializeDatabase();
    }
});

// Create tables
function initializeDatabase() {
    db.serialize(() => {
        // Users table
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Accounts table
        db.run(`
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

        // Transactions table
        db.run(`
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

        // Budget table
        db.run(`
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

        // Security alerts table
        db.run(`
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

        console.log('✅ Database tables initialized');
    });
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

// ==================== API ROUTES ====================

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

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'SecureBank API is running' });
});

// Start server
app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════╗
║   🏦 SecureBank API Server          ║
║   Port: ${PORT}                         ║
║   Database: SQLite                  ║
║   Status: ✅ Running                 ║
╚══════════════════════════════════════╝
    `);
});

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