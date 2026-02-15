#!/usr/bin/env node
/**
 * Initialize demo data (optional - for development)
 */

require('dotenv').config();
const db = require('../config/database');
const bcrypt = require('bcrypt');

const isPostgres = !!process.env.DATABASE_URL;

async function main() {
  try {
    await db.connect();
    const hash = await bcrypt.hash('demo123', 12);
    if (isPostgres) {
      await db.run(
        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?) ON CONFLICT (email) DO NOTHING',
        ['demo', 'demo@securebank.com', hash]
      );
    } else {
      await db.run(
        'INSERT OR IGNORE INTO users (username, email, password_hash) VALUES (?, ?, ?)',
        ['demo', 'demo@securebank.com', hash]
      );
    }
    const user = await db.queryOne('SELECT id FROM users WHERE email = ?', ['demo@securebank.com']);
    if (user) {
      const accCheck = await db.queryOne('SELECT id FROM accounts WHERE user_id = ? AND account_type = ?', [user.id, 'checking']);
      if (!accCheck) {
        await db.run('INSERT INTO accounts (user_id, account_type, account_number, balance) VALUES (?, ?, ?, ?)', [user.id, 'checking', '1000000001', 2500]);
        await db.run('INSERT INTO accounts (user_id, account_type, account_number, balance) VALUES (?, ?, ?, ?)', [user.id, 'savings', '1000000002', 5000]);
      }
    }
    console.log('Demo data initialized');
  } catch (err) {
    console.error('Init failed:', err);
    process.exit(1);
  } finally {
    await db.close();
    process.exit(0);
  }
}

main();
