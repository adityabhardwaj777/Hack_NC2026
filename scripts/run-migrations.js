#!/usr/bin/env node
/**
 * Run database migrations
 */

require('dotenv').config();
const db = require('../config/database');
const migrations = require('../migrations/001_init');

async function main() {
  try {
    await db.connect();
    console.log('Connected to database:', db.DB_TYPE);
    await migrations.run(db);
    console.log('Migrations completed');
  } catch (err) {
    console.error('Migration failed:', err);
    process.exit(1);
  } finally {
    await db.close();
    process.exit(0);
  }
}

main();
