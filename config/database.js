/**
 * Database abstraction - supports SQLite (dev) and PostgreSQL (production)
 * Set DATABASE_URL for PostgreSQL, otherwise uses SQLite
 */

require('dotenv').config();

const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

const DB_TYPE = process.env.DATABASE_URL ? 'postgres' : 'sqlite';
const SQLITE_PATH = process.env.SQLITE_PATH || './data/securebank.db';

let pool = null;
let sqliteDb = null;

function toPgParams(sql, params) {
  const arr = Array.isArray(params) ? params : Object.values(params);
  let i = 0;
  return [sql.replace(/\?/g, () => `$${++i}`), arr];
}

async function connect() {
  if (DB_TYPE === 'postgres') {
    const { Pool } = require('pg');
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
      max: 20,
      idleTimeoutMillis: 30000,
    });
    pool.on('error', (err) => console.error('PostgreSQL pool error:', err));
    return pool;
  }

  const dir = path.dirname(SQLITE_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  return new Promise((resolve, reject) => {
    sqliteDb = new sqlite3.Database(SQLITE_PATH, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
      if (err) reject(err);
      else {
        sqliteDb.run('PRAGMA foreign_keys = ON');
        sqliteDb.run('PRAGMA journal_mode = WAL');
        resolve(sqliteDb);
      }
    });
  });
}

function query(sql, params = []) {
  return new Promise((resolve, reject) => {
    if (DB_TYPE === 'postgres') {
      const [pgSql, pgParams] = toPgParams(sql, params);
      pool.query(pgSql, pgParams, (err, result) => {
        if (err) reject(err);
        else resolve({ rows: result.rows || [], rowCount: result.rowCount || 0 });
      });
    } else {
      sqliteDb.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve({ rows: rows || [], rowCount: rows ? rows.length : 0 });
      });
    }
  });
}

function queryOne(sql, params = []) {
  return new Promise((resolve, reject) => {
    if (DB_TYPE === 'postgres') {
      const [pgSql, pgParams] = toPgParams(sql, params);
      pool.query(pgSql, pgParams, (err, result) => {
        if (err) reject(err);
        else resolve((result.rows && result.rows[0]) || null);
      });
    } else {
      sqliteDb.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row || null);
      });
    }
  });
}

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    if (DB_TYPE === 'postgres') {
      const [pgSql, pgParams] = toPgParams(sql, params);
      pool.query(pgSql, pgParams, (err, result) => {
        if (err) reject(err);
        else {
          const lastRow = result.rows && result.rows[0];
          resolve({
            lastID: lastRow && (lastRow.id !== undefined ? lastRow.id : lastRow.id),
            changes: result.rowCount || 0,
          });
        }
      });
    } else {
      sqliteDb.run(sql, params, function (err) {
        if (err) reject(err);
        else resolve({ lastID: this.lastID, changes: this.changes });
      });
    }
  });
}

async function runWithReturn(sql, params = []) {
  if (DB_TYPE === 'postgres') {
    const [pgSql, pgParams] = toPgParams(sql, params);
    const result = await pool.query(pgSql + ' RETURNING id', pgParams);
    const row = result.rows && result.rows[0];
    return { lastID: row ? row.id : null, changes: result.rowCount || 0 };
  }
  return run(sql, params);
}

async function transaction(fn) {
  if (DB_TYPE === 'postgres') {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } else {
    return new Promise((resolve, reject) => {
      sqliteDb.run('BEGIN TRANSACTION', (err) => {
        if (err) return reject(err);
        const txApi = {
          query: (s, p) => query(s, p),
          queryOne: (s, p) => queryOne(s, p),
          run: (s, p) => run(s, p),
        };
        Promise.resolve(fn(txApi))
          .then((r) => {
            sqliteDb.run('COMMIT', (e) => (e ? reject(e) : resolve(r)));
          })
          .catch((e) => {
            sqliteDb.run('ROLLBACK', () => reject(e));
          });
      });
    });
  }
}

async function close() {
  if (pool) {
    await pool.end();
    pool = null;
  }
  if (sqliteDb) {
    return new Promise((resolve) => sqliteDb.close(resolve));
  }
}

module.exports = {
  connect,
  query,
  queryOne,
  run,
  runWithReturn,
  transaction,
  close,
  DB_TYPE,
};
