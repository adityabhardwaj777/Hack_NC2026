/**
 * Environment configuration - validates and exports config
 */

require('dotenv').config();

const required = ['JWT_SECRET'];
const optional = {
  PORT: 3000,
  NODE_ENV: 'development',
  JWT_EXPIRES_IN: '1h',
  JWT_REFRESH_EXPIRES_IN: '7d',
  RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000,
  RATE_LIMIT_MAX: 100,
  BCRYPT_ROUNDS: 12,
  CORS_ORIGIN: '*',
  SQLITE_PATH: './data/securebank.db',
};

function load() {
  const config = { ...optional };

  const numericKeys = ['PORT', 'RATE_LIMIT_WINDOW_MS', 'RATE_LIMIT_MAX', 'BCRYPT_ROUNDS'];
  for (const [key, defaultVal] of Object.entries(optional)) {
    const val = process.env[key];
    const v = val !== undefined ? val : defaultVal;
    config[key] = numericKeys.includes(key) ? Number(v) || defaultVal : v;
  }

  for (const key of required) {
    const val = process.env[key];
    if (!val || val.trim().length < 10) {
      console.warn(`⚠️ ${key} is missing or weak. Set a strong value in .env`);
    }
    config[key] = process.env[key] || 'change_me_in_production_' + Date.now();
  }

  config.isProd = config.NODE_ENV === 'production';
  config.isDev = config.NODE_ENV !== 'production';

  return config;
}

module.exports = load();
