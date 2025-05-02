const { Pool } = require('pg');

const initDB = async () => {
  console.log('Initializing database connection...');
  console.log(`Connecting to ${process.env.DB_HOST}:${process.env.DB_PORT} as ${process.env.DB_USER}`);
  
  const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
  });

  try {
    // Проверка соединения с базой данных
    const client = await pool.connect();
    console.log('Connected to database successfully');
    client.release();
    
    // Создание таблицы пользователей, если она не существует
    console.log('Creating users table if it does not exist');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Создание таблицы для refresh токенов
    console.log('Creating refresh_tokens table if it does not exist');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '7 day')
      )
    `);

    console.log('Database tables created successfully');
    return true;
  } catch (err) {
    console.error('Database initialization error:', err);
    throw err;
  } finally {
    await pool.end();
  }
};

module.exports = initDB;