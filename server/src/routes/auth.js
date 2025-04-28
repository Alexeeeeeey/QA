const router = require('express').Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../db');
const authMiddleware = require('../middleware/auth');  // Добавьте эту строку

router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Валидация
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Проверка существования пользователя
    const existingUser = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Хеширование пароля
    const saltRounds = 10;
    const hash = await bcrypt.hash(password, saltRounds);

    // Сохранение пользователя
    const newUser = await db.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *',
      [email, hash]
    );

    // Генерация JWT
    const token = jwt.sign(
      { userId: newUser.rows[0].id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(201).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Логин пользователя
router.post('/login', async (req, res) => {
    try {
      const { email, password } = req.body;
  
      // Валидация
      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
      }
  
      // Поиск пользователя
      const user = await db.query('SELECT * FROM users WHERE email = $1', [email]);
      if (user.rows.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
  
      // Проверка пароля
      const isValid = await bcrypt.compare(password, user.rows[0].password_hash);
      if (!isValid) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
  
      // Генерация токена
      const token = jwt.sign(
        { userId: user.rows[0].id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
  
      res.json({ token });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
  
  // Защищенный роут
  router.get('/profile', authMiddleware, async (req, res) => {
    try {
      const user = await db.query('SELECT id, email, created_at FROM users WHERE id = $1', [req.userId]);
      res.json(user.rows[0]);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
  
module.exports = router; 