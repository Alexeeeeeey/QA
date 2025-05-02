const router = require('express').Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../db');
const authMiddleware = require('../middleware/auth');

// Валидация пароля
function validatePassword(password) {
  if (password.length < 8) return false;
  // Проверка на наличие букв, цифр и спецсимволов
  if (!/[A-Za-z]/.test(password)) return false; // буквы
  if (!/[0-9]/.test(password)) return false;    // цифры
  if (!/[^A-Za-z0-9]/.test(password)) return false; // спецсимволы
  return true;
}

// Задержка для защиты от перебора
const delayResponse = () => new Promise(resolve => setTimeout(resolve, 300));

router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Улучшенная валидация
    if (!email || !password) {
      return res.status(400).json({ error: 'Email и пароль обязательны' });
    }

    // Валидация почты
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Некорректный формат email' });
    }

    // Валидация пароля
    if (!validatePassword(password)) {
      return res.status(400).json({ 
        error: 'Пароль должен содержать не менее 8 символов, включая буквы, цифры и спецсимволы' 
      });
    }

    // Проверка существования пользователя
    const existingUser = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      await delayResponse(); // Задержка для защиты от перебора
      return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
    }

    // Хеширование пароля
    const saltRounds = 12; // Увеличено для большей безопасности
    const hash = await bcrypt.hash(password, saltRounds);

    // Сохранение пользователя
    const newUser = await db.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
      [email, hash]
    );

    // Генерация JWT с улучшенным сроком действия
    const token = jwt.sign(
      { userId: newUser.rows[0].id },
      process.env.JWT_SECRET,
      { expiresIn: '24h' } // Увеличенный срок действия
    );

    // Генерация refresh токена
    const refreshToken = jwt.sign(
      { userId: newUser.rows[0].id, type: 'refresh' },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Сохранение refresh токена в БД
    await db.query(
      'INSERT INTO refresh_tokens (user_id, token) VALUES ($1, $2)',
      [newUser.rows[0].id, refreshToken]
    );

    res.status(201).json({ 
      token,
      refreshToken 
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// Логин пользователя с улучшенной безопасностью
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Валидация
    if (!email || !password) {
      return res.status(400).json({ error: 'Email и пароль обязательны' });
    }

    // Поиск пользователя
    const user = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    
    // Общее сообщение об ошибке для защиты от перебора
    if (user.rows.length === 0) {
      await delayResponse(); // Задержка для защиты от перебора
      return res.status(401).json({ error: 'Неверные учётные данные' });
    }

    // Проверка пароля
    const isValid = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!isValid) {
      await delayResponse(); // Задержка для защиты от перебора
      return res.status(401).json({ error: 'Неверные учётные данные' });
    }

    // Генерация токена с улучшенным сроком действия
    const token = jwt.sign(
      { userId: user.rows[0].id },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Генерация refresh токена
    const refreshToken = jwt.sign(
      { userId: user.rows[0].id, type: 'refresh' },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Сохранение refresh токена в БД
    await db.query(
      'INSERT INTO refresh_tokens (user_id, token) VALUES ($1, $2)',
      [user.rows[0].id, refreshToken]
    );

    res.json({ 
      token,
      refreshToken
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// Новый маршрут для обновления токена
router.post('/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh токен обязателен' });
    }

    // Верификация refresh токена
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    
    // Проверка, что это refresh токен
    if (!decoded.type || decoded.type !== 'refresh') {
      return res.status(401).json({ error: 'Недействительный refresh токен' });
    }
    
    // Проверка наличия токена в БД
    const tokenRecord = await db.query(
      'SELECT * FROM refresh_tokens WHERE user_id = $1 AND token = $2',
      [decoded.userId, refreshToken]
    );
    
    if (tokenRecord.rows.length === 0) {
      return res.status(401).json({ error: 'Токен отозван или недействителен' });
    }
    
    // Генерация нового access токена
    const newToken = jwt.sign(
      { userId: decoded.userId },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({ token: newToken });
  } catch (error) {
    console.error('Refresh token error:', error);
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Недействительный или истекший токен' });
    }
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// Logout - отзыв токена
router.post('/logout', authMiddleware, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (refreshToken) {
      // Удаление refresh токена из БД
      await db.query(
        'DELETE FROM refresh_tokens WHERE user_id = $1 AND token = $2',
        [req.userId, refreshToken]
      );
    }
    
    res.json({ message: 'Успешный выход из системы' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// Защищенный маршрут профиля
router.get('/profile', authMiddleware, async (req, res) => {
  try {
    const user = await db.query('SELECT id, email, created_at FROM users WHERE id = $1', [req.userId]);
    
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    res.json(user.rows[0]);
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

module.exports = router;
