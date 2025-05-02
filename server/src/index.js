require('dotenv').config();
const express = require('express');
const cors = require('cors');
const initDB = require('./db/init');

const app = express();
app.use(cors());
app.use(express.json());

// Асинхронная функция для запуска приложения
async function startApp() {
  try {
    // Дожидаемся инициализации базы данных
    await initDB();
    console.log('Database initialized successfully');
    
    const authRouter = require('./routes/auth');
    app.use('/api/auth', authRouter);

    const PORT = process.env.PORT || 5000;
    app.get('/health', (req, res) => {
      res.status(200).json({ status: 'OK' });
    });
    
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Auth service running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start application:', error);
    process.exit(1); // Завершаем процесс с ошибкой, если не удалось инициализировать БД
  }
}

// Запускаем приложение
startApp();