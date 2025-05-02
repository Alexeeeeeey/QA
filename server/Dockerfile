FROM node:20-alpine
WORKDIR /app

# Установка необходимых зависимостей для сборки bcrypt
RUN apk add --no-cache --virtual .gyp python3 make g++

COPY package*.json ./
RUN npm install
RUN npm rebuild bcrypt --build-from-source

COPY . .
EXPOSE 5000

# Добавляем команду для проверки переменных окружения при запуске
CMD echo "DB_HOST: $DB_HOST, DB_PORT: $DB_PORT, DB_USER: $DB_USER" && npm run dev