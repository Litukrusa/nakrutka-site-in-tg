FROM node:20-alpine

# Устанавливаем зависимости для сборки (если нужны)
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Копируем package.json и package-lock.json
COPY package*.json ./

# Устанавливаем зависимости
RUN npm ci --only=production

# Копируем исходный код
COPY . .

# СОЗДАЕМ ПАПКИ И ПРАВИЛЬНО ВЫСТАВЛЯЕМ ПРАВА
RUN mkdir -p /app/data /app/mafiles && \
    chown -R node:node /app && \
    chmod -R 755 /app/data && \
    chmod -R 755 /app/mafiles

# Переключаемся на пользователя node
USER node

# Запускаем приложение
CMD ["node", "src/index.js"]