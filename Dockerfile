FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

# СОЗДАЕМ ВСЕ НУЖНЫЕ ПАПКИ И ДАЕМ ПРАВА
RUN mkdir -p /app/data /app/mafiles /app/uploads && \
    chmod -R 777 /app/data && \
    chmod -R 777 /app/mafiles && \
    chmod -R 777 /app/uploads

# Запускаем от root
USER root

CMD ["node", "src/index.js"]