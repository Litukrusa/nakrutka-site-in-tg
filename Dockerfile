FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

# МАКСИМАЛЬНО ПРОСТЫЕ ПРАВА
RUN mkdir -p /app/data /app/mafiles && \
    chmod -R 777 /app/data && \
    chmod -R 777 /app/mafiles

# Запускаем от root чтобы избежать проблем с правами
USER root

CMD ["node", "src/index.js"]