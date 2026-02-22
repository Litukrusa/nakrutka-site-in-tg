FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

# СОЗДАЕМ ВСЕ ПАПКИ И ДАЕМ ПРАВА 777
RUN mkdir -p /app/data /app/mafiles /app/uploads /app/data/backups && \
    chmod -R 777 /app

USER root

CMD ["node", "src/index.js"]