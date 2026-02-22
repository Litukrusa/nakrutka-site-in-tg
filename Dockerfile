cat > /etc/dokploy/compose/zhopa-porno-mkpchi/code/Dockerfile << 'EOF'
FROM node:20-alpine

WORKDIR /app

# Копируем package файлы и устанавливаем зависимости
COPY package*.json ./
RUN npm ci --only=production

# Копируем ВСЕ исходники
COPY . .

# Создаем папки для данных и даем права
RUN mkdir -p /app/data /app/mafiles /app/uploads && \
    chmod -R 777 /app/data /app/mafiles /app/uploads /app/views && \
    chmod -R 777 /app

# Проверяем, что index.html существует
RUN ls -la /app/views/ || true

EXPOSE 8869

CMD ["node", "src/index.js"]
EOF