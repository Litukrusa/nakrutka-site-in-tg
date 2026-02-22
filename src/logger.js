// src/logger.js
const fs = require('fs');
const path = require('path');

class Logger {
    constructor(dataDir) {
        this.dataDir = dataDir;
        this.logFile = path.join(dataDir, 'app.log');
        this.logs = [];
        this.maxLogs = 1000; // Храним в памяти последние 1000 логов
    }

    log(level, message, accountId = null) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            level,
            message,
            accountId
        };

        // Добавляем в память
        this.logs.push(logEntry);
        if (this.logs.length > this.maxLogs) {
            this.logs.shift();
        }

        // Форматируем для вывода в консоль
        const consoleMessage = `[${timestamp}] [${level}]${accountId ? ` [Account ${accountId}]` : ''} ${message}`;
        console.log(consoleMessage);

        // Записываем в файл (асинхронно)
        fs.appendFile(this.logFile, consoleMessage + '\n', (err) => {
            if (err) console.error('Ошибка записи в лог-файл:', err);
        });

        return logEntry;
    }

    info(message, accountId = null) {
        return this.log('INFO', message, accountId);
    }

    warn(message, accountId = null) {
        return this.log('WARN', message, accountId);
    }

    error(message, accountId = null) {
        return this.log('ERROR', message, accountId);
    }

    debug(message, accountId = null) {
        if (process.env.DEBUG) {
            return this.log('DEBUG', message, accountId);
        }
    }

    getRecentLogs(lines = 100) {
        return this.logs.slice(-lines);
    }

    clearLogs() {
        this.logs = [];
        fs.writeFile(this.logFile, '', (err) => {
            if (err) console.error('Ошибка очистки лог-файла:', err);
        });
    }

    flush() {
        // Метод для совместимости, так как мы пишем сразу
    }
}

module.exports = Logger;