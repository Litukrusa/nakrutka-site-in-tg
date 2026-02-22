// src/telegram-bot.js
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');

class SteamHourTelegramBot {
    constructor(token, adminId, apiBaseUrl = 'http://localhost:8869/api') {
        if (!token) throw new Error('Telegram bot token is required');
        this.token = token;
        this.adminId = adminId ? Number(adminId) : null;
        this.apiBaseUrl = apiBaseUrl;
        this.bot = new TelegramBot(token, { polling: true });
        this.sessionCookie = null;
    }

    // Проверка авторизации по ID
    _isAuthorized(msg) {
        if (!this.adminId) {
            console.warn('⚠️ TELEGRAM_ADMIN_ID не задан! Бот отвечает всем - ЭТО НЕБЕЗОПАСНО!');
            return true;
        }
        return msg.from.id === this.adminId;
    }

    // Вызов API проекта
    async _callApi(method, endpoint, data = null) {
        try {
            const url = `${this.apiBaseUrl}${endpoint}`;
            const config = {
                method: method,
                url: url,
                headers: { 'Content-Type': 'application/json' },
                withCredentials: true
            };

            if (data && (method === 'POST' || method === 'PUT')) {
                config.data = data;
            }

            const response = await axios(config);
            return { success: true, data: response.data };
        } catch (error) {
            console.error(`API Call Error (${method} ${endpoint}):`, error.response?.data || error.message);
            return {
                success: false,
                error: error.response?.data?.error || error.message || 'Unknown API error',
                status: error.response?.status
            };
        }
    }

    // Настройка обработчиков команд
    setupHandlers() {
        // /start - приветствие (БЕЗ MARKDOWN, обычный текст)
        this.bot.onText(/\/start/, (msg) => {
            const chatId = msg.chat.id;
            if (!this._isAuthorized(msg)) {
                return this.bot.sendMessage(chatId, '⛔ У вас нет прав на использование этого бота.');
            }

            const welcome = `👋 Steam Hour Boost Bot

Я помогу управлять фармом часов в Steam удалённо.

Основные команды:
/status - Статистика и общая информация
/accounts - Список всех аккаунтов
/start_all - Запустить фарм на всех
/stop_all - Остановить фарм на всех

Команды для конкретного аккаунта:
/account_1 - Информация об аккаунте №1
/start_1 - Запустить аккаунт №1
/stop_1 - Остановить аккаунт №1

/help - Все доступные команды`;

            this.bot.sendMessage(chatId, welcome);
        });

        // /status - общая статистика
        this.bot.onText(/\/status/, async (msg) => {
            const chatId = msg.chat.id;
            if (!this._isAuthorized(msg)) return;

            const result = await this._callApi('GET', '/dashboard');
            if (result.success) {
                const d = result.data;
                let statusText = `📊 Общая статистика\n\n`;
                statusText += `👤 Всего аккаунтов: ${d.totalAccounts || 0}\n`;
                statusText += `🟢 Активных: ${d.activeAccounts || 0}\n`;
                statusText += `🔴 Неактивных: ${(d.totalAccounts - d.activeAccounts) || 0}\n`;
                statusText += `🎮 Игр в фарме: ${d.totalGamesIdling || 0}\n`;
                statusText += `🕒 Общее время (часы): ${Math.round(d.totalPlaytimeHours || 0)}\n`;
                this.bot.sendMessage(chatId, statusText);
            } else {
                this.bot.sendMessage(chatId, `❌ Ошибка: ${result.error}`);
            }
        });

        // /accounts - список аккаунтов
        this.bot.onText(/\/accounts/, async (msg) => {
            const chatId = msg.chat.id;
            if (!this._isAuthorized(msg)) return;

            const result = await this._callApi('GET', '/accounts');
            if (result.success && Array.isArray(result.data)) {
                if (result.data.length === 0) {
                    return this.bot.sendMessage(chatId, '📭 Нет добавленных аккаунтов.');
                }

                let listText = `📋 Список аккаунтов\n\n`;
                for (const acc of result.data) {
                    const statusEmoji = acc.isOnline ? '🟢' : '🔴';
                    listText += `${statusEmoji} ${acc.accountName || 'Без имени'} (ID: ${acc.id})\n`;
                    listText += `└ Статус: ${acc.status || 'offline'}, игр: ${acc.gamesCount || 0}\n\n`;
                }
                listText += `\nИспользуй /account_ID для деталей.`;
                this.bot.sendMessage(chatId, listText);
            } else {
                this.bot.sendMessage(chatId, `❌ Ошибка: ${result.error}`);
            }
        });

        // /account_ID - детали аккаунта
        this.bot.onText(/\/account_(\d+)/, async (msg, match) => {
            const chatId = msg.chat.id;
            if (!this._isAuthorized(msg)) return;

            const accountId = match[1];
            const result = await this._callApi('GET', `/accounts/${accountId}`);

            if (result.success) {
                const acc = result.data;
                let details = `🔍 Детали аккаунта (ID: ${accountId})\n\n`;
                details += `👤 Логин: ${acc.accountName || 'Не указан'}\n`;
                details += `📊 Статус: ${acc.status || 'неизвестно'}\n`;
                details += `🎮 Игры: ${acc.games?.map(g => g.gameId || g).join(', ') || 'не заданы'}\n`;
                details += `🕒 Наигранно: ${Math.round(acc.playtime || 0)} часов\n`;
                
                let personaText = 'Invisible';
                if (acc.personaState === 1) personaText = 'Online';
                if (acc.personaState === 2) personaText = 'Away';
                details += `🔗 Режим: ${personaText}`;
                
                this.bot.sendMessage(chatId, details);
            } else {
                this.bot.sendMessage(chatId, `❌ Аккаунт ${accountId} не найден.`);
            }
        });

        // /start_ID - запустить аккаунт
        this.bot.onText(/\/start_(\d+)/, async (msg, match) => {
            const chatId = msg.chat.id;
            if (!this._isAuthorized(msg)) return;

            const accountId = match[1];
            const result = await this._callApi('POST', `/accounts/${accountId}/start`);

            if (result.success) {
                this.bot.sendMessage(chatId, `✅ Запустил фарм на аккаунте ${accountId}`);
            } else {
                this.bot.sendMessage(chatId, `❌ Не удалось запустить: ${result.error}`);
            }
        });

        // /stop_ID - остановить аккаунт
        this.bot.onText(/\/stop_(\d+)/, async (msg, match) => {
            const chatId = msg.chat.id;
            if (!this._isAuthorized(msg)) return;

            const accountId = match[1];
            const result = await this._callApi('POST', `/accounts/${accountId}/stop`);

            if (result.success) {
                this.bot.sendMessage(chatId, `⏸ Остановил фарм на аккаунте ${accountId}`);
            } else {
                this.bot.sendMessage(chatId, `❌ Не удалось остановить: ${result.error}`);
            }
        });

        // /start_all - запустить все
        this.bot.onText(/\/start_all/, async (msg) => {
            const chatId = msg.chat.id;
            if (!this._isAuthorized(msg)) return;
            const result = await this._callApi('POST', '/accounts/start-all');
            if (result.success) {
                this.bot.sendMessage(chatId, '✅ Запустил фарм на всех аккаунтах!');
            } else {
                this.bot.sendMessage(chatId, `❌ Ошибка: ${result.error}`);
            }
        });

        // /stop_all - остановить все
        this.bot.onText(/\/stop_all/, async (msg) => {
            const chatId = msg.chat.id;
            if (!this._isAuthorized(msg)) return;
            const result = await this._callApi('POST', '/accounts/stop-all');
            if (result.success) {
                this.bot.sendMessage(chatId, '⏸ Остановил фарм на всех аккаунтах.');
            } else {
                this.bot.sendMessage(chatId, `❌ Ошибка: ${result.error}`);
            }
        });

        // /help - помощь
        this.bot.onText(/\/help/, (msg) => {
            const chatId = msg.chat.id;
            if (!this._isAuthorized(msg)) return;
            const help = `📚 Все команды бота

Общее:
/status - Статистика
/accounts - Список аккаунтов
/start_all - Старт всех
/stop_all - Стоп всех

По аккаунтам:
/account_[ID] - Инфо (напр. /account_1)
/start_[ID] - Запустить
/stop_[ID] - Остановить

Примеры:
/account_2 - инфо об аккаунте ID 2
/start_3 - запустить аккаунт ID 3`;

            this.bot.sendMessage(chatId, help);
        });

        console.log('🤖 Telegram bot handlers registered');
    }

    // Запуск бота
    start() {
        this.setupHandlers();
        console.log(`🚀 Telegram bot started. Admin ID: ${this.adminId || 'NOT SET (INSECURE!)'}`);
        return this.bot;
    }

    // Остановка бота
    async stop() {
        await this.bot.stopPolling();
        console.log('🛑 Telegram bot stopped.');
    }
}

module.exports = SteamHourTelegramBot;