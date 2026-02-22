// src/index.js
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const helmet = require('helmet');
const cors = require('cors');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const AdmZip = require('adm-zip');
const crypto = require('crypto');
const SteamUser = require('steam-user');
const SteamTotp = require('steam-totp');
const { Sequelize, DataTypes } = require('sequelize');
const Logger = require('./logger');
const AccountManager = require('./account-manager');
const MAFileManager = require('./mafile-manager');
const BackupService = require('./backup-service');
const EncryptionService = require('./encryption-service');
const SettingsService = require('./settings-service');
const DashboardService = require('./dashboard-service');
const TelegramBot = require('./telegram-bot');

// Инициализация приложения
const app = express();
const PORT = process.env.PORT || 8869;
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const MAFILES_DIR = process.env.MAFILES_DIR || path.join(__dirname, '..', 'mafiles');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Создаем необходимые директории
[DATA_DIR, MAFILES_DIR, path.join(DATA_DIR, 'backups')].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o777 });
    }
});

// Инициализация сервисов
const logger = new Logger(DATA_DIR);
const encryptionService = new EncryptionService();
const settingsService = new SettingsService(DATA_DIR, encryptionService);
const mafileManager = new MAFileManager(MAFILES_DIR, encryptionService);
const accountManager = new AccountManager(DATA_DIR, encryptionService, logger, mafileManager);
const backupService = new BackupService(DATA_DIR, encryptionService);
const dashboardService = new DashboardService(accountManager, mafileManager);

// Инициализация базы данных SQLite
const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: path.join(DATA_DIR, 'database.sqlite'),
    logging: false,
    define: {
        timestamps: true
    }
});

// Модель для пользователей админки
const User = sequelize.define('User', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    username: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: false
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    isAdmin: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
    }
});

// Модель для настроек
const Setting = sequelize.define('Setting', {
    key: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: false
    },
    value: {
        type: DataTypes.TEXT,
        allowNull: true
    }
});

// Middleware
app.use(helmet({
    contentSecurityPolicy: false,
}));
app.use(compression());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Статические файлы
const publicPath = path.join(__dirname, '..', 'public');
if (fs.existsSync(publicPath)) {
    app.use(express.static(publicPath));
}

// Сессии
const sessionStore = new session.MemoryStore();
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: false,
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'lax'
    }
}));

// Passport
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        const user = await User.findOne({ where: { username } });
        if (!user) {
            return done(null, false, { message: 'Неверное имя пользователя или пароль' });
        }
        
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return done(null, false, { message: 'Неверное имя пользователя или пароль' });
        }
        
        return done(null, user);
    } catch (error) {
        return done(error);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findByPk(id);
        done(null, user);
    } catch (error) {
        done(error);
    }
});

// Rate limiting для API
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Слишком много запросов, попробуйте позже' }
});

app.use('/api/', apiLimiter);

// Проверка аутентификации для API
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ error: 'Не авторизован' });
}

// Проверка, настроено ли приложение
async function isSetup(req, res, next) {
    const userCount = await User.count();
    if (userCount === 0) {
        if (req.path === '/api/setup' && req.method === 'POST') {
            return next();
        }
        return res.status(428).json({ error: 'Требуется первоначальная настройка' });
    }
    next();
}

app.use('/api', isSetup);

// ==================== API РОУТЫ ====================

// Первоначальная настройка
app.post('/api/setup', async (req, res) => {
    try {
        const userCount = await User.count();
        if (userCount > 0) {
            return res.status(400).json({ error: 'Приложение уже настроено' });
        }
        
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Имя пользователя и пароль обязательны' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'Пароль должен быть не менее 6 символов' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        await User.create({
            username,
            password: hashedPassword,
            isAdmin: true
        });
        
        await Setting.create({ key: 'setupComplete', value: 'true' });
        
        res.json({ success: true, message: 'Администратор создан' });
    } catch (error) {
        console.error('Setup error:', error);
        res.status(500).json({ error: 'Ошибка при настройке' });
    }
});

// Логин
app.post('/api/login', passport.authenticate('local'), (req, res) => {
    res.json({ success: true, user: { id: req.user.id, username: req.user.username } });
});

// Логаут
app.post('/api/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка при выходе' });
        }
        res.json({ success: true });
    });
});

// Проверка статуса аутентификации
app.get('/api/auth/status', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ authenticated: true, user: { id: req.user.id, username: req.user.username } });
    } else {
        res.json({ authenticated: false });
    }
});

// ==================== АККАУНТЫ ====================

app.get('/api/accounts', isAuthenticated, async (req, res) => {
    try {
        const accounts = await accountManager.getAllAccounts();
        res.json(accounts);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/accounts/:id', isAuthenticated, async (req, res) => {
    try {
        const account = await accountManager.getAccount(req.params.id);
        if (!account) {
            return res.status(404).json({ error: 'Аккаунт не найден' });
        }
        res.json(account);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/accounts', isAuthenticated, async (req, res) => {
    try {
        const { accountName, password, games, personaState, mafileId } = req.body;
        
        if (!accountName || !password) {
            return res.status(400).json({ error: 'Имя аккаунта и пароль обязательны' });
        }
        
        const account = await accountManager.createAccount({
            accountName,
            password,
            games: games || [730],
            personaState: personaState || 0,
            mafileId
        });
        
        res.json(account);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/accounts/:id', isAuthenticated, async (req, res) => {
    try {
        const { accountName, password, games, personaState, mafileId } = req.body;
        
        const account = await accountManager.updateAccount(req.params.id, {
            accountName,
            password,
            games,
            personaState,
            mafileId
        });
        
        res.json(account);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/accounts/:id', isAuthenticated, async (req, res) => {
    try {
        await accountManager.deleteAccount(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/accounts/:id/start', isAuthenticated, async (req, res) => {
    try {
        await accountManager.startAccount(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/accounts/:id/stop', isAuthenticated, async (req, res) => {
    try {
        await accountManager.stopAccount(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/accounts/start-all', isAuthenticated, async (req, res) => {
    try {
        await accountManager.startAllAccounts();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/accounts/stop-all', isAuthenticated, async (req, res) => {
    try {
        await accountManager.stopAllAccounts();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== MAFILES ====================

app.get('/api/mafiles', isAuthenticated, async (req, res) => {
    try {
        const mafiles = await mafileManager.getAllMAFiles();
        res.json(mafiles);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/mafiles/import/content', isAuthenticated, async (req, res) => {
    try {
        const { content } = req.body;
        
        if (!content) {
            return res.status(400).json({ error: 'Содержимое MAFile обязательно' });
        }
        
        const mafile = await mafileManager.importFromContent(content);
        res.json(mafile);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/mafiles/import/zip', isAuthenticated, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Файл не загружен' });
        }
        
        const zip = new AdmZip(req.file.path);
        const zipEntries = zip.getEntries();
        
        const results = [];
        for (const entry of zipEntries) {
            if (entry.entryName.endsWith('.maFile')) {
                try {
                    const content = entry.getData().toString('utf8');
                    const mafile = await mafileManager.importFromContent(content);
                    results.push({ file: entry.entryName, success: true, mafile });
                } catch (e) {
                    results.push({ file: entry.entryName, success: false, error: e.message });
                }
            }
        }
        
        fs.unlinkSync(req.file.path);
        res.json({ results });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/mafiles/import/folder', isAuthenticated, async (req, res) => {
    try {
        const results = await mafileManager.scanDirectory();
        res.json({ results });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/mafiles/:id/link/:accountId', isAuthenticated, async (req, res) => {
    try {
        const mafile = await mafileManager.linkToAccount(req.params.id, req.params.accountId);
        res.json(mafile);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/mafiles/:id', isAuthenticated, async (req, res) => {
    try {
        await mafileManager.deleteMAFile(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== DASHBOARD ====================

app.get('/api/dashboard', isAuthenticated, async (req, res) => {
    try {
        const dashboardData = await dashboardService.getDashboardData();
        res.json(dashboardData);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== НАСТРОЙКИ ====================

app.get('/api/settings', isAuthenticated, async (req, res) => {
    try {
        const settings = await settingsService.getAllSettings();
        res.json(settings);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/settings', isAuthenticated, async (req, res) => {
    try {
        const settings = req.body;
        await settingsService.updateSettings(settings);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== ЛОГИ ====================

app.get('/api/logs', isAuthenticated, async (req, res) => {
    try {
        const lines = req.query.lines ? parseInt(req.query.lines) : 100;
        const logs = await logger.getRecentLogs(lines);
        res.json({ logs });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/logs', isAuthenticated, async (req, res) => {
    try {
        await logger.clearLogs();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== БЕКАПЫ ====================

app.post('/api/backups', isAuthenticated, async (req, res) => {
    try {
        const { password } = req.body;
        const backupPath = await backupService.createBackup(password);
        res.json({ success: true, path: backupPath });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/backups/restore', isAuthenticated, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Файл не загружен' });
        }
        
        const { password } = req.body;
        await backupService.restoreFromBackup(req.file.path, password);
        fs.unlinkSync(req.file.path);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== HEALTH CHECK ====================

app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// ==================== ВЕБ-ИНТЕРФЕЙС ====================

// Путь к папке с HTML файлами
const viewsPath = path.join(__dirname, '..', 'views');

// Проверяем существование index.html, если нет - создаем
const indexPath = path.join(viewsPath, 'index.html');
if (!fs.existsSync(indexPath)) {
    console.log('⚠️ index.html не найден, создаем редирект на dashboard.html');
    const dashboardPath = path.join(viewsPath, 'dashboard.html');
    if (fs.existsSync(dashboardPath)) {
        // Создаем index.html с редиректом на dashboard.html
        const redirectHtml = `<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0;url=/dashboard.html">
    <title>Steam Hour Boost</title>
</head>
<body>
    <a href="/dashboard.html">Перейти к дашборду</a>
</body>
</html>`;
        fs.writeFileSync(indexPath, redirectHtml);
        console.log('✅ index.html создан с редиректом на dashboard.html');
    }
}

// Отдаем статические файлы из папки views
app.use(express.static(viewsPath));

// API маршруты уже определены выше

// Для всех остальных GET запросов отдаем index.html (SPA поддержка)
app.get('*', (req, res, next) => {
    // Пропускаем API запросы
    if (req.path.startsWith('/api/') || req.path === '/health') {
        return next();
    }
    
    // Проверяем, существует ли запрошенный файл
    const requestedPath = path.join(viewsPath, req.path);
    if (fs.existsSync(requestedPath) && fs.statSync(requestedPath).isFile()) {
        return res.sendFile(requestedPath);
    }
    
    // Иначе отдаем index.html
    const indexPath = path.join(viewsPath, 'index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        // Если index.html нет, пробуем dashboard.html
        const dashboardPath = path.join(viewsPath, 'dashboard.html');
        if (fs.existsSync(dashboardPath)) {
            res.sendFile(dashboardPath);
        } else {
            res.status(404).send('Файлы интерфейса не найдены');
        }
    }
});

// ==================== ЗАПУСК СЕРВЕРА ====================

async function startServer() {
    try {
        // Синхронизация базы данных
        await sequelize.authenticate();
        console.log('✅ База данных подключена');
        
        await sequelize.sync({ alter: true });
        console.log('✅ Модели синхронизированы');
        
        // Загружаем аккаунты
        await accountManager.loadAccounts();
        
        // Запускаем сервер
        const server = app.listen(PORT, HOST, () => {
            console.log(`✅ Сервер запущен на http://${HOST}:${PORT}`);
            
            // Запуск Telegram бота
            try {
                const botToken = process.env.TELEGRAM_BOT_TOKEN;
                const adminId = process.env.TELEGRAM_ADMIN_ID;
                
                if (botToken) {
                    console.log('🤖 Telegram бот инициализация...');
                    
                    if (!adminId) {
                        console.warn('⚠️ TELEGRAM_ADMIN_ID не задан! Бот будет отвечать всем - НЕБЕЗОПАСНО!');
                    }
                    
                    const bot = new TelegramBot(botToken, adminId, `http://${HOST}:${PORT}/api`);
                    bot.start();
                    app.set('telegramBot', bot);
                    
                    console.log('✅ Telegram бот успешно запущен');
                }
            } catch (botError) {
                console.error('❌ Ошибка запуска Telegram бота:', botError.message);
            }
        });
        
        // Graceful shutdown
        const shutdown = async () => {
            console.log('\n🛑 Останавливаем сервер...');
            
            const bot = app.get('telegramBot');
            if (bot) await bot.stop();
            
            await accountManager.stopAllAccounts();
            logger.flush();
            
            server.close(() => {
                console.log('✅ Сервер остановлен');
                process.exit(0);
            });
        };
        
        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);
        
        return server;
    } catch (error) {
        console.error('❌ Ошибка запуска сервера:', error);
        process.exit(1);
    }
}

if (require.main === module) {
    startServer();
}

module.exports = { app, startServer };