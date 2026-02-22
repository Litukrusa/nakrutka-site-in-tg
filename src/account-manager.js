// src/account-manager.js
const fs = require('fs').promises;
const path = require('path');
const SteamUser = require('steam-user');
const SteamTotp = require('steam-totp');
const { v4: uuidv4 } = require('uuid');

class AccountManager {
    constructor(dataDir, encryptionService, logger, mafileManager) {
        this.dataDir = dataDir;
        this.accountsFile = path.join(dataDir, 'accounts.json');
        this.encryptionService = encryptionService;
        this.logger = logger;
        this.mafileManager = mafileManager;
        this.accounts = new Map(); // id -> account data
        this.clients = new Map(); // id -> steam-user instance
        this.loadAccounts();
    }

    async loadAccounts() {
        try {
            const data = await fs.readFile(this.accountsFile, 'utf8');
            const accounts = JSON.parse(data);
            
            for (const [id, account] of Object.entries(accounts)) {
                this.accounts.set(id, account);
            }
            
            console.log(`✅ Загружено ${this.accounts.size} аккаунтов`);
            
            // Автоматически запускаем аккаунты, которые были запущены
            for (const [id, account] of this.accounts) {
                if (account.autoStart) {
                    this.startAccount(id).catch(e => {
                        this.logger.error(`Ошибка автозапуска аккаунта ${account.accountName}: ${e.message}`, id);
                    });
                }
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                console.error('Ошибка загрузки аккаунтов:', error);
            }
            // Файл не существует - это нормально для первого запуска
            await this.saveAccounts();
        }
    }

    async saveAccounts() {
        const accounts = {};
        for (const [id, account] of this.accounts) {
            // Не сохраняем клиенты
            const { client, ...accountData } = account;
            accounts[id] = accountData;
        }
        
        await fs.writeFile(this.accountsFile, JSON.stringify(accounts, null, 2));
    }

    async getAllAccounts() {
        const accounts = [];
        for (const [id, account] of this.accounts) {
            const client = this.clients.get(id);
            accounts.push({
                ...account,
                id,
                isOnline: client ? client.steamID ? true : false : false,
                status: client ? client.steamID ? 'online' : 'connecting' : 'offline',
                gamesCount: account.games ? account.games.length : 0
            });
        }
        return accounts;
    }

    async getAccount(id) {
        const account = this.accounts.get(id);
        if (!account) return null;

        const client = this.clients.get(id);
        return {
            ...account,
            id,
            isOnline: client ? client.steamID ? true : false : false,
            status: client ? client.steamID ? 'online' : 'connecting' : 'offline',
            gamesCount: account.games ? account.games.length : 0,
            playtime: account.playtime || 0
        };
    }

    async createAccount(accountData) {
        const id = uuidv4();
        
        // Шифруем пароль
        const encryptedPassword = this.encryptionService.encrypt(
            accountData.password, 
            process.env.ENCRYPTION_KEY || 'default-key-change-me'
        );

        const account = {
            accountName: accountData.accountName,
            password: encryptedPassword,
            games: accountData.games || [730],
            personaState: accountData.personaState || 0,
            mafileId: accountData.mafileId || null,
            autoStart: false,
            playtime: 0,
            createdAt: new Date().toISOString()
        };

        this.accounts.set(id, account);
        await this.saveAccounts();

        // Если есть mafileId, привязываем его
        if (accountData.mafileId) {
            await this.mafileManager.linkToAccount(accountData.mafileId, id);
        }

        return { id, ...account };
    }

    async updateAccount(id, accountData) {
        const account = this.accounts.get(id);
        if (!account) {
            throw new Error('Аккаунт не найден');
        }

        if (accountData.password) {
            account.password = this.encryptionService.encrypt(
                accountData.password,
                process.env.ENCRYPTION_KEY || 'default-key-change-me'
            );
        }

        if (accountData.accountName) account.accountName = accountData.accountName;
        if (accountData.games) account.games = accountData.games;
        if (accountData.personaState !== undefined) account.personaState = accountData.personaState;
        
        if (accountData.mafileId !== undefined) {
            account.mafileId = accountData.mafileId;
            if (accountData.mafileId) {
                await this.mafileManager.linkToAccount(accountData.mafileId, id);
            }
        }

        await this.saveAccounts();
        return { id, ...account };
    }

    async deleteAccount(id) {
        // Останавливаем, если запущен
        await this.stopAccount(id);
        
        this.accounts.delete(id);
        await this.saveAccounts();
    }

    async startAccount(id) {
        const account = this.accounts.get(id);
        if (!account) {
            throw new Error('Аккаунт не найден');
        }

        // Если уже запущен, не запускаем повторно
        if (this.clients.has(id)) {
            this.logger.info(`Аккаунт ${account.accountName} уже запущен`, id);
            return;
        }

        try {
            const client = new SteamUser();
            
            // Расшифровываем пароль
            const password = this.encryptionService.decrypt(
                account.password,
                process.env.ENCRYPTION_KEY || 'default-key-change-me'
            );

            // Получаем 2FA код, если есть привязанный MAFile
            let twoFactorCode = null;
            if (account.mafileId) {
                const mafile = await this.mafileManager.getMAFile(account.mafileId);
                if (mafile && mafile.shared_secret) {
                    twoFactorCode = SteamTotp.generateAuthCode(mafile.shared_secret);
                }
            }

            // Настройка событий
            client.on('loggedOn', () => {
                this.logger.info(`✅ Аккаунт ${account.accountName} успешно залогинен`, id);
                
                // Устанавливаем статус
                client.setPersona(account.personaState);
                
                // Запускаем игры
                if (account.games && account.games.length > 0) {
                    client.gamesPlayed(account.games);
                    this.logger.info(`🎮 Запущены игры: ${account.games.join(', ')}`, id);
                }
            });

            client.on('error', (err) => {
                this.logger.error(`❌ Ошибка аккаунта ${account.accountName}: ${err.message}`, id);
                this.clients.delete(id);
            });

            client.on('disconnected', () => {
                this.logger.warn(`⚠️ Аккаунт ${account.accountName} отключен`, id);
                this.clients.delete(id);
            });

            // Логинимся
            const logOnOptions = {
                accountName: account.accountName,
                password: password
            };

            if (twoFactorCode) {
                logOnOptions.twoFactorCode = twoFactorCode;
            }

            client.logOn(logOnOptions);
            this.clients.set(id, client);

            this.logger.info(`🔄 Попытка входа в аккаунт ${account.accountName}...`, id);
        } catch (error) {
            this.logger.error(`Ошибка запуска аккаунта ${account.accountName}: ${error.message}`, id);
            throw error;
        }
    }

    async stopAccount(id) {
        const client = this.clients.get(id);
        if (client) {
            client.logOff();
            client.removeAllListeners();
            this.clients.delete(id);
            
            const account = this.accounts.get(id);
            this.logger.info(`⏸ Аккаунт ${account.accountName} остановлен`, id);
        }
    }

    async startAllAccounts() {
        for (const id of this.accounts.keys()) {
            try {
                await this.startAccount(id);
            } catch (error) {
                this.logger.error(`Ошибка запуска аккаунта ${id}: ${error.message}`);
            }
        }
    }

    async stopAllAccounts() {
        for (const id of this.clients.keys()) {
            await this.stopAccount(id);
        }
    }

    getAccountsCount() {
        return this.accounts.size;
    }
}

module.exports = AccountManager;