// src/settings-service.js
const fs = require('fs').promises;
const path = require('path');

class SettingsService {
    constructor(dataDir, encryptionService) {
        this.dataDir = dataDir;
        this.settingsFile = path.join(dataDir, 'settings.json');
        this.encryptionService = encryptionService;
        this.defaultSettings = {
            autoStart: false,
            defaultGames: [730],
            defaultPersonaState: 0,
            reconnectAttempts: 10,
            reconnectDelay: 30000,
            theme: 'dark',
            language: 'ru',
            notifications: true
        };
        this.settings = null;
        this.loadSettings();
    }

    async loadSettings() {
        try {
            const data = await fs.readFile(this.settingsFile, 'utf8');
            this.settings = JSON.parse(data);
        } catch (error) {
            if (error.code === 'ENOENT') {
                // Файл не существует, создаем с настройками по умолчанию
                this.settings = { ...this.defaultSettings };
                await this.saveSettings();
            } else {
                console.error('Ошибка загрузки настроек:', error);
                this.settings = { ...this.defaultSettings };
            }
        }
    }

    async saveSettings() {
        await fs.writeFile(this.settingsFile, JSON.stringify(this.settings, null, 2));
    }

    async getAllSettings() {
        return { ...this.settings };
    }

    async getSetting(key) {
        return this.settings[key];
    }

    async updateSettings(newSettings) {
        this.settings = {
            ...this.settings,
            ...newSettings
        };
        await this.saveSettings();
        return this.settings;
    }

    async updateSetting(key, value) {
        this.settings[key] = value;
        await this.saveSettings();
        return value;
    }

    async resetToDefaults() {
        this.settings = { ...this.defaultSettings };
        await this.saveSettings();
        return this.settings;
    }
}

module.exports = SettingsService;