// src/mafile-manager.js
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

class MAFileManager {
    constructor(mafilesDir, encryptionService) {
        this.mafilesDir = mafilesDir;
        this.encryptionService = encryptionService;
        this.mafiles = new Map(); // id -> mafile data
        this.loadMAFiles();
    }

    async loadMAFiles() {
        try {
            const files = await fs.readdir(this.mafilesDir);
            for (const file of files) {
                if (file.endsWith('.json') || file.endsWith('.maFile')) {
                    try {
                        const filePath = path.join(this.mafilesDir, file);
                        const content = await fs.readFile(filePath, 'utf8');
                        const mafile = JSON.parse(content);
                        
                        // Проверяем наличие shared_secret
                        if (mafile.shared_secret) {
                            const id = mafile.id || uuidv4();
                            this.mafiles.set(id, {
                                id,
                                filename: file,
                                accountName: mafile.account_name || mafile.accountName || 'Unknown',
                                shared_secret: mafile.shared_secret,
                                steamid: mafile.SteamID || mafile.steamid,
                                linkedAccountId: null,
                                ...mafile
                            });
                        }
                    } catch (e) {
                        console.error(`Ошибка загрузки MAFile ${file}:`, e.message);
                    }
                }
            }
            console.log(`✅ Загружено ${this.mafiles.size} MAFiles`);
        } catch (error) {
            console.error('Ошибка загрузки MAFiles:', error);
        }
    }

    async getAllMAFiles() {
        return Array.from(this.mafiles.values());
    }

    async getMAFile(id) {
        return this.mafiles.get(id);
    }

    async importFromContent(content) {
        try {
            const mafile = JSON.parse(content);
            
            if (!mafile.shared_secret) {
                throw new Error('MAFile не содержит shared_secret');
            }

            const id = uuidv4();
            const filename = `${mafile.account_name || 'mafile'}_${id.slice(0, 8)}.maFile`;
            const filePath = path.join(this.mafilesDir, filename);

            // Добавляем id в объект
            mafile.id = id;

            // Сохраняем файл
            await fs.writeFile(filePath, JSON.stringify(mafile, null, 2));

            const mafileData = {
                id,
                filename,
                accountName: mafile.account_name || mafile.accountName || 'Unknown',
                shared_secret: mafile.shared_secret,
                steamid: mafile.SteamID || mafile.steamid,
                linkedAccountId: null,
                ...mafile
            };

            this.mafiles.set(id, mafileData);
            return mafileData;
        } catch (error) {
            throw new Error(`Ошибка импорта MAFile: ${error.message}`);
        }
    }

    async scanDirectory() {
        const results = {
            imported: [],
            failed: []
        };

        try {
            const files = await fs.readdir(this.mafilesDir);
            for (const file of files) {
                if (file.endsWith('.maFile') && !this.isFileImported(file)) {
                    try {
                        const filePath = path.join(this.mafilesDir, file);
                        const content = await fs.readFile(filePath, 'utf8');
                        const mafile = JSON.parse(content);
                        
                        if (mafile.shared_secret) {
                            const id = uuidv4();
                            mafile.id = id;
                            
                            // Пересохраняем с id
                            await fs.writeFile(filePath, JSON.stringify(mafile, null, 2));
                            
                            this.mafiles.set(id, {
                                id,
                                filename: file,
                                accountName: mafile.account_name || mafile.accountName || 'Unknown',
                                shared_secret: mafile.shared_secret,
                                steamid: mafile.SteamID || mafile.steamid,
                                linkedAccountId: null,
                                ...mafile
                            });
                            
                            results.imported.push({ file, success: true });
                        }
                    } catch (e) {
                        results.failed.push({ file, error: e.message });
                    }
                }
            }
        } catch (error) {
            console.error('Ошибка сканирования директории:', error);
        }

        return results;
    }

    isFileImported(filename) {
        return Array.from(this.mafiles.values()).some(m => m.filename === filename);
    }

    async linkToAccount(mafileId, accountId) {
        const mafile = this.mafiles.get(mafileId);
        if (!mafile) {
            throw new Error('MAFile не найден');
        }

        mafile.linkedAccountId = accountId;
        
        // Обновляем в файле
        try {
            const filePath = path.join(this.mafilesDir, mafile.filename);
            const content = await fs.readFile(filePath, 'utf8');
            const data = JSON.parse(content);
            data.linkedAccountId = accountId;
            await fs.writeFile(filePath, JSON.stringify(data, null, 2));
        } catch (error) {
            console.error('Ошибка обновления MAFile:', error);
        }

        return mafile;
    }

    async deleteMAFile(id) {
        const mafile = this.mafiles.get(id);
        if (!mafile) {
            throw new Error('MAFile не найден');
        }

        try {
            const filePath = path.join(this.mafilesDir, mafile.filename);
            await fs.unlink(filePath);
        } catch (error) {
            console.error('Ошибка удаления файла:', error);
        }

        this.mafiles.delete(id);
        return true;
    }

    getMAFileForAccount(accountId) {
        return Array.from(this.mafiles.values()).find(m => m.linkedAccountId === accountId);
    }
}

module.exports = MAFileManager;