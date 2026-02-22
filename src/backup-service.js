// src/backup-service.js
const fs = require('fs').promises;
const path = require('path');
const AdmZip = require('adm-zip');
const crypto = require('crypto');

class BackupService {
    constructor(dataDir, encryptionService) {
        this.dataDir = dataDir;
        this.encryptionService = encryptionService;
        this.backupDir = path.join(dataDir, 'backups');
        this.init();
    }

    async init() {
        try {
            await fs.mkdir(this.backupDir, { recursive: true });
        } catch (error) {
            console.error('Ошибка создания директории бэкапов:', error);
        }
    }

    async createBackup(password = null) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupName = `backup-${timestamp}.zip`;
        const backupPath = path.join(this.backupDir, backupName);

        try {
            const zip = new AdmZip();

            // Добавляем все файлы из data директории
            const files = await fs.readdir(this.dataDir);
            for (const file of files) {
                const filePath = path.join(this.dataDir, file);
                const stat = await fs.stat(filePath);
                
                if (stat.isFile() && file !== 'backups') {
                    zip.addLocalFile(filePath);
                }
            }

            // Если указан пароль, шифруем zip
            if (password) {
                // Создаем временный zip
                const tempZipPath = path.join(this.backupDir, `temp-${timestamp}.zip`);
                zip.writeZip(tempZipPath);

                // Шифруем его
                const encrypted = this.encryptionService.encrypt(
                    await fs.readFile(tempZipPath, 'base64'),
                    password
                );

                // Сохраняем зашифрованный файл
                await fs.writeFile(backupPath, encrypted);

                // Удаляем временный файл
                await fs.unlink(tempZipPath);
            } else {
                zip.writeZip(backupPath);
            }

            return backupPath;
        } catch (error) {
            throw new Error(`Ошибка создания бэкапа: ${error.message}`);
        }
    }

    async restoreFromBackup(backupPath, password = null) {
        try {
            let zipData;

            if (password) {
                // Расшифровываем
                const encrypted = await fs.readFile(backupPath, 'utf8');
                const decrypted = this.encryptionService.decrypt(encrypted, password);
                zipData = Buffer.from(decrypted, 'base64');
            } else {
                zipData = await fs.readFile(backupPath);
            }

            const zip = new AdmZip(zipData);
            
            // Создаем временную директорию для распаковки
            const tempDir = path.join(this.backupDir, 'temp_restore');
            await fs.mkdir(tempDir, { recursive: true });

            // Распаковываем
            zip.extractAllTo(tempDir, true);

            // Копируем файлы обратно в data директорию
            const files = await fs.readdir(tempDir);
            for (const file of files) {
                const srcPath = path.join(tempDir, file);
                const destPath = path.join(this.dataDir, file);
                await fs.copyFile(srcPath, destPath);
            }

            // Удаляем временную директорию
            await fs.rm(tempDir, { recursive: true, force: true });

            return true;
        } catch (error) {
            throw new Error(`Ошибка восстановления из бэкапа: ${error.message}`);
        }
    }

    async listBackups() {
        try {
            const files = await fs.readdir(this.backupDir);
            const backups = [];

            for (const file of files) {
                if (file.endsWith('.zip')) {
                    const filePath = path.join(this.backupDir, file);
                    const stat = await fs.stat(filePath);
                    
                    backups.push({
                        name: file,
                        size: stat.size,
                        created: stat.birthtime
                    });
                }
            }

            return backups.sort((a, b) => b.created - a.created);
        } catch (error) {
            console.error('Ошибка получения списка бэкапов:', error);
            return [];
        }
    }
}

module.exports = BackupService;