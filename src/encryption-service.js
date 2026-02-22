// src/encryption-service.js
const crypto = require('crypto');

class EncryptionService {
    constructor() {
        this.algorithm = 'aes-256-gcm';
        this.keyLength = 32; // 256 бит
        this.ivLength = 16; // 128 бит
        this.saltLength = 64;
        this.tagLength = 16;
    }

    // Генерация ключа из пароля
    deriveKey(password, salt) {
        return crypto.pbkdf2Sync(password, salt, 100000, this.keyLength, 'sha256');
    }

    // Шифрование данных
    encrypt(text, password) {
        const salt = crypto.randomBytes(this.saltLength);
        const iv = crypto.randomBytes(this.ivLength);
        const key = this.deriveKey(password, salt);

        const cipher = crypto.createCipheriv(this.algorithm, key, iv);
        const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();

        // Объединяем все части: соль + IV + зашифрованные данные + тег
        return Buffer.concat([salt, iv, encrypted, tag]).toString('base64');
    }

    // Дешифрование данных
    decrypt(encryptedData, password) {
        const data = Buffer.from(encryptedData, 'base64');

        const salt = data.subarray(0, this.saltLength);
        const iv = data.subarray(this.saltLength, this.saltLength + this.ivLength);
        const tag = data.subarray(data.length - this.tagLength);
        const encrypted = data.subarray(this.saltLength + this.ivLength, data.length - this.tagLength);

        const key = this.deriveKey(password, salt);

        const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
        decipher.setAuthTag(tag);

        return decipher.update(encrypted) + decipher.final('utf8');
    }

    // Хеширование пароля (для админки)
    hashPassword(password) {
        return new Promise((resolve, reject) => {
            const salt = crypto.randomBytes(16).toString('hex');
            crypto.scrypt(password, salt, 64, (err, derivedKey) => {
                if (err) reject(err);
                resolve(salt + ':' + derivedKey.toString('hex'));
            });
        });
    }

    // Проверка пароля
    verifyPassword(password, hash) {
        return new Promise((resolve, reject) => {
            const [salt, key] = hash.split(':');
            crypto.scrypt(password, salt, 64, (err, derivedKey) => {
                if (err) reject(err);
                resolve(key === derivedKey.toString('hex'));
            });
        });
    }

    // Генерация случайного токена
    generateToken(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }
}

module.exports = EncryptionService;