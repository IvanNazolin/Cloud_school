const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function encryptFile(filePath, password) {
    const algorithm = 'aes-256-cbc';
    const iv = Buffer.alloc(16, 0);  // Фиксированный IV (все нули)

    // Генерация ключа с использованием PBKDF2
    const key = crypto.pbkdf2Sync(password, '', 100000, 32, 'sha256');  // Используем PBKDF2 для создания 256-битного ключа

    const fileData = fs.readFileSync(filePath);

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(fileData);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    // Добавляем IV к зашифрованным данным
    const result = Buffer.concat([iv, encrypted]);

    // Формируем имя нового зашифрованного файла рядом с самим скриптом
    const dir = __dirname;  // Директория, где находится скрипт
    const fileName = path.basename(filePath);  // Имя исходного файла
    const encryptedFileName = fileName.replace(/(\.[\w\d_-]+)$/i, 's$1');  // Добавляем 's' перед расширением

    // Путь для нового зашифрованного файла
    const encryptedFilePath = path.join(dir, encryptedFileName);

    // Запись зашифрованного файла
    fs.writeFileSync(encryptedFilePath, result);

    return encryptedFileName;  // Возвращаем имя нового зашифрованного файла
}

const filePath = process.argv[2];
const password = process.argv[3];

if (!filePath || !password) {
    console.log('Usage: node encrypt.js <file-path> <password>');
    process.exit(1);
}

const encryptedFileName = encryptFile(filePath, password);
console.log(`File encrypted successfully: ${encryptedFileName}`);
