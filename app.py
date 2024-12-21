from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, Response
import os
import subprocess
import sys
import hashlib
import hmac
import config
import zipfile
import tempfile
import urllib.parse
from functools import wraps
from flask_talisman import Talisman

app = Flask(__name__)
talisman = Talisman(app, force_https=True)

# Укажите корневой каталог для сканирования
BASE_DIR = os.path.expanduser(config.BASE_DIR)

# Учетные данные для входа (пароль будет хешироваться)
USERNAME = config.USERNAME
PASSWORD_HASH = config.PASSWORD_HASH  # Пароль должен быть захеширован заранее в config

# Специальные данные для доступа к настройкам
SETTINGS_USERNAME = 'admin'
SETTINGS_PASSWORD = 'admin'  # Задайте свой пароль для доступа к настройкам

# Секретный ключ для работы с сессиями
app.secret_key = 'your_secret_key'

# Настройка логирования
import logging
logging.basicConfig(level=logging.DEBUG)

# Максимальный размер файла для загрузки (например, 16 MB)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

def encrypt_file_with_js(file_path, password):
    # Запуск Node.js скрипта с аргументами (путь к файлу и пароль)
    result = subprocess.run(['node', 'encrypt.js', file_path, password], capture_output=True, text=True)
    
    if result.returncode == 0:
        # Чтение результата из вывода Node.js скрипта
        encrypted_file_path = result.stdout.strip()  # Убираем лишние пробелы и новые строки
        print(f"Encryption successful. Encrypted file: {encrypted_file_path}")
    else:
        print("Error:", result.stderr)


def check_auth(username, password):
    """Функция для проверки аутентификационных данных"""
    return username == USERNAME and hmac.compare_digest(PASSWORD_HASH, hashlib.sha256(password.encode()).hexdigest())

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Реализация аутентификации через форму"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == SETTINGS_USERNAME and password == SETTINGS_PASSWORD:
            # Если введены специальные данные, перенаправляем на страницу настроек
            session['username'] = username
            return redirect(url_for('settings'))
        elif check_auth(username, password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')

@app.route('/settings', methods=['GET', 'POST'])
@requires_auth
def settings():
    """Страница настроек"""
    if request.method == 'POST':
        # Обработка изменения настроек, например, изменение пароля
        new_password = request.form.get('new_password')
        if new_password:
            # Хэшируем новый пароль и обновляем в конфиге
            new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
            config.PASSWORD_HASH = new_password_hash
            return redirect(url_for('index'))

    return render_template('settings.html', username=USERNAME)


@app.route('/')
@app.route('/<path:subpath>')
@requires_auth
def index(subpath=''):
    """Основная страница"""
    full_path = os.path.join(BASE_DIR, subpath)

    if not os.path.exists(full_path):
        return "Directory not found", 404

    items = os.listdir(full_path)
    items.sort()

    file_list = []
    for item in items:
        item_path = os.path.join(full_path, item)
        file_list.append({
            'name': item,
            'is_dir': os.path.isdir(item_path),
            'path': os.path.join(subpath, item).replace("\\", "/"),
            'size_mb': round(os.path.getsize(item_path) / (1024 * 1024), 2) if os.path.isfile(item_path) else None
        })

    current_folder = os.path.basename(full_path) if subpath else 'Root'

    return render_template('index.html', items=file_list, subpath=subpath, os=os, current_folder=current_folder)

@app.route('/logout')
def logout():
    """Выход из системы"""
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/download/<path:filepath>')
@requires_auth
def download_file(filepath):
    """Загрузка файла"""
    try:
        directory = os.path.join(BASE_DIR, os.path.dirname(filepath))
        filename = os.path.basename(filepath)

        # Проверяем существование файла
        file_path = os.path.join(directory, filename)
        if not os.path.exists(file_path):
            return "File not found", 404
        
        encrypt_file_with_js(directory+"/"+filename,config.ENCODE_PASS)
        index = filename.rfind('.')  # Находим индекс последней точки
        filename = filename[:index] + 's' + filename[index:]
        directory = os.path.dirname(os.path.abspath(__file__))
        print(directory)
        return send_from_directory(directory, filename, as_attachment=True)

    except Exception as e:
        app.logger.error(f"Error downloading file: {str(e)}")
        return "Internal Server Error", 500

def generate_zip_stream(folder_path):
    """Генерация архива без сжатия (ZIP_STORED)"""
    def generate_zip():
        # Создаем временный файл для архива
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            with zipfile.ZipFile(tmpfile, 'w', zipfile.ZIP_STORED) as archive:  # Без сжатия
                for foldername, subfolders, filenames in os.walk(folder_path):
                    for filename in filenames:
                        filepath = os.path.join(foldername, filename)
                        arcname = os.path.relpath(filepath, folder_path)  # Путь в архиве
                        archive.write(filepath, arcname)  # Добавление файла без сжатия

            # Закрываем временный файл, чтобы его можно было отдать пользователю
            tmpfile.close()

            # Читаем временный файл и отправляем его содержимое
            with open(tmpfile.name, 'rb') as f:
                yield f.read()  # Читаем и передаем содержимое файла

            # Удаляем временный файл после отправки
            os.remove(tmpfile.name)
    return generate_zip()

@app.route('/download_folder/<path:folderpath>')
@requires_auth
def download_folder(folderpath):
    """Загрузка архива папки без сжатия (ZIP_STORED) с потоковой передачей данных"""
    try:
        if folderpath == '':
            folder_to_download = BASE_DIR
        else:
            folder_to_download = os.path.join(BASE_DIR, folderpath)

        if not os.path.exists(folder_to_download) or not os.path.isdir(folder_to_download):
            return "Folder not found", 404

        # Генерация архива в потоке
        filename = f"{os.path.basename(folder_to_download)}.zip"
        filename = urllib.parse.quote(filename)  # URL-кодирование имени файла

        # Создание генератора архива
        return Response(generate_zip_stream(folder_to_download),
                        mimetype='application/zip',
                        content_type='application/zip',
                        headers={
                            'Content-Disposition': f'attachment; filename*=UTF-8\'\'{filename}'
                        })

    except Exception as e:
        app.logger.error(f"Error downloading folder: {str(e)}")
        return "Internal Server Error", 500

@app.route('/upload', methods=['POST'])
@requires_auth
def upload_file():
    # Получаем относительный путь из формы (если предоставлен)
    subpath = request.form.get('subpath', '')
    full_path = os.path.join(BASE_DIR, subpath)

    # Проверяем, существует ли папка назначения, иначе создаем
    if not os.path.exists(full_path):
        try:
            os.makedirs(full_path)
        except OSError as e:
            app.logger.error(f"Ошибка при создании папки {full_path}: {e}")
            return "Internal Server Error: Unable to create directory", 500

    # Проверяем, есть ли файл в запросе
    if 'file' not in request.files:
        app.logger.warning("Файл не найден в запросе")
        return redirect(request.referrer)

    file = request.files['file']
    if not file or file.filename == '':
        app.logger.warning("Имя файла отсутствует или файл не загружен")
        return redirect(request.referrer)

    # Безопасно извлекаем имя файла и сохраняем его
    filename = os.path.basename(file.filename)
    destination_path = os.path.join(full_path, filename)

    try:
        file.save(destination_path)
        app.logger.info(f"Файл {filename} успешно загружен в {destination_path}")
    except Exception as e:
        app.logger.error(f"Ошибка при сохранении файла {filename}: {e}")
        return "Internal Server Error: Unable to save file", 500

    # Перенаправляем обратно на страницу
    return redirect(url_for('index', subpath=subpath))

@app.route('/create_folder', methods=['POST'])
@requires_auth
def create_folder():
    """Создание новой папки"""
    folder_name = request.form.get('folder_name')
    subpath = request.form.get('subpath', '')
    parent_folder_path = os.path.join(BASE_DIR, subpath)

    if not folder_name:
        return "Folder name is required", 400

    # Проверяем, существует ли папка назначения
    if not os.path.exists(parent_folder_path):
        return "Parent directory does not exist", 404

    # Создаем новую папку
    new_folder_path = os.path.join(parent_folder_path, folder_name)
    try:
        os.makedirs(new_folder_path)
        app.logger.info(f"Folder {folder_name} created successfully at {new_folder_path}")
    except OSError as e:
        app.logger.error(f"Error creating folder {folder_name}: {e}")
        return "Internal Server Error: Unable to create folder", 500

    return redirect(url_for('index', subpath=subpath))

@app.route('/open_encode')
def open_encode():
    # Отдаем файл encode.html из папки static
   return render_template('encode.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0',
    port=100,
    ssl_context=('sertificats/certificate.crt', 'sertificats/certificate.key'))
