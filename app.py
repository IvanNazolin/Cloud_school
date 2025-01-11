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
import sqlite3


encode_mod=0

app = Flask(__name__)
talisman = Talisman(app, force_https=True)

bd = sqlite3.connect('cloud.db')
cursor = bd.cursor()

cursor.execute("SELECT base_dir_level_1 FROM config WHERE id = 1")
# Укажите корневой каталог для сканирования
BASE_DIR = os.path.expanduser((cursor.fetchone())[0])
# Специальные данные для доступа к настройкам
SETTINGS_USERNAME = 'admin'
SETTINGS_PASSWORD = 'admin'  # Задайте свой пароль для доступа к настройкам

USERNAME = ''
PASSWORD_HASH = ''  


bd.close()

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

def check_auth(username, password, password_hash):
    """Функция для проверки аутентификационных данных"""
    return  hmac.compare_digest(password_hash, hashlib.sha256(password.encode()).hexdigest())

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
        Apassword_hash = ""
        password_hash=""
        username = request.form['username']
        username = hashlib.sha256(username.encode()).hexdigest()
        password = request.form['password']
        bd = sqlite3.connect('cloud.db')
        cursor = bd.cursor()

        # Получаем хэш пароля для пользователя
        cursor.execute(f"SELECT password_hash FROM config WHERE username='{username}'")
        tmp = cursor.fetchone()
        if tmp:
            password_hash = tmp[0]

        # Получаем папку, к которой имеет доступ пользователь
        cursor.execute(f"SELECT base_dir_level_1 FROM config WHERE username='{username}'")
        tmp = cursor.fetchone()
        folder_path = tmp[0] if tmp else None

        cursor.execute(f"SELECT Admin_pass FROM config WHERE Admin_id='{username}'")
        tmp = cursor.fetchone()
        if tmp:
            Apassword_hash = tmp[0]
            print("пароль есть")

        print("проверка аутентификации")
        if check_auth(username, password, Apassword_hash):
            # Если введены специальные данные, перенаправляем на страницу настроек
            session['username'] = username
            session['folder_path'] = folder_path  # Сохраняем путь к папке в сессии
            return redirect(url_for('settings'))
        elif check_auth(username, password, password_hash):
            session['username'] = username
            session['folder_path'] = folder_path  # Сохраняем путь к папке в сессии
            ip_address = request.remote_addr  # Получаем IP-адрес пользователя
            print(f"Авторизация успешна с IP-адреса: {ip_address}")
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')

@app.route('/settings', methods=['GET', 'POST'])
@requires_auth
def settings():
    """Страница настроек"""
    user = list()
    if request.method == 'POST':
        # Получаем выбранного пользователя по user_id
        selected_user_id = request.form.get('selected_user_id')
        new_username = request.form.get('new_username')
        new_password = request.form.get('new_password')
        
        new_admin_name = request.form.get('new_admin_name')
        new_admin_password = request.form.get('new_admin_password')

        encryption_mode = request.form.get('encryption_mode')      
        
        # Подключаемся к базе данных
        try:
            conn = sqlite3.connect('cloud.db')  # Путь к вашей базе данных
            cursor = conn.cursor()


            # Если выбран пользователь, применяем изменения к нему
            if selected_user_id:
                # Применяем изменения к выбранному пользователю
                cursor.execute('SELECT username FROM config WHERE user_id = ?', (selected_user_id,))
                user = cursor.fetchone()
                if user:
                    user = user[0]  # Получаем имя пользователя
                else:
                    user = session.get('username')  # Если user_id не найден, применяем изменения к текущему пользователю
            else:
                user = session.get('username')  # Если не выбрали, изменения для текущего пользователя

            # Обновляем имя пользователя, если оно указано
            if new_username:
                new_username_hash = hashlib.sha256(new_username.encode()).hexdigest()
                cursor.execute('''UPDATE config SET username = ? WHERE user_id = ?''',
                (new_username_hash, selected_user_id))

                cursor.execute('''UPDATE config SET user_id = ? WHERE user_id = ? ''',
                (new_username, selected_user_id))

            # Обновляем пароль пользователя, если оно указано
            if new_password:
                new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
                cursor.execute('''UPDATE config SET password_hash = ? WHERE user_id = ? ''',
                (new_password_hash, selected_user_id))

            # Обновляем имя администратора, если оно указано
            if new_admin_name:
                new_admin_name_hash = hashlib.sha256(new_admin_name.encode()).hexdigest()
                cursor.execute(''' UPDATE config SET Admin_id = ? WHERE id = 1 ''',
                (new_admin_name_hash,))

            # Обновляем пароль администратора, если оно указано
            if new_admin_password:
                new_admin_password_hash = hashlib.sha256(new_admin_password.encode()).hexdigest()
                cursor.execute(''' UPDATE config SET Admin_pass = ? WHERE id = 1 ''', 
                (new_admin_password_hash,))

            # Обновляем режим шифрования, если указано
            if int(encryption_mode) == 1:
                cursor.execute(''' UPDATE config SET encryption_mode = ? WHERE id = 1 ''', (1,))
            elif int(encryption_mode) == 0:
                cursor.execute(''' UPDATE config SET encryption_mode = ? WHERE id = 1 ''', (0,))

            # Сохраняем изменения
            conn.commit()
            conn.close()

            # Перенаправляем на страницу настроек
            return redirect(url_for('settings'))

        except sqlite3.Error as e:
            print(f"Ошибка базы данных: {e}")
            return f"Ошибка базы данных: {e}", 500  # Возвращаем ошибку с описанием

    # Подключаемся к базе данных для получения всех авторизованных пользователей
    try:
        conn = sqlite3.connect('cloud.db')
        cursor = conn.cursor()
        cursor.execute('SELECT user_id, username FROM config')  # Получаем user_id и username всех пользователей
        users = cursor.fetchall()
        conn.close()

    except sqlite3.Error as e:
        print(f"Ошибка базы данных: {e}")
        users = []
    print(users)
    return render_template('settings.html', username=('Administrator'), users=users)

@app.route('/')
@app.route('/<path:subpath>')
@requires_auth
def index(subpath=''):
    """Основная страница"""
    # Получаем путь к папке, к которой имеет доступ пользователь
    user_folder_path = session.get('folder_path', '')
    if not user_folder_path:
        return "Access denied", 403  # Если папка не найдена, отказ в доступе

    # Путь до папки для отображения (пользователь не может выйти за пределы своей папки)
    full_path = os.path.join(BASE_DIR, user_folder_path, subpath)

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
        print(directory)
        bd = sqlite3.connect('cloud.db')
        cursor = bd.cursor()
        cursor.execute("SELECT encryption_mode FROM config WHERE id = 1")
        encode_mod = int(cursor.fetchone()[0])
        bd.close()

        if encode_mod == 1:
            encrypt_file_with_js(directory+"/"+filename,config.ENCODE_PASS)
            index = filename.rfind('.')  # Находим индекс последней точки
            filename = filename[:index] + 's' + filename[index:]
            directory = os.path.dirname(os.path.abspath(__file__))
            return send_from_directory(directory, filename, as_attachment=True)
        else:
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
@requires_auth
def open_encode():
    # Отдаем файл encode.html из папки static
   return render_template('encode.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0' , port=100, ssl_context=('sertificats/certificate.crt', 'sertificats/certificate.key'))
    