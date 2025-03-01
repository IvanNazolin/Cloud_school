from flask import Flask, request, jsonify, send_from_directory, Response, session, redirect, url_for
from flask_cors import CORS
import json
import os
import hashlib
import sqlite3
import subprocess
import sys
import hmac
import zipfile
import tempfile
import urllib.parse
from functools import wraps
from flask_talisman import Talisman

app = Flask(__name__)
CORS(app)

# Секретный ключ для сессий
app.secret_key = '1234'

BASE_DIR = "D:/проект 10 класс/реализация/Cloud_school/example"

# Простая эмуляция базы данных пользователей с хэшированием паролей
USERS = {
    "admin": hashlib.sha256("1234".encode()).hexdigest(),
    "user": hashlib.sha256("password".encode()).hexdigest()
}


def encrypt_file_with_js(file_path, password):
    # Запуск Node.js скрипта с аргументами (путь к файлу и пароль)
    result = subprocess.run(['node', 'encrypt.js', file_path, password], capture_output=True, text=True)
    
    if result.returncode == 0:
        # Чтение результата из вывода Node.js скрипта
        encrypted_file_path = result.stdout.strip()  # Убираем лишние пробелы и новые строки
        print(f"Encryption successful. Encrypted file: {encrypted_file_path}")
    else:
        print("Error:", result.stderr)

# Функция для записи данных в файл
def log_data_to_file(data):
    log_file_path = "login_requests.json"
    
    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as f:
            current_data = json.load(f)
    else:
        current_data = []
    
    current_data.append(data)
    
    with open(log_file_path, "w") as f:
        json.dump(current_data, f, indent=4)

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    log_data_to_file(data)
    
    login = data.get("login")
    password = data.get("password")
    
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    hashed_login = hashlib.sha256(login.encode()).hexdigest()
    
    bd = sqlite3.connect('bd/cloud.db')
    cursor = bd.cursor()

    cursor.execute(f"SELECT password_hash FROM config WHERE username='{hashed_login}'")
    tmp = cursor.fetchone()
    if tmp:
        password_hash = tmp[0]
        if password_hash == hashed_password:

    #if login in USERS and USERS[login] == hashed_password:
            session['login'] = login  # Сохраняем информацию о пользователе в сессии
            return jsonify({"status": "success", "message": "Вход выполнен успешно"}), 200
        else:
            return jsonify({"status": "error", "message": "Неверный логин или пароль"}), 401

    else:
        return jsonify({"status": "error", "message": "Неверный логин или пароль"}), 401

@app.route('/api/folder/', defaults={'subpath': ''}, methods=['GET'])
@app.route('/api/folder/<path:subpath>', methods=['GET'])
def get_folder_info(subpath):
    print(f"Requested path: {subpath}")
    
    # Получаем папку пользователя из сессии
    user_folder_path = session.get('folder_path', BASE_DIR)

    if not user_folder_path:
        return jsonify({'message': 'Access denied'}), 403

    full_path = os.path.join(user_folder_path, subpath) if subpath else user_folder_path

    print(f"Full path: {full_path}")

    if not os.path.exists(full_path):
        print(f"Directory not found: {full_path}")
        return jsonify({'message': 'Directory not found'}), 404

    items = os.listdir(full_path)
    file_list = [{
        'name': item,
        'is_dir': os.path.isdir(os.path.join(full_path, item)),
        'path': os.path.join(subpath, item).replace("\\", "/") if subpath else item
    } for item in sorted(items)]


    log_data_to_file({'requested_path': subpath, 'full_path': full_path, 'files': file_list})  # Логируем входные и выходные данные

    return jsonify({'items': file_list, 'current_folder': os.path.basename(full_path) if subpath else 'Root'})

@app.route('/download/<path:filepath>')
def download_file(filepath):
    """Загрузка файла"""
    try:
        directory = os.path.join(BASE_DIR, os.path.dirname(filepath))
        filename = os.path.basename(filepath)

        file_path = os.path.join(directory, filename)
        if not os.path.exists(file_path):
            return "File not found", 404

        bd = sqlite3.connect('cloud.db')
        cursor = bd.cursor()
        cursor.execute("SELECT encryption_mode FROM config WHERE id = 1")
        result = cursor.fetchone()
        encode_mod = int(result[0]) if result and result[0] is not None else 0
        bd.close()

        return send_from_directory(str(directory), str(filename), as_attachment=True)

    except Exception as e:
        app.logger.error(f"Error downloading file: {str(e)}")
        return "Internal Server Error", 500

def generate_zip_stream(folder_path):
    """Создание ZIP-архива в потоке"""
    def generate_zip():
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            with zipfile.ZipFile(tmpfile, 'w', zipfile.ZIP_STORED) as archive:
                for foldername, subfolders, filenames in os.walk(folder_path):
                    for filename in filenames:
                        filepath = os.path.join(foldername, filename)
                        arcname = os.path.relpath(filepath, folder_path)
                        archive.write(filepath, arcname)

            tmpfile.close()
            with open(tmpfile.name, 'rb') as f:
                yield f.read()
            os.remove(tmpfile.name)
    return generate_zip()

@app.route('/download_folder/<path:folderpath>')
def download_folder(folderpath):
    """Загрузка архива папки"""
    try:
        folder_to_download = os.path.join(BASE_DIR, folderpath) if folderpath != 'R' else BASE_DIR
        if not os.path.exists(folder_to_download) or not os.path.isdir(folder_to_download):
            return "Folder not found", 404

        filename = f"{os.path.basename(folder_to_download)}.zip"
        filename = urllib.parse.quote(filename)

        return Response(generate_zip_stream(folder_to_download),
                        mimetype='application/zip',
                        content_type='application/zip',
                        headers={'Content-Disposition': f'attachment; filename*=UTF-8\'\'{filename}'})

    except Exception as e:
        app.logger.error(f"Error downloading folder: {str(e)}")
        return "Internal Server Error", 500

@app.route('/upload/<path:subpath>', methods=['POST'])
def upload_file(subpath):
    """Загрузка файлов через drag-and-drop"""
    full_path = os.path.join(BASE_DIR, subpath)

    if not os.path.exists(full_path):
        try:
            os.makedirs(full_path)
        except OSError as e:
            app.logger.error(f"Ошибка создания папки {full_path}: {e}")
            return "Internal Server Error", 500

    if 'file' not in request.files:
        return "No file part", 400

    files = request.files.getlist('file')

    if not files:
        return "No files selected", 400

    for file in files:
        if file and file.filename:
            filename = os.path.basename(file.filename)
            destination_path = os.path.join(full_path, filename)

            try:
                file.save(destination_path)
                app.logger.info(f"Файл {filename} загружен в {destination_path}")
            except Exception as e:
                app.logger.error(f"Ошибка сохранения файла {filename}: {e}")
                return "Internal Server Error", 500

    return jsonify({"status": "success", "message": "Файлы загружены"}), 200

@app.route('/api/folder/create', methods=['POST'])
def create_folder():
    """Создание новой папки"""
    # Получаем данные из запроса
    data = request.get_json()
    folder_name = data.get('folder_name')  # Имя папки
    subpath = data.get('subpath', '')  # Путь к родительской папке, если есть

    # Проверяем, что имя папки указано
    if not folder_name:
        return jsonify({"error": "Folder name is required"}), 400
    
    # Строим полный путь для создания папки
    full_path = os.path.join(BASE_DIR, subpath, folder_name)

    # Проверяем, существует ли родительская папка
    if not os.path.exists(os.path.dirname(full_path)):
        return jsonify({"error": "Parent directory does not exist"}), 404

    # Пробуем создать новую папку
    try:
        os.makedirs(full_path)
        app.logger.info(f"Folder {folder_name} created at {full_path}")
        return jsonify({"status": "success", "message": "Folder created"}), 200
    except OSError as e:
        app.logger.error(f"Error creating folder {folder_name}: {e}")
        return jsonify({"error": "Internal Server Error"}), 500



if __name__ == "__main__":
    app.run(host='0.0.0.0' , port=100)
    #app.run(host='0.0.0.0' , port=100, ssl_context=('sertificats/certificate.crt', 'sertificats/certificate.key'))
