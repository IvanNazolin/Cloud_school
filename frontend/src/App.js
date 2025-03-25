import React, { useState, useEffect, useRef  } from 'react';
import './App.css';

const baseApiUrl = "http://192.168.1.10:100";

const hash = async (message) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(byte => byte.toString(16).padStart(2, "0")).join("");
};


function Login({ setStatus, setRole }) {
  const [login, setLogin] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [role, setRoleState] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();

    try {
      // Hash login and password before sending
      const hashedLogin = await hash(login);
      const hashedPassword = await hash(password);

      const response = await fetch(`${baseApiUrl}/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ login: hashedLogin, password: hashedPassword }),
      });

      const data = await response.json();
      if (response.ok) {
        setMessage(data.message);
        setStatus('success');
        setRole(data.role);  // Set the role passed from the response
      } else {
        setMessage(data.message);
      }
    } catch (error) {
      setMessage('Ошибка сети');
    }
  };

  useEffect(() => {
    document.body.classList.add("centered-body");

    return () => {
      document.body.classList.remove("centered-body");
    };
  }, []);

  return (
    <div className="login">
      <div className="h1">Вход</div>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Логин"
          value={login}
          onChange={(e) => setLogin(e.target.value)}
          required
        />
        <div className="password-input">
          <input
            type={showPassword ? "text" : "password"}
            placeholder="Пароль"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <span
            className="password-toggle"
            onClick={() => setShowPassword(!showPassword)}
          >
            {showPassword ? "👁️" : "👁️"}
          </span>
        </div>
        <input type="submit" value="Войти" className="btn" />
      </form>
      {message && <div className="message">{message}</div>}
      {role && <div className="role">Роль: {role}</div>}
    </div>
  );
}

function FilePage() {
  const [files, setFiles] = useState([]);
  const [currentFolder, setCurrentFolder] = useState("Главная");
  const [subpath, setSubpath] = useState("");
  const [newFolderName, setNewFolderName] = useState("");
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [showCripto, setShowCripto] = useState(false);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async (path = "") => {
    try {
      const response = await fetch(`${baseApiUrl}/api/folder/${path}`);
      if (!response.ok) throw new Error("Ошибка загрузки");
      const data = await response.json();
      setFiles(data.items || []);
      setCurrentFolder(data.current_folder || "Главная");
      setSubpath(path);
    } catch (error) {
      console.error("Ошибка загрузки:", error);
    }
  };

  const openFolder = (folderName) => {
    fetchData(folderName);
  };

  const goBack = () => {
    const pathParts = subpath.split("/");
    pathParts.pop();
    fetchData(pathParts.join("/"));
  };

  const handleFileChange = (event) => {
    setSelectedFiles(event.target.files);
  };

  const handleUpload = async () => {
    if (selectedFiles.length === 0) {
      alert("Выберите файлы для загрузки.");
      return;
    }

    const formData = new FormData();
    for (let file of selectedFiles) {
      formData.append("file", file);
    }

    try {
      const response = await fetch(`${baseApiUrl}/upload/${subpath}`, {
        method: "POST",
        body: formData,
      });

      if (response.ok) {
        alert("Файлы успешно загружены!");
        fetchData(subpath);
      } else {
        alert("Ошибка загрузки файлов.");
      }
    } catch (error) {
      console.error("Ошибка при загрузке:", error);
      alert("Ошибка сети.");
    }
  };

  const createFolder = async () => {
    if (!newFolderName.trim()) return;

    const folderData = {
      folder_name: newFolderName,
      subpath: subpath,
    };

    try {
      const response = await fetch(`${baseApiUrl}/api/folder/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(folderData),
      });

      const data = await response.json();
      if (response.ok) {
        setNewFolderName('');
        fetchData(subpath);
      } else {
        alert('Ошибка при создании папки');
      }
    } catch (error) {
      console.error('Ошибка создания папки:', error);
    }
  };

  const handleDownloadFolder = async () => {
    try {
      const response = await fetch(`${baseApiUrl}/download_folder/${subpath}`);
      
      // Если сервер возвращает ошибку или пустой ответ, выведем сообщение
      if (!response.ok) {
        const errorMessage = await response.text();
        alert(`Ошибка при скачивании папки: ${errorMessage || 'Неизвестная ошибка'}`);
        return;
      }
  
      // Проверка на пустой ответ (если папка пуста или не существует)
      const blob = await response.blob();
      if (blob.size === 0) {
        alert('Папка пуста или не существует.');
        return;
      }
  
      // Если всё в порядке, скачиваем файл
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = `${currentFolder}.zip`; // Имя архива будет равно имени текущей папки
      link.click();
    } catch (error) {
      console.error("Ошибка при скачивании папки:", error);
      alert("Ошибка при скачивании папки.");
    }
  };

  const criptFile = () => {
    setShowCripto(true); 
  };

  if (showCripto) {
    return <Cripto onBack={() => setShowCripto(false)} />;
  }

  return (
    <div className="app-container">
    <aside className="sidebar">
      {/* Sidebar content */}
    </aside>
    <main className="file-list-container">
      <h1 className="folder-title">{currentFolder}</h1>
  
      {/* Контейнер для кнопок */}
      <div className="button-group">
        {subpath && <button onClick={goBack} className="button back">🔙 Назад</button>}
        <input
          type="text"
          placeholder="Имя новой папки"
          value={newFolderName}
          onChange={(e) => setNewFolderName(e.target.value)}
          className="folder-input"
        />
        <button onClick={createFolder} className="button create-folder-btn">Создать папку</button>
        <input type="file" multiple onChange={handleFileChange} className="file-input" />
        <button onClick={handleUpload} className="button upload-btn">Загрузить файлы</button>
        <button onClick={handleDownloadFolder} className="button download-folder-btn">Скачать папку</button>
        <button onClick={criptFile} className="button criptFile">Дешифровка файла</button>
      </div>
  
      {/* Список файлов */}
      <ul className="file-list">
        {files.map((item) => (
          <li key={item.name} className={`file-item ${item.is_dir ? 'folder' : 'file'}`}>
            <div className="file-row">
              {item.is_dir ? (
                <button className="file-button" onClick={() => openFolder(item.path)}>📁 {item.name}</button>
              ) : (
                <a className="file-link" href={`${baseApiUrl}/download/${item.path}`}>{item.name}</a>
              )}
            </div>
          </li>
        ))}
      </ul>
    </main>
  </div>
  
  );
}

async function hashData(data) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function AdminPage() {
  const [users, setUsers] = useState([]);
  const [activeSessions, setActiveSessions] = useState([]);
  const [formData, setFormData] = useState({});

  useEffect(() => {
    fetch("/api/users")
      .then((response) => response.json())
      .then((data) => setUsers(data))
      .catch((error) => console.error("Error fetching users:", error));

    fetch("/api/sessions")
      .then((response) => response.json())
      .then((data) => setActiveSessions(data))
      .catch((error) => console.error("Error fetching sessions:", error));
  }, []);

  const handleChange = async (field, value) => {
    if (value) {
      const hashedValue = ["newPassword", "newAdminPassword"].includes(field)
        ? await hashData(value)
        : value;
      setFormData(prev => ({ ...prev, [field]: hashedValue }));
    } else {
      setFormData(prev => {
        const updatedForm = { ...prev };
        delete updatedForm[field];
        return updatedForm;
      });
    }
  };

  const handleSave = async (event) => {
    event.preventDefault();
    if (Object.keys(formData).length === 0) {
      alert("No changes detected");
      return;
    }

    try {
      const response = await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });
      const result = await response.json();
      alert(result.message);
    } catch (error) {
      console.error("Error saving settings:", error);
    }
  };

  const handleDisconnect = async (ip) => {
    try {
      const response = await fetch(`/api/disconnect/${ip}`, { method: "POST" });
      const result = await response.json();
      alert(result.message);
      setActiveSessions(prev => prev.filter(session => session.ip !== ip));
    } catch (error) {
      console.error("Error disconnecting user:", error);
    }
  };

  return (
    <div>
      <h1>Settings</h1>
      <form onSubmit={handleSave}>
        <a className="button log out" href="/logout">Вернуться</a>
        <label htmlFor="selected_user_id">Выберите пользователя:</label>
        <select
          id="selected_user_id"
          onChange={(e) => handleChange("selectedUser", e.target.value)}
        >
          <option value="">Текущий пользователь</option>
          {users.map((user) => (
            <option key={user.id} value={user.id}>{user.name}</option>
          ))}
        </select>
        <br /><br />

        <label htmlFor="new_username">Новое имя пользователя:</label>
        <input
          type="text"
          id="new_username"
          onChange={(e) => handleChange("newUsername", e.target.value)}
        />
        <br /><br />

        <label htmlFor="new_password">Новый пароль пользователя:</label>
        <input
          type="password"
          id="new_password"
          onChange={(e) => handleChange("newPassword", e.target.value)}
        />
        <hr />

        <label htmlFor="new_admin_name">Новое имя админа:</label>
        <input
          type="text"
          id="new_admin_name"
          onChange={(e) => handleChange("newAdminName", e.target.value)}
        />
        <br /><br />

        <label htmlFor="new_admin_password">Новый пароль админа:</label>
        <input
          type="password"
          id="new_admin_password"
          onChange={(e) => handleChange("newAdminPassword", e.target.value)}
        />
        <hr />

        <label htmlFor="encryption_mode">Активировать шифрование:</label>
        <select
          id="encryption_mode"
          onChange={(e) => handleChange("encryptionMode", e.target.value)}
        >
          <option value="1">Да</option>
          <option value="0">Нет</option>
        </select>
        <br /><br />

        <button type="submit">Сохранить изменения</button>
      </form>

      <h2>Активные сессии</h2>
      <table>
        <thead>
          <tr>
            <th>IP-адрес</th>
            <th>Действие</th>
          </tr>
        </thead>
        <tbody>
          {activeSessions.map((session) => (
            <tr key={session.ip}>
              <td>{session.ip}</td>
              <td>
                <button onClick={() => handleDisconnect(session.ip)}>Отключить</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Cripto({ onBack }) {
  const [file, setFile] = useState(null);
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState({ message: '', isError: false });
  const fileInputRef = useRef(null);

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handlePasswordChange = (e) => {
    setPassword(e.target.value);
  };

  const deriveKey = async (password, salt) => {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    const importedKey = await window.crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      importedKey,
      { name: 'AES-CBC', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  };

  const encryptFile = async () => {
    if (!file || !password) {
      setStatus({ message: 'Пожалуйста, выберите файл и введите пароль', isError: true });
      return;
    }

    try {
      setStatus({ message: 'Шифрование...', isError: false });

      // Generate a random salt and IV
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      const iv = window.crypto.getRandomValues(new Uint8Array(16));

      // Derive key from password
      const key = await deriveKey(password, salt);

      // Read file as ArrayBuffer
      const fileData = await file.arrayBuffer();

      // Encrypt the file
      const encryptedData = await window.crypto.subtle.encrypt(
        {
          name: 'AES-CBC',
          iv: iv
        },
        key,
        fileData
      );

      // Combine salt + iv + encrypted data
      const result = new Uint8Array(salt.length + iv.length + encryptedData.byteLength);
      result.set(salt, 0);
      result.set(iv, salt.length);
      result.set(new Uint8Array(encryptedData), salt.length + iv.length);

      // Create download link
      const blob = new Blob([result], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = file.name.replace(/(\.[\w\d_-]+)$/i, 's$1');
      link.click();
      URL.revokeObjectURL(url);

      setStatus({ message: `Файл успешно зашифрован: ${link.download}`, isError: false });
    } catch (error) {
      console.error('Encryption error:', error);
      setStatus({ message: 'Ошибка при шифровании', isError: true });
    }
  };

  const decryptFile = async () => {
    if (!file || !password) {
      setStatus({ message: 'Пожалуйста, выберите файл и введите пароль', isError: true });
      return;
    }

    try {
      setStatus({ message: 'Расшифровка...', isError: false });

      // Read file as ArrayBuffer
      const fileData = await file.arrayBuffer();
      const dataView = new Uint8Array(fileData);

      // Extract salt, iv and encrypted data
      const salt = dataView.slice(0, 16);
      const iv = dataView.slice(16, 32);
      const encryptedData = dataView.slice(32);

      // Derive key from password
      const key = await deriveKey(password, salt);

      // Decrypt the file
      const decryptedData = await window.crypto.subtle.decrypt(
        {
          name: 'AES-CBC',
          iv: iv
        },
        key,
        encryptedData
      );

      // Create download link
      const blob = new Blob([decryptedData], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = file.name.replace(/s(\.[\w\d_-]+)$/i, '$1');
      link.click();
      URL.revokeObjectURL(url);

      setStatus({ message: `Файл успешно дешифрован: ${link.download}`, isError: false });
    } catch (error) {
      console.error('Decryption error:', error);
      setStatus({ message: 'Ошибка при дешифровка. Проверьте пароль.', isError: true });
    }
  };

  const triggerFileInput = () => {
    fileInputRef.current.click();
  };

  return (
    <div className="App">
      <div className="container">
        <h1>Дешифровать или зашифровать</h1>

        <div className="input-container">
          <label htmlFor="file">Выбрать Файл:</label>
          <input 
            type="file" 
            id="file" 
            ref={fileInputRef}
            onChange={handleFileChange}
            style={{ display: 'none' }}
          />
          <label htmlFor="file" className="custom-file-upload" onClick={triggerFileInput}>
            Выбрать Файл
          </label>
          {file && <p style={{ marginTop: '10px' }}>Выбранный файл: {file.name}</p>}
        </div>

        <div className="input-container">
          <label htmlFor="password">Ввести пароль:</label>
          <input 
            type="password" 
            id="password" 
            value={password}
            onChange={handlePasswordChange}
          />
        </div>

        <div className="button-container">
          <button id="encryptButton" onClick={encryptFile}>Зашифровать</button>
          <button id="decryptButton" onClick={decryptFile}>Дешифровать</button>
          <button onClick={onBack} className="button log out">Вернуться</button>
        </div>
        
        <a className="button log out" href="/">Вернуться</a>
        
        <p id="status" className={status.isError ? 'error' : ''}>
          {status.message}
        </p>
      </div>
    </div>
  );
}

export default function App() {
  const [status, setStatus] = useState('');
  const [role, setRole] = useState(''); 

  return status !== "success" ? (
    <Login setStatus={setStatus} setRole={setRole} />
  ) : role === 'admin' ? (
    <AdminPage />
  ) : (
    <FilePage />
  );
}
