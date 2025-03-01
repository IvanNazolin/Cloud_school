import React, { useState, useEffect } from 'react';
import './App.css';

const baseApiUrl = "http://192.168.1.10:100";

// Login Component
function Login({ setStatus }) {
  const [login, setLogin] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();

    try {
      const response = await fetch(`${baseApiUrl}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ login, password }),
      });

      const data = await response.json();
      if (response.ok) {
        setMessage(data.message);
        setStatus('success');
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
            {showPassword ? "🙈" : "👁️"}
          </span>
        </div>
        <input type="submit" value="Войти" className="btn" />
      </form>
      {message && <div className="message">{message}</div>}
    </div>
  );
}

// FilePage Component
function FilePage() {
  const [files, setFiles] = useState([]);
  const [currentFolder, setCurrentFolder] = useState("Главная");
  const [subpath, setSubpath] = useState("");
  const [newFolderName, setNewFolderName] = useState("");
  const [selectedFiles, setSelectedFiles] = useState([]);

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

// App Component
export default function App() {
  const [status, setStatus] = useState('');

  return status !== "success" ? <Login setStatus={setStatus} /> : <FilePage />;
}
