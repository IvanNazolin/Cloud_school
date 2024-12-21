async function encryptFile(file, password) {
    const algorithm = 'AES-CBC';
    const iv = new Uint8Array(16);  // Fixed IV with all zeros (or any fixed value)

    // Create a key from the password using PBKDF2
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    const key = await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: new Uint8Array(0),  // No salt used
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-CBC', length: 256 },
        false,
        ['encrypt']
    );

    const fileData = await file.arrayBuffer();

    // Encrypt the file data
    const encryptedData = await window.crypto.subtle.encrypt(
        { name: algorithm, iv: iv },
        key,
        fileData
    );

    const encryptedArray = new Uint8Array(encryptedData);

    // Return the result (IV + encrypted data)
    const result = new Uint8Array(iv.length + encryptedArray.length);
    result.set(iv);
    result.set(encryptedArray, iv.length);

    return result;
}

async function decryptFile(encryptedData, password) {
    const algorithm = 'AES-CBC';
    const iv = encryptedData.slice(0, 16);  // The first 16 bytes are the IV
    const encryptedContent = encryptedData.slice(16);  // The rest is the encrypted content

    // Create a key from the password using PBKDF2
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    const key = await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: new Uint8Array(0),  // No salt used
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-CBC', length: 256 },
        false,
        ['decrypt']
    );

    // Decrypt the data
    try {
        const decryptedData = await window.crypto.subtle.decrypt(
            { name: algorithm, iv: iv },
            key,
            encryptedContent
        );

        return new Uint8Array(decryptedData);
    } catch (e) {
        throw new Error('Decryption failed: ' + e.message);
    }
}

function downloadFile(data, originalFileName, extension) {
    const blob = new Blob([data], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = originalFileName.replace(/(\.[\w\d_-]+)$/i, extension + '$1');
    a.click();

    // Clean up
    URL.revokeObjectURL(url);
}

document.getElementById('encryptButton').addEventListener('click', async () => {
    const fileInput = document.getElementById('file');
    const password = document.getElementById('password').value;
    
    if (!fileInput.files[0] || !password) {
        alert('Please select a file and enter a password');
        return;
    }

    const file = fileInput.files[0];
    try {
        const encryptedData = await encryptFile(file, password);
        downloadFile(encryptedData, file.name, 's');
        document.getElementById('status').textContent = 'File encrypted successfully!';
    } catch (e) {
        document.getElementById('status').textContent = 'Encryption failed: ' + e.message;
    }
});

document.getElementById('decryptButton').addEventListener('click', async () => {
    const fileInput = document.getElementById('file');
    const password = document.getElementById('password').value;
    
    if (!fileInput.files[0] || !password) {
        alert('Please select a file and enter a password');
        return;
    }

    const file = fileInput.files[0];
    try {
        const fileData = await file.arrayBuffer();
        const decryptedData = await decryptFile(new Uint8Array(fileData), password);
        downloadFile(decryptedData, file.name, 'd');
        document.getElementById('status').textContent = 'File decrypted successfully!';
    } catch (e) {
        document.getElementById('status').textContent = 'Decryption failed: ' + e.message;
    }
});

console.log("jdfjkhfdg")