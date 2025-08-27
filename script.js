// Simulated JSON storage (replace with server-side storage in production)
const storage = {
    users: JSON.parse(localStorage.getItem('users')) || {},
    messages: JSON.parse(localStorage.getItem('messages')) || [],
};

// DOM elements
const authSection = document.getElementById('auth-section');
const messagingSection = document.getElementById('messaging-section');
const authForm = document.getElementById('auth-form');
const authBtn = document.getElementById('auth-btn');
const toggleAuthBtn = document.getElementById('toggle-auth');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const authTitle = document.getElementById('auth-title');
const messageForm = document.getElementById('message-form');
const recipientInput = document.getElementById('recipient');
const messageInput = document.getElementById('message');
const messageList = document.getElementById('message-list');
const currentUserSpan = document.getElementById('current-user');
const logoutBtn = document.getElementById('logout-btn');

let isLogin = true;
let currentUser = null;

// Helper: Convert string to ArrayBuffer
function stringToArrayBuffer(str) {
    return new TextEncoder().encode(str);
}

// Helper: Convert ArrayBuffer to string
function arrayBufferToString(buffer) {
    return new TextDecoder().decode(buffer);
}

// Helper: Convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

// Helper: Convert Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// Hash password with SHA-256
async function hashPassword(password) {
    const buffer = stringToArrayBuffer(password);
    const hash = await crypto.subtle.digest('SHA-256', buffer);
    return arrayBufferToBase64(hash);
}

// Generate AES key from password
async function deriveKey(password) {
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        stringToArrayBuffer(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: stringToArrayBuffer('salt'),
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

// Encrypt message
async function encryptMessage(message, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        stringToArrayBuffer(message)
    );
    return {
        iv: arrayBufferToBase64(iv),
        data: arrayBufferToBase64(encrypted),
    };
}

// Decrypt message
async function decryptMessage(encrypted, key) {
    try {
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: base64ToArrayBuffer(encrypted.iv) },
            key,
            base64ToArrayBuffer(encrypted.data)
        );
        return arrayBufferToString(decrypted);
    } catch (e) {
        return '[Decryption Failed]';
    }
}

// Save data to localStorage (replace with server API call)
function saveData() {
    localStorage.setItem('users', JSON.stringify(storage.users));
    localStorage.setItem('messages', JSON.stringify(storage.messages));
}

// Load messages for current user
async function loadMessages() {
    messageList.innerHTML = '';
    const key = await deriveKey(currentUser);
    for (const msg of storage.messages) {
        if (msg.recipient === currentUser || msg.sender === currentUser) {
            const decrypted = await decryptMessage(msg.content, key);
            const div = document.createElement('div');
            div.className = 'message';
            div.textContent = `${msg.sender} to ${msg.recipient}: ${decrypted} (${msg.timestamp})`;
            messageList.appendChild(div);
        }
    }
}

// Toggle between login and register
toggleAuthBtn.addEventListener('click', () => {
    isLogin = !isLogin;
    authTitle.textContent = isLogin ? 'Login' : 'Register';
    authBtn.textContent = isLogin ? 'Login' : 'Register';
    toggleAuthBtn.textContent = isLogin ? 'Switch to Register' : 'Switch to Login';
});

// Handle login/register
authForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const hashedPassword = await hashPassword(password);

    if (isLogin) {
        // Login
        if (storage.users[username] && storage.users[username].password === hashedPassword) {
            currentUser = username;
            authSection.classList.add('hidden');
            messagingSection.classList.remove('hidden');
            currentUserSpan.textContent = currentUser;
            await loadMessages();
        } else {
            alert('Invalid username or password');
        }
    } else {
        // Register
        if (storage.users[username]) {
            alert('Username already exists');
        } else {
            storage.users[username] = { password: hashedPassword };
            saveData();
            alert('Registered successfully! Please login.');
            isLogin = true;
            authTitle.textContent = 'Login';
            authBtn.textContent = 'Login';
            toggleAuthBtn.textContent = 'Switch to Register';
        }
    }
});

// Handle message sending
messageForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const recipient = recipientInput.value.trim();
    const message = messageInput.value.trim();

    if (!storage.users[recipient]) {
        alert('Recipient does not exist');
        return;
    }

    const key = await deriveKey(currentUser);
    const encrypted = await encryptMessage(message, key);
    storage.messages.push({
        sender: currentUser,
        recipient,
        content: encrypted,
        timestamp: new Date().toISOString(),
    });
    saveData();
    recipientInput.value = '';
    messageInput.value = '';
    await loadMessages();
});

// Handle logout
logoutBtn.addEventListener('click', () => {
    currentUser = null;
    authSection.classList.remove('hidden');
    messagingSection.classList.add('hidden');
    usernameInput.value = '';
    passwordInput.value = '';
});