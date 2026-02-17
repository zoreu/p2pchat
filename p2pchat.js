// ============================================
// SERVICE WORKER & PWA
// ============================================
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
  if ('Notification' in window) Notification.requestPermission();
}

// ============================================
// CRYPTO: Web Crypto API (ECDH) + CryptoJS (AES-256)
// ============================================
const KeyManager = {
  async generateKeyPair() {
    return crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
  },

  async exportPublicKey(publicKey) {
    const raw = await crypto.subtle.exportKey('raw', publicKey);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  },

  async importPublicKey(base64Key) {
    const binary = atob(base64Key);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return crypto.subtle.importKey(
      'raw', bytes,
      { name: 'ECDH', namedCurve: 'P-256' },
      true, []
    );
  },

  async exportPrivateKey(privateKey) {
    return crypto.subtle.exportKey('jwk', privateKey);
  },

  async importPrivateKey(jwk) {
    return crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true, ['deriveKey', 'deriveBits']
    );
  },

  async deriveSharedKey(myPrivateKey, theirPublicKeyBase64) {
    const theirPublicKey = await this.importPublicKey(theirPublicKeyBase64);
    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: theirPublicKey },
      myPrivateKey, 256
    );
    const bytes = new Uint8Array(sharedBits);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  deriveKeyFromPassword(password, salt) {
    return CryptoJS.PBKDF2(password, salt, {
      keySize: 256 / 32,
      iterations: 100000,
      hasher: CryptoJS.algo.SHA256
    }).toString(CryptoJS.enc.Hex);
  },

  fingerprint(publicKeyBase64) {
    const hash = CryptoJS.SHA256(publicKeyBase64).toString();
    return hash.substring(0, 32).match(/.{2}/g).join(':').toUpperCase();
  },

  generatePeerId() {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return 'p2p_' + Array.from(arr).map(b => b.toString(36)).join('').substring(0, 20);
  },

  encodeShareKey(displayName, peerId, publicKeyBase64) {
    return `${displayName}|${peerId}|${publicKeyBase64}`;
  },

  decodeShareKey(shareString) {
    const firstPipe = shareString.indexOf('|');
    if (firstPipe === -1) return null;
    const secondPipe = shareString.indexOf('|', firstPipe + 1);
    if (secondPipe === -1) return null;
    const displayName = shareString.substring(0, firstPipe).trim();
    const peerId = shareString.substring(firstPipe + 1, secondPipe).trim();
    const publicKey = shareString.substring(secondPipe + 1).trim();
    if (!displayName || !peerId || !publicKey) return null;
    return { displayName, peerId, publicKey };
  }
};

const CryptoService = {
  async encryptMessage(message, myPrivateKey, theirPublicKeyBase64) {
    try {
      const sharedKeyHex = await KeyManager.deriveSharedKey(myPrivateKey, theirPublicKeyBase64);
      const keyWA = CryptoJS.enc.Hex.parse(sharedKeyHex);
      const iv = CryptoJS.lib.WordArray.random(16);
      const encrypted = CryptoJS.AES.encrypt(message, keyWA, {
        iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7
      });
      return iv.toString(CryptoJS.enc.Hex) + ':' + encrypted.ciphertext.toString(CryptoJS.enc.Hex);
    } catch (e) {
      console.error('Encrypt error:', e);
      return null;
    }
  },

  async decryptMessage(encryptedData, myPrivateKey, theirPublicKeyBase64) {
    try {
      const parts = encryptedData.split(':');
      if (parts.length !== 2) return null;
      const sharedKeyHex = await KeyManager.deriveSharedKey(myPrivateKey, theirPublicKeyBase64);
      const keyWA = CryptoJS.enc.Hex.parse(sharedKeyHex);
      const iv = CryptoJS.enc.Hex.parse(parts[0]);
      const ciphertext = CryptoJS.enc.Hex.parse(parts[1]);
      const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext });
      const decrypted = CryptoJS.AES.decrypt(cipherParams, keyWA, {
        iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7
      });
      const result = decrypted.toString(CryptoJS.enc.Utf8);
      return result || null;
    } catch (e) {
      console.error('Decrypt error:', e);
      return null;
    }
  },

  encryptLocal(data) {
    try {
      if (!localEncKey) return null;
      const keyWA = CryptoJS.enc.Hex.parse(localEncKey);
      const iv = CryptoJS.lib.WordArray.random(16);
      const text = typeof data === 'string' ? data : JSON.stringify(data);
      const encrypted = CryptoJS.AES.encrypt(text, keyWA, {
        iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7
      });
      return iv.toString(CryptoJS.enc.Hex) + ':' + encrypted.ciphertext.toString(CryptoJS.enc.Hex);
    } catch (e) {
      console.error('Local encrypt error:', e);
      return null;
    }
  },

  decryptLocal(encryptedData) {
    try {
      if (!localEncKey || !encryptedData) return null;
      const parts = encryptedData.split(':');
      if (parts.length !== 2) return null;
      const keyWA = CryptoJS.enc.Hex.parse(localEncKey);
      const iv = CryptoJS.enc.Hex.parse(parts[0]);
      const ciphertext = CryptoJS.enc.Hex.parse(parts[1]);
      const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext });
      const decrypted = CryptoJS.AES.decrypt(cipherParams, keyWA, {
        iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7
      });
      return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (e) {
      console.error('Local decrypt error:', e);
      return null;
    }
  }
};

// ============================================
// INDEXEDDB
// ============================================
let db;
const DB_VERSION = 7;

function initDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('p2pchat_secure_db', DB_VERSION);
    request.onupgradeneeded = (e) => {
      const database = e.target.result;
      const names = ['accounts', 'friends', 'knownPeers', 'chats', 'conversations'];
      names.forEach(name => { if (database.objectStoreNames.contains(name)) database.deleteObjectStore(name); });
      database.createObjectStore('accounts', { keyPath: 'username' });
      database.createObjectStore('friends', { keyPath: 'peerId' });
      database.createObjectStore('knownPeers', { keyPath: 'peerId' });
      const cs = database.createObjectStore('chats', { keyPath: 'msgId' });
      cs.createIndex('friendPeerId', 'friendPeerId', { unique: false });
      cs.createIndex('timestamp', 'timestamp', { unique: false });
      const cvs = database.createObjectStore('conversations', { keyPath: 'friendPeerId' });
      cvs.createIndex('lastMessageTime', 'lastMessageTime', { unique: false });
    };
    request.onsuccess = (e) => { db = e.target.result; resolve(db); };
    request.onerror = (e) => reject(e.target.error);
  });
}

const Storage = {
  async put(store, data) { return new Promise((resolve, reject) => { const tx = db.transaction(store, 'readwrite'); tx.objectStore(store).put(data); tx.oncomplete = () => resolve(); tx.onerror = (e) => reject(e.target.error); }); },
  async delete(store, key) { return new Promise((resolve, reject) => { const tx = db.transaction(store, 'readwrite'); tx.objectStore(store).delete(key); tx.oncomplete = () => resolve(); tx.onerror = (e) => reject(e.target.error); }); },
  async get(store, key) { return new Promise((resolve, reject) => { const tx = db.transaction(store, 'readonly'); const req = tx.objectStore(store).get(key); req.onsuccess = () => resolve(req.result); req.onerror = (e) => reject(e.target.error); }); },
  async getAll(store) { return new Promise((resolve, reject) => { const tx = db.transaction(store, 'readonly'); const req = tx.objectStore(store).getAll(); req.onsuccess = () => resolve(req.result); req.onerror = (e) => reject(e.target.error); }); },
  async getAllFromIndex(store, index, value) { return new Promise((resolve, reject) => { const tx = db.transaction(store, 'readonly'); const req = tx.objectStore(store).index(index).getAll(value); req.onsuccess = () => resolve(req.result); req.onerror = (e) => reject(e.target.error); }); },
  generateMsgId() { return Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 10); },

  async saveMessage(friendPeerId, message, direction, msgId, fileData) {
    try {
      const id = msgId || this.generateMsgId();
      const encMsg = CryptoService.encryptLocal(message);
      if (!encMsg) return null;
      let encFile = null;
      if (fileData) encFile = CryptoService.encryptLocal(JSON.stringify(fileData));
      const msgData = { msgId: id, friendPeerId, message: encMsg, fileData: encFile, timestamp: Date.now(), direction, deleted: false, read: direction !== 'incoming' };
      await this.put('chats', msgData);
      const conv = (await this.get('conversations', friendPeerId)) || { friendPeerId, lastMessage: '', lastMessageTime: Date.now(), unread: 0 };
      conv.lastMessage = fileData ? `📎 ${fileData.name || 'Arquivo'}` : message;
      conv.lastMessageTime = Date.now();
      if (direction === 'incoming') { conv.unread = (conv.unread || 0) + 1; showNotification(friendPeerId, conv.lastMessage); }
      await this.put('conversations', conv);
      return { ...msgData, msgId: id };
    } catch (e) { console.error('Save message error:', e); return null; }
  },

  async getMessages(friendPeerId) {
    const msgs = await this.getAllFromIndex('chats', 'friendPeerId', friendPeerId);
    return msgs.filter(m => !m.deleted).map(msg => {
      const decMsg = CryptoService.decryptLocal(msg.message);
      let decFile = null;
      if (msg.fileData) { try { const fs = CryptoService.decryptLocal(msg.fileData); if (fs) decFile = JSON.parse(fs); } catch (e) {} } 
      return { ...msg, message: decMsg || '[Erro]', fileData: decFile };
    }).sort((a, b) => a.timestamp - b.timestamp);
  },

  async deleteMessage(msgId) { const msg = await this.get('chats', msgId); if (msg) { msg.deleted = true; msg.message = CryptoService.encryptLocal('🚫 Mensagem apagada'); msg.fileData = null; await this.put('chats', msg); } },
  async getConversations() { const convs = await this.getAll('conversations'); const valid = []; for (const conv of convs) { const msgs = await this.getAllFromIndex('chats', 'friendPeerId', conv.friendPeerId); if (msgs.some(m => !m.deleted)) valid.push(conv); } return valid; },
  async markAsRead(friendPeerId) { const conv = await this.get('conversations', friendPeerId); if (conv) { conv.unread = 0; await this.put('conversations', conv); } },
  async clearConversation(friendPeerId) { const msgs = await this.getAllFromIndex('chats', 'friendPeerId', friendPeerId); const tx = db.transaction('chats', 'readwrite'); const store = tx.objectStore('chats'); msgs.forEach(m => store.delete(m.msgId)); await new Promise(r => { tx.oncomplete = r; }); await this.delete('conversations', friendPeerId); },
  async cleanOldMessages() {
    const weekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
    const tx = db.transaction('chats', 'readwrite'); const store = tx.objectStore('chats'); const index = store.index('timestamp'); const range = IDBKeyRange.upperBound(weekAgo);
    const deletedFriends = new Set();
    index.openCursor(range).onsuccess = (e) => {
      const cursor = e.target.result; if (cursor) { deletedFriends.add(cursor.value.friendPeerId); store.delete(cursor.primaryKey); cursor.continue(); }
    };
    tx.oncomplete = async () => {
      for (const fid of deletedFriends) {
        const rem = await this.getAllFromIndex('chats', 'friendPeerId', fid);
        if (rem.length === 0) await this.delete('conversations', fid);
      }
    };
  }
};

// ============================================
// SESSION PERSISTENCE
// ============================================
const Session = {
  save(username, encKey) {
    const sessionData = JSON.stringify({ username, encKey, timestamp: Date.now() });
    const sessionKey = CryptoJS.SHA256('session_guard_' + username).toString();
    const keyWA = CryptoJS.enc.Hex.parse(sessionKey);
    const iv = CryptoJS.lib.WordArray.random(16);
    const encrypted = CryptoJS.AES.encrypt(sessionData, keyWA, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    const stored = iv.toString(CryptoJS.enc.Hex) + ':' + encrypted.ciphertext.toString(CryptoJS.enc.Hex);
    localStorage.setItem('p2pchat_session', stored);
    localStorage.setItem('p2pchat_session_user', username);
  },
  load() {
    try {
      const stored = localStorage.getItem('p2pchat_session'); const username = localStorage.getItem('p2pchat_session_user');
      if (!stored || !username) return null;
      const sessionKey = CryptoJS.SHA256('session_guard_' + username).toString();
      const keyWA = CryptoJS.enc.Hex.parse(sessionKey); const parts = stored.split(':'); if (parts.length !== 2) return null;
      const iv = CryptoJS.enc.Hex.parse(parts[0]); const ciphertext = CryptoJS.enc.Hex.parse(parts[1]);
      const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext });
      const decrypted = CryptoJS.AES.decrypt(cipherParams, keyWA, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
      const jsonStr = decrypted.toString(CryptoJS.enc.Utf8); if (!jsonStr) return null;
      return JSON.parse(jsonStr);
    } catch (e) { console.error('Session load error:', e); return null; }
  },
  clear() { localStorage.removeItem('p2pchat_session'); localStorage.removeItem('p2pchat_session_user'); }
};

// ============================================
// NOTIFICATIONS
// ============================================
function showNotification(friendPeerId, message) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  if (document.hasFocus() && currentChat === friendPeerId) return;
  const name = getPeerDisplayName(friendPeerId);
  if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
    navigator.serviceWorker.ready.then(reg => { reg.showNotification(`💬 ${name}`, { body: message, icon: 'icon.png', badge: 'icon.png', vibrate: [200, 100, 200], data: { friendPeerId } }); });
  }
}

// ============================================
// GLOBALS
// ============================================
let identity = null;
let privateKey = null;
let publicKeyBase64 = '';
let localEncKey = null;
let peer = null;
let connections = new Map();
let knownPeers = new Map();
let currentChat = null;
let friendsCache = [];
let pendingConfirmAction = null;
let pendingDeleteMsgId = null;
let pendingDeleteFriendId = null;
let selectedFile = null;
let fileTransfers = new Map();
let reconnectTimers = new Map();

const MAX_FILE_SIZE = 50 * 1024 * 1024;
const CHUNK_SIZE = 64 * 1024;
const RECONNECT_INTERVAL = 10000;

// ============================================
// PEER INFO HELPERS
// ============================================
function getPeerPublicKey(peerId) {
  const friend = getFriendByPeerId(peerId);
  if (friend && friend.publicKey) return friend.publicKey;
  const known = knownPeers.get(peerId);
  if (known && known.publicKey) return known.publicKey;
  return null;
}

function getPeerDisplayName(peerId) {
  const friend = getFriendByPeerId(peerId);
  if (friend && friend.displayName) return friend.displayName;
  const known = knownPeers.get(peerId);
  if (known && known.displayName) return known.displayName;
  return peerId.substring(0, 12) + '...';
}

function getFriendByPeerId(peerId) { return friendsCache.find(f => f.peerId === peerId); }
function getFriendByPublicKey(pubKey) { return friendsCache.find(f => f.publicKey === pubKey); }

// ============================================
// LOGIN / REGISTER
// ============================================
function switchLoginTab(tab) {
  document.querySelectorAll('.login-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('loginError').textContent = '';
  if (tab === 'login') { document.querySelectorAll('.login-tab')[0].classList.add('active'); document.getElementById('loginForm').classList.remove('hidden'); document.getElementById('registerForm').classList.add('hidden'); }
  else { document.querySelectorAll('.login-tab')[1].classList.add('active'); document.getElementById('loginForm').classList.add('hidden'); document.getElementById('registerForm').classList.remove('hidden'); }
}

function checkPasswordStrength(pw) {
  const bar = document.getElementById('passwordStrengthBar'); let s = 0;
  if (pw.length >= 8) s += 25; if (pw.length >= 12) s += 15;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s += 20; if (/\d/.test(pw)) s += 20; if (/[^a-zA-Z0-9]/.test(pw)) s += 20;
  bar.style.width = s + '%'; bar.style.background = s < 40 ? '#ea4335' : s < 70 ? '#fbbc04' : '#34a853';
}

async function doRegister() {
  const username = document.getElementById('regUsername').value.trim().toLowerCase();
  const displayName = document.getElementById('regDisplayName').value.trim();
  const password = document.getElementById('regPassword').value;
  const confirm = document.getElementById('regPasswordConfirm').value;
  const errEl = document.getElementById('loginError'); errEl.textContent = '';
  if (!username || username.length < 3) { errEl.textContent = 'Usuário: mín 3 caracteres'; return; }
  if (/[^a-z0-9_]/.test(username)) { errEl.textContent = 'Usuário: só letras minúsculas, números e _'; return; }
  if (!displayName) { errEl.textContent = 'Digite um nome de exibição'; return; }
  if (password.length < 8) { errEl.textContent = 'Senha: mín 8 caracteres'; return; }
  if (password !== confirm) { errEl.textContent = 'Senhas não coincidem'; return; }
  const existing = await Storage.get('accounts', username);
  if (existing) { errEl.textContent = 'Usuário já existe neste dispositivo'; return; }
  try {
    const keyPair = await KeyManager.generateKeyPair();
    const pubKeyBase64 = await KeyManager.exportPublicKey(keyPair.publicKey);
    const privKeyJwk = await KeyManager.exportPrivateKey(keyPair.privateKey);
    const peerId = KeyManager.generatePeerId();
    const salt = CryptoJS.lib.WordArray.random(32).toString();
    const encKey = KeyManager.deriveKeyFromPassword(password, salt);
    const privKeyStr = JSON.stringify(privKeyJwk);
    const keyWA = CryptoJS.enc.Hex.parse(encKey); const iv = CryptoJS.lib.WordArray.random(16);
    const encPrivKey = CryptoJS.AES.encrypt(privKeyStr, keyWA, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    const encPrivKeyStr = iv.toString(CryptoJS.enc.Hex) + ':' + encPrivKey.ciphertext.toString(CryptoJS.enc.Hex);
    const passwordHash = CryptoJS.SHA256(password + salt).toString();
    await Storage.put('accounts', { username, displayName, peerId, publicKey: pubKeyBase64, encryptedPrivateKey: encPrivKeyStr, passwordHash, salt, createdAt: Date.now() });
    identity = { username, displayName, peerId, publicKey: pubKeyBase64 };
    privateKey = keyPair.privateKey; publicKeyBase64 = pubKeyBase64; localEncKey = encKey;
    Session.save(username, encKey);
    showToast('✅ Conta criada!'); showPublicKeyModal(true);
  } catch (e) { console.error('Register error:', e); errEl.textContent = 'Erro: ' + e.message; }
}

async function doLogin() {
  const username = document.getElementById('loginUsername').value.trim().toLowerCase();
  const password = document.getElementById('loginPassword').value;
  const errEl = document.getElementById('loginError'); errEl.textContent = '';
  if (!username || !password) { errEl.textContent = 'Preencha usuário e senha'; return; }
  await restoreSession(username, password, errEl);
}

async function restoreSession(username, password, errEl) {
  const account = await Storage.get('accounts', username);
  if (!account) { if (errEl) errEl.textContent = 'Conta não encontrada neste dispositivo'; return false; }
  const passwordHash = CryptoJS.SHA256(password + account.salt).toString();
  if (passwordHash !== account.passwordHash) { if (errEl) errEl.textContent = 'Senha incorreta'; return false; }
  try {
    const encKey = KeyManager.deriveKeyFromPassword(password, account.salt);
    const parts = account.encryptedPrivateKey.split(':');
    const iv = CryptoJS.enc.Hex.parse(parts[0]); const ciphertext = CryptoJS.enc.Hex.parse(parts[1]);
    const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext }); const keyWA = CryptoJS.enc.Hex.parse(encKey);
    const decrypted = CryptoJS.AES.decrypt(cipherParams, keyWA, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    const privKeyJwkStr = decrypted.toString(CryptoJS.enc.Utf8);
    if (!privKeyJwkStr) { if (errEl) errEl.textContent = 'Erro ao descriptografar chave'; return false; }
    const privKeyJwk = JSON.parse(privKeyJwkStr); const privKeyObj = await KeyManager.importPrivateKey(privKeyJwk);
    identity = { username: account.username, displayName: account.displayName, peerId: account.peerId, publicKey: account.publicKey };
    privateKey = privKeyObj; publicKeyBase64 = account.publicKey; localEncKey = encKey;
    Session.save(username, encKey);
    startApp(); return true;
  } catch (e) { console.error('Login error:', e); if (errEl) errEl.textContent = 'Erro ao fazer login'; return false; }
}

async function autoLogin() {
  const session = Session.load();
  if (!session || !session.username || !session.encKey) return false;
  const account = await Storage.get('accounts', session.username);
  if (!account) { Session.clear(); return false; }
  try {
    const parts = account.encryptedPrivateKey.split(':');
    const iv = CryptoJS.enc.Hex.parse(parts[0]); const ciphertext = CryptoJS.enc.Hex.parse(parts[1]);
    const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext }); const keyWA = CryptoJS.enc.Hex.parse(session.encKey);
    const decrypted = CryptoJS.AES.decrypt(cipherParams, keyWA, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    const privKeyJwkStr = decrypted.toString(CryptoJS.enc.Utf8);
    if (!privKeyJwkStr) { Session.clear(); return false; }
    const privKeyJwk = JSON.parse(privKeyJwkStr); const privKeyObj = await KeyManager.importPrivateKey(privKeyJwk);
    identity = { username: account.username, displayName: account.displayName, peerId: account.peerId, publicKey: account.publicKey };
    privateKey = privKeyObj; publicKeyBase64 = account.publicKey; localEncKey = session.encKey;
    console.log('✅ Auto-login:', identity.username); startApp(); return true;
  } catch (e) { console.error('Auto-login error:', e); Session.clear(); return false; }
}

function doLogout() {
  closeSettingsModal();
  showConfirm('🚪 Sair', 'Deseja sair da sua conta?', () => {
    Session.clear();
    if (peer) { try { peer.destroy(); } catch(e){} peer = null; }
    connections.forEach(c => { try { c.close(); } catch(e){} }); connections.clear(); knownPeers.clear();
    reconnectTimers.forEach(t => clearInterval(t)); reconnectTimers.clear();
    identity = null; privateKey = null; publicKeyBase64 = ''; localEncKey = null; currentChat = null; friendsCache = [];
    document.getElementById('appScreen').classList.add('hidden'); document.getElementById('chatContainer').classList.add('hidden');
    document.querySelector('.tabs').classList.remove('hidden'); document.querySelector('.tab-content').classList.remove('hidden');
    document.getElementById('loginScreen').classList.remove('hidden');
    document.getElementById('loginUsername').value = ''; document.getElementById('loginPassword').value = '';
    document.getElementById('loginError').textContent = ''; switchLoginTab('login');
  });
}

// ============================================
// PUBLIC KEY MODAL
// ============================================
function showPublicKeyModal(isFirstTime) {
  document.getElementById('keyModalTitle').textContent = '🔑 Sua Chave Pública';
  document.getElementById('keyModalDesc').textContent = isFirstTime ? 'Conta criada! Compartilhe esta chave com amigos:' : 'Compartilhe esta chave para amigos te adicionarem:';
  const shareKey = KeyManager.encodeShareKey(identity.displayName, identity.peerId, publicKeyBase64);
  document.getElementById('keyModalDisplay').textContent = shareKey;
  document.getElementById('keyModal').classList.remove('hidden');
}

function closeKeyModal() { document.getElementById('keyModal').classList.add('hidden'); if (document.getElementById('appScreen').classList.contains('hidden')) startApp(); }
async function copyKeyToClipboard() { const key = document.getElementById('keyModalDisplay').textContent; try { await navigator.clipboard.writeText(key); showToast('✅ Chave copiada!'); } catch { const ta = document.createElement('textarea'); ta.value = key; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); showToast('✅ Chave copiada!'); } }
function showMyPublicKey() { showPublicKeyModal(false); }

// ============================================
// INIT & START
// ============================================
async function init() {
  await initDB();
  try { const peers = await Storage.getAll('knownPeers'); peers.forEach(p => knownPeers.set(p.peerId, p)); } catch(e) {} 
  const loggedIn = await autoLogin();
  if (!loggedIn) document.getElementById('loginScreen').classList.remove('hidden');
}

async function startApp() {
  document.getElementById('loginScreen').classList.add('hidden');
  document.getElementById('appScreen').classList.remove('hidden');
  friendsCache = await Storage.getAll('friends');
  initPeer(); loadFriends(); loadConversations();
  Storage.cleanOldMessages(); setInterval(() => Storage.cleanOldMessages(), 3600000);
}

// ============================================
// PEERJS
// ============================================
// ============================================
// PEERJS
// ============================================
function initPeer() {
  if (!identity) return;
  if (peer) { try { peer.destroy(); } catch(e){} }
  peer = new Peer(identity.peerId, {
    host: '0.peerjs.com',
    port: 443,
    secure: true,
    config: {
      iceServers: [

        // ========================
        // GOOGLE STUN
        // ========================
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun3.l.google.com:19302' },
        { urls: 'stun:stun4.l.google.com:19302' },

        // ========================
        // PEERJS TURN (FALLBACK PRINCIPAL)
        // ========================
        {
          urls: [
            'turn:eu-0.turn.peerjs.com:3478',
            'turn:us-0.turn.peerjs.com:3478'
          ],
          username: 'peerjs',
          credential: 'peerjsp'
        }

      ],
      sdpSemantics: 'unified-plan'
    }
  });
  peer.on('open', (id) => { console.log('✅ Peer connected:', id); connectToAllFriends(); startReconnectLoop(); });
  peer.on('connection', conn => handleConnection(conn));
  peer.on('error', err => { console.error('Peer error:', err.type); });
  peer.on('disconnected', () => { setTimeout(() => { if (peer && !peer.disconnected && !peer.destroyed) { try { peer.reconnect(); } catch(e){} } }, 3000); });
}

function connectToFriend(friendPeerId) {
  if (!peer || peer.destroyed || !peer.open) return;
  if (friendPeerId === identity.peerId) return;
  const existing = connections.get(friendPeerId);
  if (existing && existing.open) return;
  try { const conn = peer.connect(friendPeerId, { reliable: true }); if (conn) handleConnection(conn); } catch (e) {} 
}

async function connectToAllFriends() {
  friendsCache = await Storage.getAll('friends');
  friendsCache.forEach(f => connectToFriend(f.peerId));
  const convs = await Storage.getConversations();
  convs.forEach(c => { if (!connections.has(c.friendPeerId) || !connections.get(c.friendPeerId).open) connectToFriend(c.friendPeerId); });
}

// Robust Reconnection Loop
function startReconnectLoop() {
  reconnectTimers.forEach(t => clearInterval(t)); reconnectTimers.clear();
  const timer = setInterval(async () => {
    if (!peer || peer.destroyed) { clearInterval(timer); return; }
    
    // Check channel peer health
    if (typeof activeChannel !== 'undefined' && activeChannel !== null) {
      const peers = channelPeers.get(activeChannel);
      if (peers) {
        peers.forEach((peerData, pid) => {
          if (!peerData.conn || !peerData.conn.open) {
            console.log(`Mesh check: reconnection triggered for ${pid} in channel ${activeChannel}`);
            if (typeof tryConnectChannelPeer === 'function') tryConnectChannelPeer(activeChannel, pid);
          }
        });
      }
    }

    await connectToAllFriends(); 
  }, RECONNECT_INTERVAL);
  reconnectTimers.set('main', timer);
}

// ============================================
// CONNECTION HANDLER
// ============================================
function handleConnection(conn) {
  const friendPeerId = conn.peer;
  conn.on('open', () => {
    console.log('🔗 Connected to:', friendPeerId);
    const old = connections.get(friendPeerId); if (old && old !== conn) { try { old.close(); } catch(e){} }
    connections.set(friendPeerId, conn);
    conn.send({ type: 'handshake', publicKey: publicKeyBase64, displayName: identity.displayName, peerId: identity.peerId });
    updateAllUI();
    if (currentChat === friendPeerId) { enableChat(true); updateChatStatus(true); }
  });
  conn.on('data', async (data) => {
    if (!data || !data.type) return;
    switch (data.type) {
      case 'handshake': await handleHandshake(data, friendPeerId); break;
      case 'message': await handleIncomingMessage(data, friendPeerId); break;
      case 'delete-message': await handleDeleteMessage(data, friendPeerId); break;
      case 'file-start': handleFileStart(data, friendPeerId); break;
      case 'file-chunk': handleFileChunk(data, friendPeerId); break;
      case 'file-end': await handleFileEnd(data, friendPeerId); break;
    }
  });
  conn.on('close', () => { if (connections.get(friendPeerId) === conn) connections.delete(friendPeerId); updateAllUI(); if (currentChat === friendPeerId) { enableChat(false); updateChatStatus(false); } });
  conn.on('error', (err) => { if (connections.get(friendPeerId) === conn) connections.delete(friendPeerId); });
}

async function handleHandshake(data, friendPeerId) {
  console.log('🤝 Handshake from:', data.displayName, friendPeerId);
  const peerInfo = { peerId: friendPeerId, publicKey: data.publicKey, displayName: data.displayName, lastSeen: Date.now() };
  knownPeers.set(friendPeerId, peerInfo);
  await Storage.put('knownPeers', peerInfo);
  let friend = await Storage.get('friends', friendPeerId);
  if (friend) { friend.publicKey = data.publicKey; friend.displayName = data.displayName; await Storage.put('friends', friend); friendsCache = await Storage.getAll('friends'); }
  else {
    const existingByKey = getFriendByPublicKey(data.publicKey);
    if (existingByKey && existingByKey.peerId !== friendPeerId) await migrateFriend(existingByKey.peerId, friendPeerId, data);
  }
  updateAllUI();
  if (currentChat === friendPeerId) { document.getElementById('chatFriendName').textContent = data.displayName; updateFriendActionButton(friendPeerId); }
}

async function migrateFriend(oldPeerId, newPeerId, handshakeData) {
  const msgs = await Storage.getAllFromIndex('chats', 'friendPeerId', oldPeerId);
  for (const msg of msgs) { msg.friendPeerId = newPeerId; await Storage.put('chats', msg); }
  const oldConv = await Storage.get('conversations', oldPeerId);
  if (oldConv) { await Storage.delete('conversations', oldPeerId); oldConv.friendPeerId = newPeerId; await Storage.put('conversations', oldConv); }
  await Storage.delete('friends', oldPeerId);
  await Storage.put('friends', { peerId: newPeerId, publicKey: handshakeData.publicKey, displayName: handshakeData.displayName, addedAt: Date.now() });
  friendsCache = await Storage.getAll('friends');
  if (currentChat === oldPeerId) { currentChat = newPeerId; document.getElementById('chatFriendName').textContent = handshakeData.displayName; }
  updateAllUI(); showToast(`🤝 ${handshakeData.displayName} conectado!`);
}

// ============================================
// MESSAGE HANDLING
// ============================================
async function handleIncomingMessage(data, friendPeerId) {
  const theirPublicKey = getPeerPublicKey(friendPeerId);
  if (!theirPublicKey) { const conn = connections.get(friendPeerId); if (conn && conn.open) conn.send({ type: 'handshake', publicKey: publicKeyBase64, displayName: identity.displayName, peerId: identity.peerId }); return; }
  const decrypted = await CryptoService.decryptMessage(data.encrypted, privateKey, theirPublicKey);
  if (decrypted) {
    await Storage.saveMessage(friendPeerId, decrypted, 'incoming', data.msgId);
    if (currentChat === friendPeerId) { displayMessage(decrypted, false, data.timestamp || Date.now(), data.msgId); await Storage.markAsRead(friendPeerId); }
    loadConversations(); updateUnreadBadge();
  }
}

async function handleDeleteMessage(data, friendPeerId) { await Storage.deleteMessage(data.msgId); if (currentChat === friendPeerId) await openChat(friendPeerId, true); loadConversations(); }

// ============================================
// FILE TRANSFER
// ============================================
function handleFileStart(data, friendPeerId) { fileTransfers.set(data.transferId, { name: data.fileName, type: data.fileType, size: data.fileSize, chunks: [], received: 0, total: data.totalChunks, msgId: data.msgId }); if (currentChat === friendPeerId) showTransferProgress(data.transferId, data.fileName, 0); }
function handleFileChunk(data, friendPeerId) { const t = fileTransfers.get(data.transferId); if (!t) return; t.chunks[data.index] = data.chunk; t.received++; if (currentChat === friendPeerId) updateTransferProgress(data.transferId, (t.received / t.total) * 100); }
async function handleFileEnd(data, friendPeerId) { const t = fileTransfers.get(data.transferId); if (!t) return; const fullData = t.chunks.join(''); const fileData = { name: t.name, type: t.type, data: fullData }; await Storage.saveMessage(friendPeerId, `📎 ${t.name}`, 'incoming', t.msgId, fileData); if (currentChat === friendPeerId) { removeTransferProgress(data.transferId); displayMessage(`📎 ${t.name}`, false, Date.now(), t.msgId, fileData); await Storage.markAsRead(friendPeerId); } fileTransfers.delete(data.transferId); loadConversations(); updateUnreadBadge(); }
function showTransferProgress(tid, name, pct) { if (document.getElementById(`transfer-${tid}`)) return; const div = document.createElement('div'); div.id = `transfer-${tid}`; div.className = 'message other'; div.innerHTML = `📥 ${escapeHtml(name)}<div class="transfer-progress"><div class="transfer-progress-bar" style="width:${pct}%"></div></div>`; const c = document.getElementById('chatMessages'); c.appendChild(div); c.scrollTop = c.scrollHeight; }
function updateTransferProgress(tid, pct) { const el = document.querySelector(`#transfer-${tid} .transfer-progress-bar`); if (el) el.style.width = `${pct}%`; }
function removeTransferProgress(tid) { const el = document.getElementById(`transfer-${tid}`); if (el) el.remove(); }

function handleFileSelect(event) {
  const file = event.target.files[0];
  if (!file) return;
  if (file.size > MAX_FILE_SIZE) { showToast('❌ Máx 50MB'); event.target.value = ''; return; }
  selectedFile = file;
  showFilePreview(file);
}

function showFilePreview(file) {
  const area = document.getElementById('filePreviewArea');
  let preview = '';
  if (file.type.startsWith('image/')) { preview = `<img src="${URL.createObjectURL(file)}">`; }
  else if (file.type.startsWith('video/')) { preview = `<video src="${URL.createObjectURL(file)}" muted></video>`; }
  else if (file.type.startsWith('audio/')) { preview = '🎵'; }
  else { preview = `<span style="font-size:32px">${getFileIcon(file.name)}</span>`; }
  area.innerHTML = `<div class="file-upload-preview">${preview}<span class="file-name">${escapeHtml(file.name)} (${formatFileSize(file.size)})</span><button class="cancel-file" onclick="cancelFileSelect()">✕</button></div>`;
}

function cancelFileSelect() { selectedFile = null; document.getElementById('filePreviewArea').innerHTML = ''; document.getElementById('fileInput').value = ''; }

async function sendFile() {
  if (!selectedFile || !currentChat) return;
  const conn = connections.get(currentChat);
  if (!conn || !conn.open) { showToast('❌ Offline'); return; }
  const file = selectedFile; const transferId = Storage.generateMsgId(); const msgId = Storage.generateMsgId();
  const reader = new FileReader();
  reader.onload = async (e) => {
    const base64 = e.target.result; const chunks = [];
    for (let i = 0; i < base64.length; i += CHUNK_SIZE) chunks.push(base64.substring(i, i + CHUNK_SIZE));
    conn.send({ type: 'file-start', transferId, msgId, fileName: file.name, fileType: file.type || 'application/octet-stream', fileSize: file.size, totalChunks: chunks.length });
    for (let i = 0; i < chunks.length; i++) {
      conn.send({ type: 'file-chunk', transferId, index: i, chunk: chunks[i] });
      if (i % 10 === 0) await new Promise(r => setTimeout(r, 20));
    }
    conn.send({ type: 'file-end', transferId });
    const fileData = { name: file.name, type: file.type || 'application/octet-stream', size: file.size, data: base64 };
    await Storage.saveMessage(currentChat, `📎 ${file.name}`, 'outgoing', msgId, fileData);
    displayMessage(`📎 ${file.name}`, true, Date.now(), msgId, fileData);
    cancelFileSelect(); loadConversations();
  };
  reader.readAsDataURL(file);
}

function formatFileSize(b) { if (b < 1024) return b + ' B'; if (b < 1048576) return (b / 1024).toFixed(1) + ' KB'; return (b / 1048576).toFixed(1) + ' MB'; }
function getFileIcon(fileName) {
  const ext = (fileName || '').split('.').pop().toLowerCase();
  const icons = { 'zip': '📦', 'rar': '📦', '7z': '📦', 'tar': '📦', 'pdf': '📄', 'doc': '📝', 'docx': '📝', 'txt': '📃', 'xls': '📊', 'xlsx': '📊', 'mp3': '🎵', 'mp4': '🎬', 'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'exe': '💻', 'apk': '📱' };
  return icons[ext] || '📁';
}

function downloadFile(dataUrl, fileName) { const a = document.createElement('a'); a.href = dataUrl; a.download = fileName; document.body.appendChild(a); a.click(); document.body.removeChild(a); }

// ============================================
// FRIENDS
// ============================================
async function addFriend() {
  const input = document.getElementById('friendKeyInput').value.trim(); if (!input) return;
  const parsed = KeyManager.decodeShareKey(input); if (!parsed) { showToast('❌ Formato inválido'); return; }
  const { displayName, peerId, publicKey } = parsed;
  try { await KeyManager.importPublicKey(publicKey); } catch (e) { showToast('❌ Chave pública inválida'); return; }
  if (publicKey === publicKeyBase64 || peerId === identity.peerId) { showToast('❌ Essa é sua própria chave'); return; }
  if (getFriendByPeerId(peerId) || getFriendByPublicKey(publicKey)) { showToast('❌ Amigo já adicionado'); return; }
  const friend = { peerId, publicKey, displayName, addedAt: Date.now() }; await Storage.put('friends', friend);
  knownPeers.set(peerId, { peerId, publicKey, displayName, lastSeen: Date.now() }); await Storage.put('knownPeers', { peerId, publicKey, displayName, lastSeen: Date.now() });
  friendsCache = await Storage.getAll('friends'); document.getElementById('friendKeyInput').value = ''; loadFriends();
  connectToFriend(peerId); showToast(`✅ ${displayName} adicionado!`);
}

async function addFriendFromPeer(peerId) {
  const info = knownPeers.get(peerId); if (!info) { showToast('❌ Info não encontrada'); return; }
  if (getFriendByPeerId(peerId)) { showToast('❌ Já é amigo'); return; }
  await Storage.put('friends', { peerId, publicKey: info.publicKey, displayName: info.displayName, addedAt: Date.now() });
  friendsCache = await Storage.getAll('friends'); loadFriends(); updateFriendActionButton(peerId); showToast(`✅ ${info.displayName} adicionado!`);
}

async function removeFriend(friendPeerId) {
  await Storage.delete('friends', friendPeerId);
  if (connections.has(friendPeerId)) { try { connections.get(friendPeerId).close(); } catch(e) {} connections.delete(friendPeerId); }
  friendsCache = await Storage.getAll('friends'); loadFriends(); loadConversations();
  if (currentChat === friendPeerId) updateFriendActionButton(friendPeerId); showToast('❌ Amigo removido');
}

async function toggleFriend() { if (!currentChat) return; const friend = getFriendByPeerId(currentChat); if (friend) showConfirm('⚠️ Remover', `Remover ${friend.displayName}?`, () => removeFriend(currentChat)); else await addFriendFromPeer(currentChat); }
async function updateFriendActionButton(friendPeerId) { const btn = document.getElementById('friendActionBtn'); if (!btn) return; const friend = getFriendByPeerId(friendPeerId); btn.textContent = friend ? '➖' : '➕'; btn.title = friend ? 'Remover amigo' : 'Adicionar amigo'; }

// ============================================
// LOAD FRIENDS & CONVERSATIONS
// ============================================
async function loadFriends() {
  friendsCache = await Storage.getAll('friends'); const list = document.getElementById('friendsList'); list.innerHTML = '';
  if (friendsCache.length === 0) { list.innerHTML = '<div class="friend-item" style="justify-content:center"><div style="color:var(--whatsapp-text-light);padding:20px;">Nenhum amigo adicionado.<br>Compartilhe sua chave e peça a do amigo!</div></div>'; return; }
  friendsCache.forEach(friend => {
    const conn = connections.get(friend.peerId); const isOnline = conn && conn.open; const name = friend.displayName || '?';
    const div = document.createElement('div'); div.className = 'friend-item'; div.onclick = () => openChat(friend.peerId);
    div.innerHTML = `<div class="friend-avatar">${name.charAt(0).toUpperCase()}</div><div class="friend-info"><div class="friend-name">${escapeHtml(name)}<span class="friend-status ${isOnline ? '' : 'offline'}"></span></div><div class="friend-last-msg">${isOnline ? '🟢 Online' : '⚪ Offline'}</div></div>`;
    list.appendChild(div);
  });
}

async function loadConversations() {
  const conversations = await Storage.getConversations(); const list = document.getElementById('chatsList'); list.innerHTML = '';
  if (conversations.length === 0) { list.innerHTML = '<div class="friend-item" style="justify-content:center"><div style="color:var(--whatsapp-text-light);padding:20px;">Nenhuma conversa ainda</div></div>'; updateUnreadBadge(); return; }
  conversations.sort((a, b) => b.lastMessageTime - a.lastMessageTime);
  for (const conv of conversations) {
    const name = getPeerDisplayName(conv.friendPeerId); const conn = connections.get(conv.friendPeerId); const isOnline = conn && conn.open;
    const time = new Date(conv.lastMessageTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const div = document.createElement('div'); div.className = 'friend-item'; div.onclick = () => openChat(conv.friendPeerId);
    const isFriend = !!getFriendByPeerId(conv.friendPeerId); const badge = isFriend ? '' : '<span class="contact-badge">(contato)</span>';
    div.innerHTML = `<div class="friend-avatar">${name.charAt(0).toUpperCase()}</div><div class="friend-info"><div class="friend-name">${escapeHtml(name)} ${badge}<span class="friend-status ${isOnline ? '' : 'offline'}"></span></div><div class="friend-last-msg">${escapeHtml(conv.lastMessage || '')}</div></div><div class="friend-time">${time}</div>${conv.unread ? `<div class="friend-unread">${conv.unread}</div>` : ''}`;
    list.appendChild(div);
  }
  updateUnreadBadge();
}

async function updateUnreadBadge() { const convs = await Storage.getConversations(); const total = convs.reduce((s, c) => s + (c.unread || 0), 0); const badge = document.getElementById('chatBadge'); if (total > 0) { badge.style.display = 'inline-flex'; badge.textContent = total > 9 ? '9+' : total; } else badge.style.display = 'none'; }
function updateAllUI() { loadFriends(); loadConversations(); }

// ============================================
// CHAT VIEW
// ============================================
async function openChat(friendPeerId, keepView) {
  currentChat = friendPeerId; await Storage.markAsRead(friendPeerId);
  const messages = await Storage.getMessages(friendPeerId); const chatMessages = document.getElementById('chatMessages'); chatMessages.innerHTML = '';
  messages.forEach(msg => displayMessage(msg.message, msg.direction === 'outgoing', msg.timestamp, msg.msgId, msg.fileData));
  document.getElementById('chatFriendName').textContent = getPeerDisplayName(friendPeerId);
  const conn = connections.get(friendPeerId); updateChatStatus(conn && conn.open); await updateFriendActionButton(friendPeerId);
  if (!keepView) { document.querySelector('.tabs').classList.add('hidden'); document.querySelector('.tab-content').classList.add('hidden'); document.getElementById('chatContainer').classList.remove('hidden'); }
  cancelFileSelect(); setTimeout(() => { chatMessages.scrollTop = chatMessages.scrollHeight; }, 50); loadConversations();
}

function closeChat() { currentChat = null; document.querySelector('.tabs').classList.remove('hidden'); document.querySelector('.tab-content').classList.remove('hidden'); document.getElementById('chatContainer').classList.add('hidden'); cancelFileSelect(); enableChat(false); loadFriends(); loadConversations(); }
function updateChatStatus(isOnline) { document.getElementById('chatFriendStatus').className = `friend-status ${isOnline ? '' : 'offline'}`; document.getElementById('chatFriendStatusText').textContent = isOnline ? 'online · criptografado' : 'offline'; enableChat(isOnline); }
function enableChat(enabled) { document.getElementById('chatInput').disabled = !enabled; document.getElementById('sendBtn').disabled = !enabled; document.getElementById('attachBtn').disabled = !enabled; }

// ============================================
// SEND MESSAGE
// ============================================
async function sendMessage() {
  if (selectedFile) { await sendFile(); return; }
  const input = document.getElementById('chatInput'); const text = input.value.trim(); if (!text || !currentChat) return;
  const conn = connections.get(currentChat); if (!conn || !conn.open) { showToast('❌ Offline'); return; }
  const theirPubKey = getPeerPublicKey(currentChat); if (!theirPubKey) { showToast('❌ Chave não encontrada'); return; }
  const msgId = Storage.generateMsgId();
  const encrypted = await CryptoService.encryptMessage(text, privateKey, theirPubKey); if (!encrypted) { showToast('❌ Erro ao criptografar'); return; }
  conn.send({ type: 'message', encrypted, msgId, timestamp: Date.now() });
  await Storage.saveMessage(currentChat, text, 'outgoing', msgId);
  displayMessage(text, true, Date.now(), msgId); input.value = ''; loadConversations();
}

function displayMessage(text, isMine, timestamp, msgId, fileData) {
  const div = document.createElement('div'); div.className = `message ${isMine ? 'mine' : 'other'}`; if (msgId) div.dataset.msgId = msgId;
  const time = new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  let content = '';
  if (fileData && fileData.data) {
    const type = fileData.type || ''; const name = fileData.name || 'arquivo';
    if (type.startsWith('image/')) { content += `<img class="message-image" src="${fileData.data}" onclick="viewImage(this.src)"><div style="font-size:12px;opacity:0.7;">${escapeHtml(name)}</div>`; }
    else if (type.startsWith('video/')) { content += `<video class="message-video" src="${fileData.data}" controls></video><div style="font-size:12px;opacity:0.7;">${escapeHtml(name)}</div>`; }
    else if (type.startsWith('audio/')) { content += `<audio class="message-audio" src="${fileData.data}" controls></audio><div style="font-size:12px;opacity:0.7;">${escapeHtml(name)}</div>`; }
    else { content += `<div class="message-file" onclick="downloadFile('${fileData.data}', '${escapeHtml(name)}')"><span class="message-file-icon">${getFileIcon(name)}</span><div class="message-file-info"><div class="message-file-name">${escapeHtml(name)}</div></div><span class="message-file-download">⬇️</span></div>`; }
  } else { content = parseMessageContent(text); }
  content += `<span class="message-time">${time}</span>`;
  if (msgId) content += `<button class="message-delete-btn" onclick="event.stopPropagation();showDeleteMessageModal('${escapeHtml(msgId)}','${escapeHtml(currentChat || '')}')">✕</button>`;
  div.innerHTML = content; const container = document.getElementById('chatMessages'); container.appendChild(div); container.scrollTop = container.scrollHeight;
}

function parseMessageContent(text) {
  const ytRegex = /(?:https?:\/\/)?(?:www\.)?(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/|youtube\.com\/shorts\/)([a-zA-Z0-9_-]{11})/gi;
  const imgRegex = /(https?:\/\/[^\s]+\.(?:jpg|jpeg|png|gif|webp))/gi;
  let match; const embeds = []; const imageUrls = [];
  while ((match = ytRegex.exec(text)) !== null) embeds.push(`<iframe class="youtube-embed" src="https://www.youtube.com/embed/${match[1]}" allowfullscreen></iframe>`);
  while ((match = imgRegex.exec(text)) !== null) imageUrls.push(match[1]);
  let result = renderTextWithLinks(text);
  imageUrls.forEach(u => { result += `<br><img class="message-image" src="${escapeHtml(u)}" onclick="viewImage(this.src)" onerror="this.style.display='none'">`; });
  embeds.forEach(e => { result += `<br>${e}`; }); return result;
}

function renderTextWithLinks(text) {
  const urlRegex = /(https?:\/\/[^\s<]+)/gi; const parts = text.split(urlRegex); let html = '';
  for (const part of parts) { if (/^https?:\/\//i.test(part)) html += `<a href="${escapeHtml(part)}" class="link-preview" target="_blank">${escapeHtml(part)}</a>`; else html += escapeHtml(part); } 
  return html;
}

function viewImage(src) { const v = document.createElement('div'); v.className = 'image-viewer'; v.onclick = () => v.remove(); v.innerHTML = `<button class="image-viewer-close" onclick="this.parentElement.remove()">✕</button><img src="${src}">`; document.body.appendChild(v); }

// ============================================
// MODALS
// ============================================
function showConfirm(title, text, action, isDanger) { document.getElementById('confirmTitle').textContent = title; document.getElementById('confirmText').textContent = text; document.getElementById('confirmYesBtn').className = isDanger ? 'danger' : ''; pendingConfirmAction = action; document.getElementById('confirmModal').classList.remove('hidden'); }
function closeConfirmModal() { pendingConfirmAction = null; document.getElementById('confirmModal').classList.add('hidden'); }
function confirmAction() { if (pendingConfirmAction) pendingConfirmAction(); closeConfirmModal(); }
function showDeleteMessageModal(msgId, fId) { pendingDeleteMsgId = msgId; pendingDeleteFriendId = fId; document.getElementById('deleteMessageModal').classList.remove('hidden'); }
function closeDeleteMessageModal() { pendingDeleteMsgId = null; pendingDeleteFriendId = null; document.getElementById('deleteMessageModal').classList.add('hidden'); }
async function deleteMessageForMe() { if (!pendingDeleteMsgId) return; await Storage.deleteMessage(pendingDeleteMsgId); if (currentChat) await openChat(currentChat, true); loadConversations(); closeDeleteMessageModal(); showToast('🗑️ Apagada'); }
async function deleteMessageForAll() { if (!pendingDeleteMsgId || !pendingDeleteFriendId) return; await Storage.deleteMessage(pendingDeleteMsgId); const conn = connections.get(pendingDeleteFriendId); if (conn && conn.open) conn.send({ type: 'delete-message', msgId: pendingDeleteMsgId }); if (currentChat) await openChat(currentChat, true); loadConversations(); closeDeleteMessageModal(); showToast('🗑️ Apagada para todos'); }

async function clearConversation() { closeChatMenu(); if (!currentChat) return; const name = getPeerDisplayName(currentChat); showConfirm('🗑️ Limpar conversa', `Apagar todas mensagens com ${name}?`, async () => { await Storage.clearConversation(currentChat); document.getElementById('chatMessages').innerHTML = ''; loadConversations(); showToast('🗑️ Conversa limpa'); }, true); }
async function deleteAllAndClose() { closeChatMenu(); if (!currentChat) return; const name = getPeerDisplayName(currentChat); showConfirm('❌ Apagar tudo', `Apagar tudo com ${name} e voltar?`, async () => { await Storage.clearConversation(currentChat); closeChat(); loadConversations(); showToast('❌ Apagado'); }, true); }

function showFriendKey() { closeChatMenu(); if (!currentChat) return; const pubKey = getPeerPublicKey(currentChat); const name = getPeerDisplayName(currentChat); if (!pubKey) { showToast('Chave não disponível'); return; } document.getElementById('keyModalTitle').textContent = `🔑 Chave de ${name}`; document.getElementById('keyModalDesc').textContent = 'Fingerprint: ' + KeyManager.fingerprint(pubKey); document.getElementById('keyModalDisplay').textContent = pubKey; document.getElementById('keyModal').classList.remove('hidden'); }
function showSettings() { document.getElementById('settingsUsername').textContent = identity.username; document.getElementById('settingsDisplayName').textContent = identity.displayName; document.getElementById('settingsPeerId').textContent = identity.peerId; document.getElementById('settingsFingerprint').textContent = KeyManager.fingerprint(publicKeyBase64); document.getElementById('settingsModal').classList.remove('hidden'); }
function closeSettingsModal() { document.getElementById('settingsModal').classList.add('hidden'); }
function toggleChatMenu(e) { e.stopPropagation(); document.getElementById('chatDropdown').classList.toggle('hidden'); setTimeout(() => { const close = () => { document.getElementById('chatDropdown').classList.add('hidden'); document.removeEventListener('click', close); }; document.addEventListener('click', close); }, 10); }
function closeChatMenu() { document.getElementById('chatDropdown').classList.add('hidden'); }

function switchTab(tab) {
  if (!document.getElementById('chatContainer').classList.contains('hidden')) return;
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active')); document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  if (tab === 'friends') { document.querySelectorAll('.tab')[0].classList.add('active'); document.getElementById('friendsTab').classList.add('active'); loadFriends(); }
  else { document.querySelectorAll('.tab')[1].classList.add('active'); document.getElementById('chatsTab').classList.add('active'); loadConversations(); }
}

function showToast(message) { document.querySelectorAll('.toast').forEach(t => t.remove()); const toast = document.createElement('div'); toast.className = 'toast'; toast.textContent = message; document.body.appendChild(toast); setTimeout(() => { toast.style.animation = 'fadeOut 0.3s'; setTimeout(() => toast.remove(), 300); }, 3000); }
function escapeHtml(text) { if (!text) return ''; const d = document.createElement('div'); d.textContent = text; return d.innerHTML; }

init();

window.addEventListener('beforeunload', () => { reconnectTimers.forEach(t => clearInterval(t)); if (peer) { try { peer.destroy(); } catch(e){} } });
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') {
    if (peer && peer.disconnected && !peer.destroyed) { try { peer.reconnect(); } catch(e) {} }
    setTimeout(() => connectToAllFriends(), 1000);
  }
});
