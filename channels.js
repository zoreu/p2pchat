// ============================================
// CHANNELS — Predictable Mesh + Robust Voice Fix
// + ID longo, mute por usuário, controle de volume,
//   lista de membros, menu de contexto, anexos no canal,
//   miniaturas de imagem, mensagens criptografadas no storage
// ============================================

let myChannels = [];
let activeChannel = null;
let channelPeers = new Map();
let channelStreams = new Map();
let localStream = null;
let inVoice = false;
let isMuted = false;
let isDeafened = false;
let discoveryInterval = null;
let channelHostPeer = null;

// Controles de volume
let speakerVolume = 1.0;
let micVolume = 1.0;
let micGainNode = null;
let audioContext = null;
let micSource = null;
let micDest = null;

// Mute individual por peer
let mutedPeers = new Set();

// Arquivo anexo aguardando envio no canal
let channelPendingFile = null;

// ============================================
// ICE SERVERS — Configuração compartilhada
// ============================================
const CHANNEL_ICE_SERVERS = [

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

];

// ============================================
// STORAGE — Criptografia de mensagens do canal
// ============================================
function getChannelStorageKey(channelId) {
  return 'p2pchat_channel_msgs_' + identity.username + '_' + btoa(unescape(encodeURIComponent(channelId))).replace(/[^a-zA-Z0-9]/g, '').substring(0, 20);
}

function encryptChannelMessages(msgs) {
  try {
    const json = JSON.stringify(msgs);
    const key = identity.username + '_channel_' + (identity.peerId || '');
    return CryptoJS.AES.encrypt(json, key).toString();
  } catch(e) { return null; }
}

function decryptChannelMessages(enc) {
  try {
    const key = identity.username + '_channel_' + (identity.peerId || '');
    const bytes = CryptoJS.AES.decrypt(enc, key);
    return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
  } catch(e) { return []; }
}

function saveChannelMessage(channelId, msgObj) {
  try {
    const storKey = getChannelStorageKey(channelId);
    let msgs = loadChannelMessages(channelId);
    msgs.push(msgObj);
    if (msgs.length > 200) msgs = msgs.slice(-200);
    const encrypted = encryptChannelMessages(msgs);
    if (encrypted) localStorage.setItem(storKey, encrypted);
  } catch(e) {}
}

function deleteChannelMessageFromStorage(channelId, msgId) {
  try {
    const storKey = getChannelStorageKey(channelId);
    let msgs = loadChannelMessages(channelId);
    msgs = msgs.filter(m => m.msgId !== msgId);
    const encrypted = encryptChannelMessages(msgs);
    if (encrypted) localStorage.setItem(storKey, encrypted);
  } catch(e) {}
}

function loadChannelMessages(channelId) {
  try {
    const storKey = getChannelStorageKey(channelId);
    const enc = localStorage.getItem(storKey);
    if (!enc) return [];
    return decryptChannelMessages(enc) || [];
  } catch(e) { return []; }
}

function clearChannelMessages(channelId) {
  try {
    const storKey = getChannelStorageKey(channelId);
    localStorage.removeItem(storKey);
  } catch(e) {}
}

// ============================================
// CANAIS — CRUD
// ============================================
async function loadChannels() {
  try {
    const stored = localStorage.getItem('p2pchat_channels_' + identity.username);
    myChannels = stored ? JSON.parse(stored) : [];
  } catch(e) { myChannels = []; }
  renderChannelsList();
}

function saveChannels() {
  localStorage.setItem('p2pchat_channels_' + identity.username, JSON.stringify(myChannels));
}

function createChannel() {
  const nameInput = document.getElementById('channelNameInput');
  const name = nameInput.value.trim().replace('|', '-');
  if (!name) { showToast('Digite um nome'); return; }
  // ID longo: 24 chars para evitar colisão
  const arr = crypto.getRandomValues(new Uint8Array(18));
  const rawId = 'ch_' + Array.from(arr).map(b => b.toString(36).padStart(2,'0')).join('').substring(0, 24);
  const fullId = name + '|' + rawId;
  myChannels.push({ id: fullId, name: name, createdAt: Date.now() });
  saveChannels();
  nameInput.value = '';
  renderChannelsList();
  openChannel(fullId);
}

function joinChannelById() {
  const input = document.getElementById('joinChannelInput');
  const inputVal = input.value.trim();
  if (!inputVal) return;
  let name = 'Canal Público';
  let fullId = inputVal;
  if (inputVal.includes('|')) name = inputVal.split('|')[0];
  if (!myChannels.find(c => c.id === fullId)) {
    myChannels.push({ id: fullId, name: name, createdAt: Date.now() });
    saveChannels();
  }
  input.value = '';
  renderChannelsList();
  openChannel(fullId);
}

function renderChannelsList() {
  const list = document.getElementById('channelsList');
  if (!list) return;
  list.innerHTML = '';
  if (myChannels.length === 0) {
    list.innerHTML = '<div class="friend-item" style="justify-content:center"><div style="color:var(--whatsapp-text-light);padding:20px;">Nenhum canal ativo.</div></div>';
    return;
  }
  myChannels.forEach(ch => {
    const div = document.createElement('div');
    div.className = 'channel-item';
    div.onclick = () => openChannel(ch.id);
    div.innerHTML = '<div class="channel-avatar">📡</div><div class="channel-info"><div class="channel-name">' + escapeHtml(ch.name) + '</div><div class="channel-members">Clique para entrar</div></div>';
    list.appendChild(div);
  });
}

function openChannel(channelId) {
  activeChannel = channelId;
  const ch = myChannels.find(c => c.id === channelId);
  document.getElementById('channelViewName').textContent = ch ? ch.name : 'Canal';
  document.querySelector('.tabs').classList.add('hidden');
  document.querySelector('.tab-content').classList.add('hidden');
  document.getElementById('channelContainer').classList.remove('hidden');
  document.getElementById('channelMessages').innerHTML = '';

  inVoice = false; isMuted = false; isDeafened = false;
  speakerVolume = 1.0; micVolume = 1.0;
  mutedPeers.clear();
  channelPendingFile = null;
  clearChannelFilePreview();

  const spk = document.getElementById('speakerVolumeSlider');
  const mic = document.getElementById('micVolumeSlider');
  if (spk) { spk.value = 100; document.getElementById('speakerVolumeLabel').textContent = '100%'; }
  if (mic) { mic.value = 100; document.getElementById('micVolumeLabel').textContent = '100%'; }

  updateVoiceUI();
  renderChannelMembers();

  const history = loadChannelMessages(channelId);
  history.forEach(m => {
    if (m.system) addChannelSystemMessage(m.text, false);
    else addChannelChatMessage(m.author, m.text, m.timestamp, m.isMine, false, m.fileData, m.msgId);
  });

  electChannelHost(channelId);
  connectToChannel(channelId);
}

// ============================================
// P2P MESH — NÃO ALTERAR
// ============================================
function electChannelHost(channelId) {
  const hostId = 'host_' + channelId.replace(/[^a-zA-Z0-9]/g, '_');
  channelHostPeer = new Peer(hostId, {
    host: '0.peerjs.com',
    port: 443,
    secure: true,
    config: {
      iceServers: CHANNEL_ICE_SERVERS,
      sdpSemantics: 'unified-plan'
    }
  });
  const channelMembers = new Set();
  channelHostPeer.on('error', (err) => {
    if (err.type === 'unavailable-id') {
      channelHostPeer.destroy();
      channelHostPeer = null;
    }
  });
  channelHostPeer.on('open', () => {
    channelHostPeer.on('connection', (conn) => {
      conn.on('data', (data) => {
        if (data.type === 'channel-join') {
          channelMembers.add(data.peerId);
          conn.send({ type: 'sync-peers', channelId, peers: Array.from(channelMembers) });
        }
      });
    });
  });
}

function connectToChannel(channelId) {
  if (!peer || !peer.open) return;
  if (discoveryInterval) clearInterval(discoveryInterval);
  const hostId = 'host_' + channelId.replace(/[^a-zA-Z0-9]/g, '_');
  const connectToHost = () => {
    if (activeChannel !== channelId) return;
    const hostConn = peer.connect(hostId, { reliable: true });
    hostConn.on('open', () => {
       hostConn.send({ type: 'channel-join', channelId, displayName: identity.displayName, peerId: identity.peerId });
    });
    hostConn.on('data', (data) => {
       if (data.type === 'sync-peers') {
         data.peers.forEach(pid => {
           if (pid !== identity.peerId) tryConnectPublicPeer(channelId, pid);
         });
       }
    });
  };
  connectToHost();
  discoveryInterval = setInterval(connectToHost, 15000);
  if (!channelPeers.has(channelId)) channelPeers.set(channelId, new Map());
}

function tryConnectPublicPeer(channelId, targetPeerId) {
  const peers = channelPeers.get(channelId);
  if (peers && peers.has(targetPeerId)) return;
  const conn = peer.connect(targetPeerId, { metadata: { publicJoin: true, channelId }, reliable: true });
  if (conn) {
    conn.on('open', () => {
      conn.send({ type: 'channel-join', channelId, displayName: identity.displayName, peerId: identity.peerId });
      setupChannelConnection(channelId, targetPeerId, conn);
    });
  }
}

function setupChannelConnection(channelId, peerId, conn) {
  let peers = channelPeers.get(channelId);
  if (!peers) { peers = new Map(); channelPeers.set(channelId, peers); }
  if (peers.has(peerId)) return;
  peers.set(peerId, { conn, displayName: 'Carregando...', inVoice: false, muted: false });
  conn.on('data', (data) => {
    if (data && data.channelId === channelId) handleChannelData(data, peerId, channelId);
  });
  conn.on('close', () => {
    const pd = peers.get(peerId);
    if (pd) addChannelSystemMessage(pd.displayName + ' desconectou');
    peers.delete(peerId);
    removeVoiceStream(peerId);
    updateVoiceUI();
    updateChannelMemberCount();
    renderChannelMembers();
  });
  updateChannelMemberCount();
  renderChannelMembers();
}

async function handleChannelData(data, fromPeerId, channelId) {
  const peers = channelPeers.get(channelId); if (!peers) return;
  switch(data.type) {
    case 'channel-join':
      if (!peers.has(fromPeerId)) setupChannelConnection(channelId, fromPeerId, connections.get(fromPeerId) || peer.connect(fromPeerId));
      const pObj = peers.get(fromPeerId);
      if (pObj) { pObj.displayName = data.displayName; }
      updateVoiceUI(); updateChannelMemberCount(); renderChannelMembers();
      break;
    case 'channel-message':
      addChannelChatMessage(data.displayName, data.text, data.timestamp, false, true, data.fileData);
      break;
    case 'channel-voice-join':
      const vpd = peers.get(fromPeerId);
      if (vpd) { vpd.inVoice = true; vpd.displayName = data.displayName; vpd.muted = !!data.muted; }
      updateVoiceUI();
      if (inVoice && localStream) callPeer(fromPeerId);
      break;
    case 'channel-voice-leave':
      const lpd = peers.get(fromPeerId); if (lpd) lpd.inVoice = false;
      removeVoiceStream(fromPeerId);
      updateVoiceUI();
      break;
    case 'channel-voice-mute':
      const mpd = peers.get(fromPeerId); if (mpd) mpd.muted = data.muted;
      updateVoiceUI();
      break;
    case 'channel-delete-msg':
      const delEl = document.querySelector('.channel-msg[data-msg-id="' + data.msgId + '"]');
      if (delEl) delEl.remove();
      if (activeChannel) deleteChannelMessageFromStorage(activeChannel, data.msgId);
      break;
  }
}
// ============================================
// FIM DO BLOCO P2P MESH
// ============================================

// ============================================
// ENVIO DE MENSAGEM — com suporte a arquivo
// ============================================
function sendChannelMessage() {
  const input = document.getElementById('channelChatInput');
  const text = input.value.trim();
  if (!text && !channelPendingFile) return;
  if (!activeChannel) return;

  let fileData = null;
  if (channelPendingFile) {
    fileData = channelPendingFile;
    channelPendingFile = null;
    clearChannelFilePreview();
  }

  const msgText = text || (fileData ? fileData.name : '');
  const timestamp = Date.now();
  const peers = channelPeers.get(activeChannel);
  if (peers) peers.forEach(pd => {
    if (pd.conn && pd.conn.open) pd.conn.send({
      type: 'channel-message',
      channelId: activeChannel,
      displayName: identity.displayName,
      text: msgText,
      timestamp,
      fileData
    });
  });

  addChannelChatMessage(identity.displayName, msgText, timestamp, true, true, fileData);
  input.value = '';
}

function handleChannelFileSelect(event) {
  const file = event.target.files[0];
  if (!file) return;
  const MAX = 10 * 1024 * 1024;
  if (file.size > MAX) { showToast('Arquivo muito grande (máx 10MB)'); event.target.value = ''; return; }
  const reader = new FileReader();
  reader.onload = (e) => {
    channelPendingFile = { name: file.name, type: file.type, size: file.size, data: e.target.result };
    showChannelFilePreview(channelPendingFile);
  };
  reader.readAsDataURL(file);
  event.target.value = '';
}

function showChannelFilePreview(fileData) {
  const area = document.getElementById('channelFilePreviewArea');
  if (!area) return;
  let previewHtml = '';
  if (fileData.type && fileData.type.startsWith('image/')) {
    previewHtml = '<img src="' + fileData.data + '" style="max-height:60px;border-radius:6px;">';
  } else {
    previewHtml = '<span style="font-size:22px;">' + getChannelFileIcon(fileData.name) + '</span>';
  }
  area.innerHTML = '<div class="file-upload-preview">' + previewHtml + '<span class="file-name">' + escapeHtml(fileData.name) + ' (' + formatChannelFileSize(fileData.size) + ')</span><button class="cancel-file" onclick="cancelChannelFile()">✕</button></div>';
}

function clearChannelFilePreview() {
  const area = document.getElementById('channelFilePreviewArea');
  if (area) area.innerHTML = '';
}

function cancelChannelFile() {
  channelPendingFile = null;
  clearChannelFilePreview();
}

function getChannelFileIcon(filename) {
  const ext = (filename.split('.').pop() || '').toLowerCase();
  const icons = { pdf:'📄', doc:'📝', docx:'📝', xls:'📊', xlsx:'📊', zip:'🗜️', rar:'🗜️', '7z':'🗜️', mp3:'🎵', wav:'🎵', ogg:'🎵', mp4:'🎬', webm:'🎬', txt:'📃', csv:'📊' };
  return icons[ext] || '📎';
}

function formatChannelFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

// ============================================
// RENDERIZAÇÃO DE MENSAGENS
// ============================================
function addChannelChatMessage(author, text, timestamp, isMine, saveToStorage, fileData, existingMsgId) {
  if (saveToStorage === undefined) saveToStorage = true;
  if (fileData === undefined) fileData = null;
  const container = document.getElementById('channelMessages');
  if (!container) return;

  const msgId = existingMsgId || ('cm_' + timestamp + '_' + Math.random().toString(36).substring(2, 8));

  const div = document.createElement('div');
  div.className = 'channel-msg';
  div.dataset.msgId = msgId;
  div.dataset.isMine = isMine ? '1' : '0';
  const timeStr = new Date(timestamp).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
  const avatarColor = isMine ? 'background:var(--whatsapp-green)' : '';

  let contentHtml = '';
  if (fileData && fileData.data) {
    if (fileData.type && fileData.type.startsWith('image/')) {
      const safeMime = (fileData.type || 'image/png').replace(/'/g, '');
      contentHtml = '<div class="channel-img-thumb-wrap"><img src="' + fileData.data + '" class="channel-img-thumb" title="' + escapeHtml(fileData.name) + '" onclick="openChannelImageBlob(\'' + encodeURIComponent(fileData.data) + '\',\'' + safeMime + '\')"></div>';
    } else if (fileData.type && fileData.type.startsWith('audio/')) {
      contentHtml = '<audio controls src="' + fileData.data + '" class="channel-audio"></audio>';
    } else if (fileData.type && fileData.type.startsWith('video/')) {
      contentHtml = '<video controls src="' + fileData.data + '" class="channel-video"></video>';
    } else {
      contentHtml = '<a class="channel-file-dl" href="' + fileData.data + '" download="' + escapeHtml(fileData.name) + '"><span class="channel-file-icon">' + getChannelFileIcon(fileData.name) + '</span><span class="channel-file-info"><span class="channel-file-name">' + escapeHtml(fileData.name) + '</span><span class="channel-file-size">' + formatChannelFileSize(fileData.size) + '</span></span><span>⬇️</span></a>';
    }
    if (text && text !== fileData.name) {
      contentHtml = '<div class="channel-msg-text">' + parseChannelContent(text) + '</div>' + contentHtml;
    }
  } else {
    contentHtml = '<div class="channel-msg-text">' + parseChannelContent(text) + '</div>';
  }

  div.innerHTML =
    '<div class="channel-msg-avatar" style="' + avatarColor + '">' + (author[0]||'?').toUpperCase() + '</div>' +
    '<div class="channel-msg-content">' +
      '<div class="channel-msg-header">' +
        '<span class="channel-msg-author" style="' + (isMine ? 'color:var(--whatsapp-green)' : '') + '">' + escapeHtml(author) + '</span>' +
        '<span class="channel-msg-time">' + timeStr + '</span>' +
        '<button class="channel-msg-delete-btn" onclick="showChannelDeleteMenu(event, \'' + msgId + '\')" title="Apagar mensagem">✕</button>' +
      '</div>' +
      contentHtml +
    '</div>';

  container.appendChild(div);
  container.scrollTop = container.scrollHeight;

  if (saveToStorage && activeChannel) {
    saveChannelMessage(activeChannel, {
      msgId, author, text, timestamp, isMine,
      fileData: fileData ? { name: fileData.name, type: fileData.type, size: fileData.size, data: fileData.data } : null
    });
  }
}

function showChannelDeleteMenu(e, msgId) {
  e.stopPropagation();
  const old = document.getElementById('channelDeleteMenu');
  if (old) old.remove();

  const msgEl = document.querySelector('.channel-msg[data-msg-id="' + msgId + '"]');
  const isMine = msgEl && msgEl.dataset.isMine === '1';

  const menu = document.createElement('div');
  menu.id = 'channelDeleteMenu';
  menu.className = 'channel-delete-menu';

  let html = '<div class="channel-delete-item" onclick="deleteChannelMsgForMe(\'' + msgId + '\')">🗑️ Apagar para mim</div>';
  if (isMine) {
    html += '<div class="channel-delete-item danger" onclick="deleteChannelMsgForAll(\'' + msgId + '\')">❌ Apagar para todos</div>';
  }
  html += '<div class="channel-delete-item cancel" onclick="document.getElementById(\'channelDeleteMenu\').remove()">Cancelar</div>';
  menu.innerHTML = html;
  document.body.appendChild(menu);

  const btn = e.currentTarget || e.target;
  const rect = btn.getBoundingClientRect();
  menu.style.top = (rect.bottom + 4) + 'px';
  menu.style.left = Math.min(rect.left, window.innerWidth - 180) + 'px';

  setTimeout(() => {
    const close = (ev) => {
      if (!menu.contains(ev.target)) { menu.remove(); document.removeEventListener('click', close); }
    };
    document.addEventListener('click', close);
  }, 10);
}

function deleteChannelMsgForMe(msgId) {
  const menu = document.getElementById('channelDeleteMenu');
  if (menu) menu.remove();
  const el = document.querySelector('.channel-msg[data-msg-id="' + msgId + '"]');
  if (el) el.remove();
  if (activeChannel) deleteChannelMessageFromStorage(activeChannel, msgId);
}

function deleteChannelMsgForAll(msgId) {
  const menu = document.getElementById('channelDeleteMenu');
  if (menu) menu.remove();
  const el = document.querySelector('.channel-msg[data-msg-id="' + msgId + '"]');
  if (el) el.remove();
  if (activeChannel) deleteChannelMessageFromStorage(activeChannel, msgId);
  const peers = channelPeers.get(activeChannel);
  if (peers) peers.forEach(pd => {
    if (pd.conn && pd.conn.open) pd.conn.send({ type: 'channel-delete-msg', channelId: activeChannel, msgId });
  });
}

function openChannelImageBlob(encodedData, mimeType) {
  try {
    const dataUrl = decodeURIComponent(encodedData);
    const arr = dataUrl.split(',');
    const bstr = atob(arr[1]);
    let n = bstr.length;
    const u8arr = new Uint8Array(n);
    while (n--) u8arr[n] = bstr.charCodeAt(n);
    const blob = new Blob([u8arr], { type: mimeType || 'image/png' });
    const url = URL.createObjectURL(blob);
    window.open(url, '_blank');
  } catch(e) { console.error('Erro ao abrir imagem:', e); }
}

function parseChannelContent(text) {
  const urlRegex = /(https?:\/\/[^\s<]+)/gi;
  return text.split(urlRegex).map(part => {
    if (part.match(urlRegex)) {
      const cleanUrl = escapeHtml(part);
      if (part.match(/\.(jpeg|jpg|gif|png|webp|svg)$/i)) {
        return '<br><img src="' + cleanUrl + '" style="max-width:100%;max-height:220px;border-radius:8px;margin-top:5px;cursor:pointer;" onclick="window.open(\'' + cleanUrl + '\',\'_blank\')"><br>';
      }
      if (part.match(/\.(mp3|wav|ogg)$/i)) return '<br><audio controls src="' + cleanUrl + '" style="width:100%;margin-top:5px"></audio><br>';
      return '<a href="' + cleanUrl + '" target="_blank" style="color:#53bdeb;text-decoration:underline">' + cleanUrl + '</a>';
    }
    return escapeHtml(part);
  }).join('');
}

function addChannelSystemMessage(text, saveToStorage) {
  if (saveToStorage === undefined) saveToStorage = true;
  const container = document.getElementById('channelMessages');
  if (!container) return;
  const div = document.createElement('div');
  div.className = 'channel-msg-system';
  div.textContent = text;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  if (saveToStorage && activeChannel) {
    saveChannelMessage(activeChannel, { system: true, text, timestamp: Date.now() });
  }
}

// ============================================
// MEMBROS DO CANAL
// ============================================
function renderChannelMembers() {
  const panel = document.getElementById('channelMembersPanel');
  if (!panel) return;

  const peers = activeChannel ? channelPeers.get(activeChannel) : null;
  let html = '<div class="members-title">👥 Membros</div>';

  html += '<div class="member-item" id="member-self"><div class="member-avatar" style="background:var(--whatsapp-green)">' + ((identity.displayName||'?')[0]).toUpperCase() + '</div><div class="member-info"><div class="member-name">' + escapeHtml(identity.displayName) + ' <span class="member-you-badge">você</span></div><div class="member-status online-dot">● online</div></div></div>';

  if (peers && peers.size > 0) {
    peers.forEach((pd, pid) => {
      const isMutedLocal = mutedPeers.has(pid);
      const safePid = pid.replace(/'/g, '');
      const safeName = escapeHtml(pd.displayName).replace(/'/g, '&#39;');
      html += '<div class="member-item" oncontextmenu="showMemberContextMenu(event,\'' + safePid + '\',\'' + safeName + '\')" onclick="showMemberContextMenu(event,\'' + safePid + '\',\'' + safeName + '\')"><div class="member-avatar">' + ((pd.displayName||'?')[0]).toUpperCase() + '</div><div class="member-info"><div class="member-name">' + escapeHtml(pd.displayName) + '</div><div class="member-status ' + (pd.inVoice ? 'voice-dot' : 'online-dot') + '">' + (pd.inVoice ? (pd.muted ? '🔇 voz' : '🎤 voz') : '● online') + '</div></div>' + (isMutedLocal ? '<span class="member-muted-badge">🔇</span>' : '') + '</div>';
    });
  }

  panel.innerHTML = html;
}

function showMemberContextMenu(e, peerId, displayName) {
  e.preventDefault();
  e.stopPropagation();

  const old = document.getElementById('memberContextMenu');
  if (old) old.remove();

  const isMutedLocal = mutedPeers.has(peerId);
  const menu = document.createElement('div');
  menu.id = 'memberContextMenu';
  menu.className = 'member-context-menu';
  const safePid = peerId.replace(/'/g, '');
  const safeName = displayName.replace(/'/g, '\\\'');
  menu.innerHTML = '<div class="context-menu-header">' + escapeHtml(displayName) + '</div><div class="context-menu-item" onclick="addFriendFromChannel(\'' + safePid + '\',\'' + safeName + '\')">➕ Adicionar como amigo</div><div class="context-menu-item" onclick="sendDMFromChannel(\'' + safePid + '\',\'' + safeName + '\')">💬 Mensagem privada</div><div class="context-menu-item" onclick="toggleMutePeer(\'' + safePid + '\')">' + (isMutedLocal ? '🔊 Desmutar' : '🔇 Mutar') + ' localmente</div>';

  document.body.appendChild(menu);

  const x = (e.clientX || (e.touches && e.touches[0] ? e.touches[0].clientX : 100));
  const y = (e.clientY || (e.touches && e.touches[0] ? e.touches[0].clientY : 100));
  menu.style.left = Math.min(x, window.innerWidth - 220) + 'px';
  menu.style.top = Math.min(y, window.innerHeight - 160) + 'px';

  setTimeout(() => {
    const closeMenu = (ev) => {
      if (!menu.contains(ev.target)) {
        menu.remove();
        document.removeEventListener('click', closeMenu);
        document.removeEventListener('touchstart', closeMenu);
      }
    };
    document.addEventListener('click', closeMenu);
    document.addEventListener('touchstart', closeMenu);
  }, 10);
}

function addFriendFromChannel(peerId, displayName) {
  const menu = document.getElementById('memberContextMenu');
  if (menu) menu.remove();
  showToast('Para adicionar ' + displayName + ', compartilhe sua chave pública com eles.');
  leaveChannelView();
  setTimeout(() => switchTab('friends'), 200);
}

function sendDMFromChannel(peerId, displayName) {
  const menu = document.getElementById('memberContextMenu');
  if (menu) menu.remove();
  if (typeof openChatWith === 'function') {
    leaveChannelView();
    setTimeout(() => openChatWith(peerId, displayName), 200);
  } else {
    showToast('Adicione ' + displayName + ' como amigo primeiro para enviar mensagem privada.');
  }
}

function toggleMutePeer(peerId) {
  const menu = document.getElementById('memberContextMenu');
  if (menu) menu.remove();
  if (mutedPeers.has(peerId)) {
    mutedPeers.delete(peerId);
    const sd = channelStreams.get(peerId);
    if (sd && sd.audioEl) sd.audioEl.volume = isDeafened ? 0 : speakerVolume;
    showToast('🔊 Áudio restaurado');
  } else {
    mutedPeers.add(peerId);
    const sd = channelStreams.get(peerId);
    if (sd && sd.audioEl) sd.audioEl.volume = 0;
    showToast('🔇 Usuário mutado localmente');
  }
  renderChannelMembers();
  updateVoiceUI();
}

// ============================================
// VOZ — JOIN/LEAVE/VOLUME
// ============================================
function updateChannelMemberCount() {
  if (!activeChannel) return;
  const count = (channelPeers.get(activeChannel) ? channelPeers.get(activeChannel).size : 0) + 1;
  const el = document.getElementById('channelViewMembers');
  if (el) el.textContent = count + ' membro(s) online';
}

function leaveChannelView() {
  if (inVoice) leaveVoice();
  if (discoveryInterval) clearInterval(discoveryInterval);
  if (channelHostPeer) { channelHostPeer.destroy(); channelHostPeer = null; }
  activeChannel = null;
  channelPendingFile = null;
  const menu = document.getElementById('memberContextMenu');
  if (menu) menu.remove();
  document.querySelector('.tabs').classList.remove('hidden');
  document.querySelector('.tab-content').classList.remove('hidden');
  document.getElementById('channelContainer').classList.add('hidden');
  renderChannelsList();
}

function leaveChannel() {
  const menu = document.getElementById('channelDropdown');
  if (menu) menu.classList.add('hidden');
  if (!activeChannel) return;
  showConfirm('🚪 Sair', 'Deseja sair do canal?', () => {
    myChannels = myChannels.filter(c => c.id !== activeChannel);
    saveChannels(); leaveChannelView();
  });
}

function toggleChannelMenu(e) {
  e.stopPropagation();
  const menu = document.getElementById('channelDropdown');
  if (menu) {
    menu.classList.toggle('hidden');
    const close = () => { menu.classList.add('hidden'); document.removeEventListener('click', close); };
    setTimeout(() => document.addEventListener('click', close), 10);
  }
}

async function copyChannelId() {
  if (!activeChannel) return;
  const menu = document.getElementById('channelDropdown');
  if (menu) menu.classList.add('hidden');
  try {
    await navigator.clipboard.writeText(activeChannel);
    showToast('📋 Chave copiada!');
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = activeChannel; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); ta.remove(); showToast('📋 Chave copiada!');
  }
}

async function toggleVoice() { if (inVoice) leaveVoice(); else await joinVoice(); }

async function joinVoice() {
  try {
    const rawStream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true } });
    audioContext = new (window.AudioContext || window.webkitAudioContext)();
    micSource = audioContext.createMediaStreamSource(rawStream);
    micGainNode = audioContext.createGain();
    micGainNode.gain.value = micVolume;
    micDest = audioContext.createMediaStreamDestination();
    micSource.connect(micGainNode);
    micGainNode.connect(micDest);
    localStream = micDest.stream;

    inVoice = true; isMuted = false;
    const peers = channelPeers.get(activeChannel);
    if (peers) peers.forEach(pd => {
      if (pd.conn && pd.conn.open) pd.conn.send({ type: 'channel-voice-join', channelId: activeChannel, displayName: identity.displayName, muted: isMuted });
      if (pd.inVoice) callPeer(pd.conn.peer);
    });
    updateVoiceUI();
  } catch(e) {
    console.error(e);
    showToast('Erro ao acessar microfone');
  }
}

function leaveVoice() {
  if (localStream) localStream.getTracks().forEach(t => t.stop());
  if (micSource) { try { micSource.disconnect(); } catch(e){} micSource = null; }
  if (micGainNode) { try { micGainNode.disconnect(); } catch(e){} micGainNode = null; }
  if (audioContext) { try { audioContext.close(); } catch(e){} audioContext = null; }
  micDest = null;

  const peers = channelPeers.get(activeChannel);
  if (peers) peers.forEach(pd => { if (pd.conn && pd.conn.open) pd.conn.send({ type: 'channel-voice-leave', channelId: activeChannel }); });
  inVoice = false; localStream = null;
  channelStreams.forEach(d => { if (d.audioEl) d.audioEl.remove(); });
  channelStreams.clear();
  updateVoiceUI();
}

function toggleMute() {
  isMuted = !isMuted;
  if (micGainNode) micGainNode.gain.value = isMuted ? 0 : micVolume;
  const peers = channelPeers.get(activeChannel);
  if (peers) peers.forEach(pd => { if (pd.conn && pd.conn.open) pd.conn.send({ type: 'channel-voice-mute', channelId: activeChannel, muted: isMuted }); });
  updateVoiceUI();
}

function toggleDeafen() {
  isDeafened = !isDeafened;
  channelStreams.forEach((d, pid) => {
    if (d.audioEl) d.audioEl.volume = isDeafened ? 0 : (mutedPeers.has(pid) ? 0 : speakerVolume);
  });
  updateVoiceUI();
}

function setSpeakerVolume(val) {
  speakerVolume = val / 100;
  if (!isDeafened) {
    channelStreams.forEach((d, pid) => {
      if (d.audioEl) d.audioEl.volume = mutedPeers.has(pid) ? 0 : speakerVolume;
    });
  }
  const label = document.getElementById('speakerVolumeLabel');
  if (label) label.textContent = Math.round(val) + '%';
}

function setMicVolume(val) {
  micVolume = val / 100;
  if (micGainNode && !isMuted) micGainNode.gain.value = micVolume;
  const label = document.getElementById('micVolumeLabel');
  if (label) label.textContent = Math.round(val) + '%';
}

function callPeer(peerId) {
  if (peer && localStream && inVoice) {
    const call = peer.call(peerId, localStream);
    if (call) {
      call.on('stream', s => addVoiceStream(peerId, s));
      call.on('error', e => console.error('Call error:', e));
    }
  }
}

function addVoiceStream(peerId, stream) {
  removeVoiceStream(peerId);
  const audio = document.createElement('audio');
  audio.srcObject = stream;
  audio.autoplay = true;
  audio.playsInline = true;
  audio.volume = isDeafened ? 0 : (mutedPeers.has(peerId) ? 0 : speakerVolume);
  channelStreams.set(peerId, { stream, audioEl: audio });
  document.body.appendChild(audio);
}

function removeVoiceStream(peerId) {
  const data = channelStreams.get(peerId);
  if (data && data.audioEl) data.audioEl.remove();
  channelStreams.delete(peerId);
}

// ============================================
// UI VOZ
// ============================================
function updateVoiceUI() {
  const joinBtn = document.getElementById('voiceJoinBtn');
  const muteBtn = document.getElementById('voiceMuteBtn');
  const deafenBtn = document.getElementById('voiceDeafenBtn');
  const usersDiv = document.getElementById('voiceUsers');
  const volumeControls = document.getElementById('voiceVolumeControls');
  if (!joinBtn || !usersDiv) return;

  joinBtn.textContent = inVoice ? '🔴 Sair da Voz' : '🎤 Entrar na Voz';
  joinBtn.className = inVoice ? 'voice-btn voice-btn-leave' : 'voice-btn voice-btn-join';
  muteBtn.classList.toggle('hidden', !inVoice);
  deafenBtn.classList.toggle('hidden', !inVoice);
  if (volumeControls) volumeControls.classList.toggle('hidden', !inVoice);

  muteBtn.textContent = isMuted ? '🔇 Desmutar' : '🎤 Mutar';
  muteBtn.className = 'voice-btn voice-btn-mute' + (isMuted ? ' muted' : '');
  deafenBtn.textContent = isDeafened ? '🔕 Desativar Surdo' : '🔊 Surdo';
  deafenBtn.className = 'voice-btn voice-btn-deafen' + (isDeafened ? ' deafened' : '');

  usersDiv.innerHTML = inVoice ? '<div class="voice-user ' + (isMuted ? 'voice-user-muted' : '') + '"><span class="voice-user-dot"></span> ' + escapeHtml(identity.displayName) + ' (você)</div>' : '';

  if (activeChannel) {
    const peers = channelPeers.get(activeChannel);
    if (peers) peers.forEach((pd, pid) => {
      if (pd.inVoice) {
        const isMutedLocal = mutedPeers.has(pid);
        usersDiv.innerHTML += '<div class="voice-user ' + (pd.muted || isMutedLocal ? 'voice-user-muted' : '') + ' ' + (channelStreams.has(pid) ? 'voice-user-speaking' : '') + '"><span class="voice-user-dot"></span> ' + escapeHtml(pd.displayName) + (isMutedLocal ? ' 🔇' : '') + '</div>';
      }
    });
  }

  renderChannelMembers();
}

// ============================================
// INTERCEPTORS
// ============================================
function setupVoiceAutoAnswer() {
  if (!peer) return;
  peer.on('call', (call) => {
    if (inVoice && localStream) {
      call.answer(localStream);
      call.on('stream', (remoteStream) => {
        addVoiceStream(call.peer, remoteStream);
        updateVoiceUI();
      });
    } else {
      call.answer();
      call.close();
    }
  });
}

const _origStartAppC = startApp;
startApp = async function() {
  await _origStartAppC();
  loadChannels();
  setTimeout(setupVoiceAutoAnswer, 1000);
};

const _origHandleConnC = handleConnection;
handleConnection = function(conn) {
  _origHandleConnC(conn);
  conn.on('data', (data) => {
    if (data.type === 'channel-announce') tryConnectPublicPeer(data.channelId, conn.peer);
    if (data.type === 'channel-join' && activeChannel === data.channelId) setupChannelConnection(data.channelId, conn.peer, conn);
  });
};

switchTab = function(tab) {
  if (!document.getElementById('chatContainer').classList.contains('hidden')) return;
  if (!document.getElementById('channelContainer').classList.contains('hidden')) return;
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  if (tab === 'friends') { document.querySelectorAll('.tab')[0].classList.add('active'); document.getElementById('friendsTab').classList.add('active'); loadFriends(); }
  else if (tab === 'chats') { document.querySelectorAll('.tab')[1].classList.add('active'); document.getElementById('chatsTab').classList.add('active'); loadConversations(); }
  else if (tab === 'channels') { document.querySelectorAll('.tab')[2].classList.add('active'); document.getElementById('channelsTab').classList.add('active'); loadChannels(); }
};