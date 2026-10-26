const express = require('express');
const { WebSocketServer, WebSocket } = require('ws');

const fs = require('fs');
const crypto = require('crypto');

const env = fs.readFileSync('.env', 'utf8');
const token = env.match(/^AUTH_TOKEN=(.+)$/m);

if (!token || !token[1].trim()) {
  throw new Error('AUTH_TOKEN is missing');
}

const AUTH_TOKEN = token[1].trim();
const app = express();
const path = require('path');

const {
  sessionMiddleware,
  verifyPassword,
  requireAuth
} = require('./auth');

app.use(express.json({ limit: '4kb' }));
app.use(sessionMiddleware);

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};

  if (username !== 'admin' || !verifyPassword(password)) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }

  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Session error' });

    req.session.authenticated = true;
    res.json({ success: true });
  });
});

app.post('/api/logout', requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('spydroid.sid');
    res.json({ success: true });
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ username: 'admin' });
});

app.get('/', (req, res) => {
  if (!req.session?.authenticated) {
    return res.redirect('/login.html');
  }
  res.sendFile(path.join(__dirname, '../web/index.html'));
});

app.get('/index.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, '../web/index.html'));
});

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../web/login.html'));
});
const PORT = 3000;
const HOST = '127.0.0.1';

const server = app.listen(PORT, HOST, () => {
  console.log(`Server running at http://${HOST}:${PORT}`);
});

const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://localhost');

  if (url.pathname !== '/signal') {
    socket.destroy();
    return;
  }

  sessionMiddleware(req, {}, (err) => {
    if (err) {
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit('connection', ws, req);
    });
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Spydroid WebRTC Signaling'
  });
});


const peers = {
  camera: null,
  viewer: null
};

function send(peer, message) {
  if (peer && peer.readyState === WebSocket.OPEN) {
    peer.send(JSON.stringify(message));
  }
}

wss.on('connection', (ws, req) => {
  // Сессия Express проверяется до обработки подключения.

  const url = new URL(req.url, 'http://localhost');
  const role = url.searchParams.get('role');
  if (!['camera', 'viewer'].includes(role)) {
    ws.close(1008, 'Invalid role');
    return;
  }

  if (role === 'camera') {
    const provided = req.headers['x-device-token'] || '';
    const expected = crypto.createHash('sha256')
      .update(AUTH_TOKEN).digest();
    const received = crypto.createHash('sha256')
      .update(String(provided)).digest();

    if (!crypto.timingSafeEqual(expected, received)) {
      ws.close(1008, 'Unauthorized');
      return;
    }
  }

  if (role === 'viewer') {
    if (!req.session?.authenticated) {
      ws.close(1008, 'Login required');
      return;
    }
  }

  if (peers[role]) {
    ws.close(1008, 'Role already connected');
    return;
  }

  peers[role] = ws;
  console.log(role + ' connected');

  send(peers.viewer, {
    type: 'camera-status',
    online: !!peers.camera
  });

  ws.on('message', data => {
    if (data.length > 65536) {
      ws.close(1009, 'Message too large');
      return;
    }

    let message;
    try {
      message = JSON.parse(data.toString());
    } catch {
      return;
    }

    if (!['offer', 'answer', 'candidate'].includes(message.type)) {
      return;
    }

    const destination = role === 'camera'
      ? peers.viewer
      : peers.camera;

    send(destination, message);
  });

  ws.on('close', () => {
    if (peers[role] === ws) {
      peers[role] = null;
    }

    send(peers.viewer, {
      type: 'camera-status',
      online: !!peers.camera
    });

    console.log(role + ' disconnected');
  });
});
