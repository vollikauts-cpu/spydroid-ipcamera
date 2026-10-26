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

const wss = new WebSocketServer({ server, path: '/signal' });

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Spydroid WebRTC Signaling'
  });
});

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const provided = url.searchParams.get('token') || '';

  const expectedHash = crypto.createHash('sha256')
    .update(AUTH_TOKEN).digest();
  const providedHash = crypto.createHash('sha256')
    .update(provided).digest();

  if (!crypto.timingSafeEqual(expectedHash, providedHash)) {
    ws.close(1008, 'Unauthorized');
    return;
  }

  console.log('WebSocket client connected');

  ws.on('message', (data) => {
    // Пока только проверяем получение сообщений.
    // Передачу SDP/ICE добавим после авторизации.
    console.log('Message received, bytes:', data.length);
  });

  ws.on('close', () => {
    console.log('WebSocket client disconnected');
  });
});
