const fs = require('fs');
const crypto = require('crypto');
const session = require('express-session');

const admin = JSON.parse(
  fs.readFileSync(__dirname + '/.admin', 'utf8')
);

const sessionMiddleware = session({
  name: 'spydroid.sid',
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: false,
    maxAge: 3600000
  }
});

function verifyPassword(password) {
  if (typeof password !== 'string' || password.length > 1024) {
    return false;
  }

  const candidate = crypto.scryptSync(password, admin.salt, 64);
  const expected = Buffer.from(admin.hash, 'hex');

  return candidate.length === expected.length &&
    crypto.timingSafeEqual(candidate, expected);
}

function requireAuth(req, res, next) {
  if (req.session?.authenticated === true) {
    return next();
  }

  res.status(401).json({ error: 'Unauthorized' });
}

module.exports = {
  sessionMiddleware,
  verifyPassword,
  requireAuth
};
