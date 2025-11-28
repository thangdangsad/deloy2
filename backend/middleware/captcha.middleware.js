// FILE: session.middleware.js
// Purpose: single session middleware to be used across the whole app.
// Usage: const { sessionManager } = require('./middleware/session.middleware');
//        app.use(sessionManager);

const session = require('express-session');
const RedisStore = require('connect-redis').default;
const redis = require('redis');

// Create Redis client only if REDIS_URL provided. Otherwise fallback to in-memory store (not for production).
let redisClient;
let redisStore;
if (process.env.REDIS_URL) {
  redisClient = redis.createClient({ url: process.env.REDIS_URL });
  redisClient.connect().catch((err) => console.error('Redis connect error', err));
  redisStore = new RedisStore({ client: redisClient });
}

// IMPORTANT: configure these env vars appropriately in production
const SESSION_NAME = process.env.SESSION_NAME || 'sid';
const SESSION_SECRET = process.env.SESSION_SECRET || (process.env.JWT_SECRET || 'dev_session_secret');
const SESSION_MAX_AGE = process.env.SESSION_MAX_AGE ? parseInt(process.env.SESSION_MAX_AGE, 10) : 30 * 60 * 1000; // 30 minutes

// Exported middleware
const sessionManager = session({
  name: SESSION_NAME,
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false, // do not create session until something stored
  store: redisStore || undefined, // use redis in production; undefined uses default MemoryStore (not for prod)
  cookie: {
    httpOnly: true,
    secure: (process.env.NODE_ENV === 'production'), // true in production (HTTPS)
    sameSite: 'none', // Allow cross-site cookies (required for cross-origin frontends). Set to 'lax' or 'strict' if same origin.
    maxAge: SESSION_MAX_AGE,
  },
});

module.exports = { sessionManager };


// ==================================================================
// FILE: captcha.middleware.js
// Purpose: generate and verify CAPTCHA. This file DOES NOT create its own session middleware.
// It expects the main server to apply the single sessionManager (above) before the /api routes.
// Usage: const { generateCaptcha, verifyCaptcha } = require('./middleware/captcha.middleware');
//        app.get('/api/captcha', generateCaptcha);
//        app.post('/api/auth/login', verifyCaptcha, loginHandler);

const svgCaptcha = require('svg-captcha');

// Configuration options
const CAPTCHA_OPTIONS = {
  size: 6,
  noise: 3,
  color: true,
  background: '#f0f0f0',
  width: 200,
  height: 80,
  charPreset: '0123456789abcdefghijklmnopqrstuvwxyz',
};

// Generate CAPTCHA and store the text in req.session.captcha (lowercased)
function generateCaptcha(req, res) {
  try {
    // Ensure session exists. If session middleware uses saveUninitialized:false then session will be created when we write to it.
    const captcha = svgCaptcha.create(CAPTCHA_OPTIONS);

    // Store lowercase text in session with a timestamp for expiration logic
    if (!req.session) {
      // Defensive: if session middleware not applied, return error
      console.error('Session middleware not found. Ensure sessionManager is applied before captcha routes.');
      return res.status(500).json({ success: false, message: 'Server misconfiguration: session not available' });
    }

    req.session.captcha = captcha.text.toLowerCase();
    req.session.captchaCreatedAt = Date.now();

    // Optional: save session immediately so cookie is set in the response
    req.session.save((err) => {
      if (err) console.error('Failed to save session after setting captcha:', err);

      // Send SVG
      res.type('svg');
      res.status(200).send(captcha.data);

      console.log('🔐 Generated CAPTCHA:', captcha.text, 'Session ID:', req.sessionID);
    });
  } catch (error) {
    console.error('❌ Error generating CAPTCHA:', error);
    res.status(500).json({ success: false, message: 'Failed to generate CAPTCHA' });
  }
}

// Verify CAPTCHA middleware: expects body { captcha }
function verifyCaptcha(req, res, next) {
  try {
    const provided = (req.body?.captcha || '').toString();

    // Defensive checks
    if (!req.session) {
      console.warn('verifyCaptcha: session missing');
      return res.status(400).json({ success: false, errors: [{ msg: 'Session không tồn tại. Vui lòng làm mới trang và thử lại.' }] });
    }

    const expected = req.session.captcha;

    console.log('🔍 Verifying CAPTCHA:', { provided, expected, sessionID: req.sessionID, hasSession: !!req.session });

    if (!provided) {
      return res.status(400).json({ success: false, errors: [{ msg: 'Vui lòng nhập mã CAPTCHA' }] });
    }

    if (!expected) {
      return res.status(400).json({ success: false, errors: [{ msg: 'CAPTCHA đã hết hạn, vui lòng tải lại' }] });
    }

    // Optional expiration check (e.g., 5 minutes)
    const createdAt = req.session.captchaCreatedAt || 0;
    const EXPIRE_MS = process.env.CAPTCHA_EXPIRE_MS ? parseInt(process.env.CAPTCHA_EXPIRE_MS, 10) : 5 * 60 * 1000;
    if (Date.now() - createdAt > EXPIRE_MS) {
      // cleanup
      delete req.session.captcha;
      delete req.session.captchaCreatedAt;
      return res.status(400).json({ success: false, errors: [{ msg: 'CAPTCHA đã hết hạn, vui lòng tải lại' }] });
    }

    if (provided.toLowerCase() !== expected.toLowerCase()) {
      return res.status(400).json({ success: false, errors: [{ msg: 'Mã CAPTCHA không đúng' }] });
    }

    // One-time use: delete from session
    delete req.session.captcha;
    delete req.session.captchaCreatedAt;

    // Save and continue
    req.session.save((err) => {
      if (err) console.error('Failed to save session after deleting captcha:', err);
      console.log('✅ CAPTCHA verified successfully for session', req.sessionID);
      next();
    });
  } catch (error) {
    console.error('❌ Error verifying CAPTCHA:', error);
    res.status(500).json({ success: false, errors: [{ msg: 'Lỗi xác thực CAPTCHA' }] });
  }
}

module.exports = {
  generateCaptcha,
  verifyCaptcha,
};
