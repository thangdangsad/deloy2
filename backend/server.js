'use strict';

const express = require("express");
const cors = require("cors");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const dotenv = require("dotenv");
const multer = require("multer");
const path = require("path");
const jwt = require("jsonwebtoken");
const { expressjwt } = require('express-jwt');
const fs = require("fs");
const axios = require("axios");

// --- SEQUELIZE ---
const db = require('./models');

// SIMPLE LOGGER
const logger = {
    info: (...args) => console.log('[INFO]', ...args),
    error: (...args) => console.error('[ERROR]', ...args),
    warn: (...args) => console.warn('[WARN]', ...args),
    debug: (...args) => console.log('[DEBUG]', ...args)
};

// ANTI-CLICKJACKING MIDDLEWARE
const { antiClickjacking, presets, detectIframeRequest, testAntiClickjacking } = require('./middleware/antiClickjacking');

// ADVANCED SECURITY MIDDLEWARE
const {
    helmetMiddleware,
    enforceHTTPS,
    additionalSecurityHeaders,
    rateLimiters,
    sanitizeData,
    preventXSS,
    preventHPP,
    detectSuspiciousActivity,
    requestLogger,
    firewallMiddleware,
    ipRateLimit
} = require('./middleware/security.middleware');

// CAPTCHA middleware
const { sessionMiddleware: captchaSession, generateCaptcha, verifyCaptcha } = require('./middleware/captcha.middleware');

// SESSION MANAGEMENT
const { sessionManager } = require('./middleware/session.middleware');

// Load .env
dotenv.config({ path: path.join(__dirname, '.env') });

const app = express();

/* ---------------- SECURITY MIDDLEWARES ---------------- */
app.use(helmetMiddleware);

if (process.env.NODE_ENV === 'production') {
    app.use(enforceHTTPS);
    app.use(additionalSecurityHeaders);
}

/* ---------------- CORS & BODY PARSERS ---------------- */
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
app.use(cors({
    origin: [FRONTEND_URL, 'http://localhost:3000', 'http://localhost:5000'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-ID', 'X-Client-IP'],
    exposedHeaders: ['X-Session-ID'],
    methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ---------------- SESSION (QUAN TRỌNG) ---------------- */
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 30, // 30 phút
        sameSite: 'lax',
    }
}));

/* ---------------- CAPTCHA SESSION ---------------- */
app.use(captchaSession);

/* ---------------- OTHER MIDDLEWARES ---------------- */
app.use(sessionManager);
app.use(firewallMiddleware);

app.use((req,res,next)=>{
    const skipPaths = ['/api/security','/api/bot-stats','/api/captcha','/api/home'];
    if(skipPaths.some(p=>req.path.startsWith(p))) return next();
    return ipRateLimit(100,60000)(req,res,next);
});

app.use(antiClickjacking(presets.dev));
app.use(detectIframeRequest);
app.use(testAntiClickjacking);

// Multer storage
const storage = multer.diskStorage({
    destination: (req,file,cb)=>{
        const uploadDir = path.join(__dirname,"uploads");
        if(!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir,{recursive:true});
        cb(null,"uploads/");
    },
    filename: (req,file,cb)=>cb(null, Date.now()+path.extname(file.originalname))
});
const upload = multer({ storage });

// Static files
app.use('/uploads', (req,res,next)=>{
    res.header('Access-Control-Allow-Origin','*');
    res.header('Access-Control-Allow-Methods','GET, OPTIONS');
    res.header('Access-Control-Allow-Headers','Content-Type');
    res.header('Cross-Origin-Resource-Policy','cross-origin');
    next();
}, express.static(path.join(__dirname,'uploads')));

app.use('/images', (req,res,next)=>{
    res.header('Access-Control-Allow-Origin','*');
    res.header('Access-Control-Allow-Methods','GET, OPTIONS');
    res.header('Access-Control-Allow-Headers','Content-Type');
    res.header('Cross-Origin-Resource-Policy','cross-origin');
    next();
}, express.static(path.join(__dirname,'uploads','blogs')));

// API data sanitization
app.use('/api', sanitizeData);
app.use('/api', preventXSS);
app.use('/api', preventHPP);
app.use('/api', requestLogger);
app.use('/api', detectSuspiciousActivity);

/* ---------------- PASSPORT SOCIAL LOGIN ---------------- */
app.use(passport.initialize());

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
}, async (accessToken,refreshToken,profile,done)=>{
    try{
        const email = profile.emails[0].value;
        const [user,created] = await db.User.findOrCreate({
            where:{ Email: email },
            defaults:{
                Username: profile.displayName.replace(/\s/g,'')+Date.now().toString().slice(-4),
                Password: 'provided_by_google',
                Role: 'user',
                FullName: profile.displayName,
                AvatarURL: profile.photos?.[0]?.value || null
            }
        });
        return done(null,user);
    }catch(err){
        return done(err,null);
    }
}));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: process.env.FACEBOOK_CALLBACK_URL,
    profileFields: ["id","displayName","photos","email"]
}, async (accessToken,refreshToken,profile,done)=>{
    try{
        const email = profile.emails?.[0]?.value || `${profile.id}@facebook-placeholder.com`;
        const [user,created] = await db.User.findOrCreate({
            where:{ Email: email },
            defaults:{
                Username: profile.displayName.replace(/\s/g,'')+Date.now().toString().slice(-4),
                Password:'provided_by_facebook',
                Role:'user',
                FullName: profile.displayName,
                AvatarURL: profile.photos?.[0]?.value || null
            }
        });
        return done(null,user);
    }catch(err){
        return done(err,null);
    }
}));

/* ---------------- IMPORT ROUTERS ---------------- */
const authRouter = require('./routes/user/auth');
// ... giữ nguyên tất cả routers như bạn có

/* ---------------- API ROUTER ---------------- */
const apiRouter = express.Router();

// CAPTCHA
apiRouter.get('/captcha', generateCaptcha);

// Auth routes
apiRouter.use('/auth', authRouter);

// ... giữ nguyên tất cả route user/admin/public khác

app.use('/api', apiRouter);

/* ---------------- ERROR HANDLER ---------------- */
app.use((err,req,res,next)=>{
    if(err && err.name==='UnauthorizedError') return res.status(401).json({ message:'Token không hợp lệ hoặc đã hết hạn.' });
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

/* ---------------- START SERVER ---------------- */
const PORT = process.env.PORT || 5000;

process.on('uncaughtException', (err)=>{
    console.error('❌ Uncaught Exception:', err);
});
process.on('unhandledRejection', (reason,promise)=>{
    console.error('❌ Unhandled Rejection at:', promise,'reason:', reason);
});

db.sequelize.authenticate()
    .then(()=>{
        console.log('✅ Kết nối CSDL thành công bằng Sequelize.');
        app.listen(PORT, ()=>{
            logger.info(`🚀 Backend đang chạy tại http://localhost:${PORT}`);
        });
    })
    .catch(err=>{
        console.error('❌ Kết nối CSDL thất bại:', err);
    });
