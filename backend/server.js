require('dotenv').config();
const express = require('express');
const app = express();
const port = process.env.PORT || 3001;
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

// ==================== MongoDB Connection ====================
const connectDB = require('./config/db');
const User = require('./models/User');
const Link = require('./models/Link');
const Stats = require('./models/Stats');
const PopupSettings = require('./models/PopupSettings');
const RenewalRequest = require('./models/RenewalRequest');
const Pricing = require('./models/Pricing');
const Session = require('./models/Session');
const AdminLog = require('./models/AdminLog');
const LoginAttempt = require('./models/LoginAttempt');
const TwoFactorAuth = require('./models/TwoFactorAuth');
const BlockedDevice = require('./models/BlockedDevice');
const OTPVerification = require('./models/OTPVerification');
const ShortLink = require('./models/ShortLink');
const ShortLinkClick = require('./models/ShortLinkClick');

// Security Module
const Security = require('./config/security');

// Connect to MongoDB
connectDB();

// ==================== Environment Variables ====================
const ADMIN_PASSCODE = process.env.ADMIN_PASSCODE || '951753';
const MAX_LOGIN_ATTEMPTS = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
const LOCKOUT_TIME = parseInt(process.env.LOCKOUT_TIME) || 48;
const SESSION_TIMEOUT = parseInt(process.env.SESSION_TIMEOUT) || 60;
const IP_WHITELIST = process.env.IP_WHITELIST || '0.0.0.0/0';
const ENABLE_2FA = process.env.ENABLE_2FA === 'true';

// Email Config
const EMAIL_USER = process.env.EMAIL_USER || '';
const EMAIL_PASS = process.env.EMAIL_PASS || '';

let transporter = null;
if (EMAIL_USER && EMAIL_PASS) {
    transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: EMAIL_USER, pass: EMAIL_PASS }
    });
}

// ==================== Database Initialization ====================
async function initializeDatabase() {
    try {
        const adminExists = await User.findOne();
        if (!adminExists) {
            const hashedPasscode = bcrypt.hashSync(ADMIN_PASSCODE, 10);
            await User.create({
                passcode: hashedPasscode,
                theme: 'dark',
                email: process.env.ADMIN_EMAIL || '',
                phone: process.env.ADMIN_PHONE || '',
                secretKey: 'admin@2024'
            });
            console.log('✅ Admin user created with default secretKey: admin@2024');
        } else if (!adminExists.secretKey) {
            adminExists.secretKey = 'admin@2024';
            await adminExists.save();
        }

        const statsExists = await Stats.findOne();
        if (!statsExists) await Stats.create({});

        const popupExists = await PopupSettings.findOne();
        if (!popupExists) {
            await PopupSettings.create({
                image: null,
                title: '🎁 Claim Your Reward',
                buttonText: 'Claim Now',
                subtitle: 'Tap below to unlock your reward'
            });
        }

        const pricingExists = await Pricing.findOne();
        if (!pricingExists) {
            await Pricing.create({
                pricing: {
                    '3days': 50, '7days': 100, '15days': 200, '1month': 500,
                    '3months': 1200, '6months': 2000, '12months': 3500
                },
                paymentSettings: {
                    method: 'UPI',
                    details: { upiId: 'admin@upi', qrCode: null, text: '' }
                },
                whatsappNumber: '916372923348'
            });
        }

        await Session.deleteMany({ expiresAt: { $lt: new Date() } });
    } catch (error) {
        console.error('Database initialization error:', error);
    }
}
initializeDatabase();

// ==================== Security Headers ====================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
            imgSrc: ["'self'", "data:", "https:", "http:"],
            connectSrc: ["'self'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
            frameSrc: ["'self'", "https://www.youtube.com", "*"],
            mediaSrc: ["'self'", "https:", "http:", "*"],
            objectSrc: ["'none'"]
        }
    },
    frameguard: { action: 'deny' },
    noSniff: true,
    xssFilter: true,
    hidePoweredBy: true
}));

app.set('trust proxy', 1);

app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

// Protect sensitive backend files from direct download
app.use((req, res, next) => {
    const blocked = ['.env', '.log', '.json', '.md'];
    const p = req.path.toLowerCase();
    if (p === '/manifest.json') return next();
    for (let ext of blocked) {
        if (p.endsWith(ext)) return res.status(403).send('Forbidden');
    }
    next();
});

// Rate limiting
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 600,
    message: { error: 'Too many requests, please try again later.' }
});
app.use('/api', globalLimiter);

const deviceAuthLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: MAX_LOGIN_ATTEMPTS,
    keyGenerator: (req) => {
        const ip = req.ip || req.connection.remoteAddress || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';
        return crypto.createHash('sha256').update(ip + userAgent).digest('hex');
    },
    message: { error: 'Too many login attempts. Please wait 15 minutes.' }
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// ==================== JWT & Token Helpers ====================
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRY = '7d';

function generateToken(userId) {
    return jwt.sign({ id: userId, role: 'admin', timestamp: Date.now() }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
}

function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (e) {
        return null;
    }
}

function generateCSRFToken() {
    return crypto.randomBytes(32).toString('hex');
}

function getDeviceId(req) {
    const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';
    const fingerprint = crypto.createHash('sha256').update(ip + userAgent).digest('hex');
    return { ip, userAgent, fingerprint };
}

function getDeviceKey(fingerprint, ip) {
    return crypto.createHash('sha256').update(fingerprint + '|' + ip).digest('hex');
}

async function isDeviceBlocked(req) {
    const { fingerprint, ip } = getDeviceId(req);
    const deviceKey = getDeviceKey(fingerprint, ip);
    const admin = await User.findOne();
    if (admin && fingerprint === admin.fingerprint && ip === admin.ip) return null;
    return await BlockedDevice.findOne({
        deviceKey,
        $or: [{ blockedUntil: { $gt: new Date() } }, { isPermanent: true }]
    });
}

async function blockDevice(req, reason = 'Too many failed attempts', durationMinutes = 48 * 60) {
    const { fingerprint, ip } = getDeviceId(req);
    const deviceKey = getDeviceKey(fingerprint, ip);
    const admin = await User.findOne();
    if (admin && fingerprint === admin.fingerprint && ip === admin.ip) return null;

    let record = await BlockedDevice.findOne({ deviceKey });
    if (record) {
        record.attempts = (record.attempts || 0) + 1;
        record.lastAttempt = new Date();
        record.blockedUntil = new Date(Date.now() + durationMinutes * 60 * 1000);
        record.reason = reason;
        await record.save();
        return record;
    } else {
        const newRecord = new BlockedDevice({
            deviceKey, fingerprint, ip,
            attempts: 1, reason,
            blockedUntil: new Date(Date.now() + durationMinutes * 60 * 1000),
            lastAttempt: new Date()
        });
        await newRecord.save();
        return newRecord;
    }
}

async function createSession(token, userId, csrfToken, ip, userAgent) {
    const session = new Session({
        token, userId, csrfToken, ip, userAgent,
        expiresAt: new Date(Date.now() + SESSION_TIMEOUT * 60 * 1000),
        lastActivity: new Date(),
        isActive: true
    });
    await session.save();
    return session;
}

async function validateSession(token) {
    const session = await Session.findOne({ token, isActive: true, expiresAt: { $gt: new Date() } });
    if (!session) return null;
    session.lastActivity = new Date();
    await session.save();
    return session;
}

// Auth Middleware
async function authMiddleware(req, res, next) {
    const blocked = await isDeviceBlocked(req);
    if (blocked) return res.status(403).json({ error: 'Device is blocked.' });

    const token = req.cookies?.adminToken;
    const csrfToken = req.headers['x-csrf-token'];

    if (!token) return res.status(401).json({ error: 'Authentication required' });
    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid or expired token' });

    const session = await validateSession(token);
    if (!session) {
        res.clearCookie('adminToken');
        return res.status(401).json({ error: 'Session expired' });
    }

    if (csrfToken && csrfToken !== session.csrfToken) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    req.user = decoded;
    req.session = session;
    next();
}

// ==================== PUBLIC APIS ====================
app.get('/api/whatsapp-number', async (req, res) => {
    try {
        const pricing = await Pricing.findOne();
        res.json({ number: pricing?.whatsappNumber || '916372923348' });
    } catch (e) {
        res.json({ number: '916372923348' });
    }
});

app.get('/api/pricing', async (req, res) => {
    try {
        const pricingDoc = await Pricing.findOne();
        res.json({
            pricing: pricingDoc?.pricing || {},
            paymentSettings: pricingDoc?.paymentSettings || { method: 'UPI', details: { upiId: 'admin@upi' } },
            whatsappNumber: pricingDoc?.whatsappNumber || '916372923348'
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch pricing' });
    }
});

app.get('/api/link/:id', async (req, res) => {
    try {
        const link = await Link.findOne({ id: req.params.id });
        if (!link) return res.status(404).json({ error: 'not_found', message: 'Link not found' });
        if (link.status !== 'active') {
            return res.status(403).json({ error: link.status, message: `Link is ${link.status}` });
        }
        if (link.expiryDate && new Date() > new Date(link.expiryDate)) {
            return res.status(403).json({ error: 'expired', message: 'Link expired' });
        }

        const { fingerprint } = getDeviceId(req);
        const today = new Date().toISOString().split('T')[0];
        let stats = await Stats.findOne();
        if (!stats) stats = await Stats.create({});

        const uniqueKey = fingerprint + '_' + today;
        const uniqueVisitors = stats.uniqueVisitors || new Map();
        if (!uniqueVisitors.has(uniqueKey) || (Date.now() - uniqueVisitors.get(uniqueKey) > 48 * 60 * 60 * 1000)) {
            uniqueVisitors.set(uniqueKey, Date.now());
            stats.totalVisitors = (stats.totalVisitors || 0) + 1;
            stats.dailyVisitors.set(today, (stats.dailyVisitors.get(today) || 0) + 1);
            link.visits = (link.visits || 0) + 1;
            link.dailyVisits.set(today, (link.dailyVisits.get(today) || 0) + 1);
            await link.save();
            await stats.save();
        }

        res.json({
            id: link.id,
            video: link.video,
            claim: link.claim,
            buttonText: link.buttonText,
            headline: link.headline,
            status: link.status,
            popupSettings: link.popupSettings
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch link' });
    }
});

app.post('/api/track-claim/:linkId', async (req, res) => {
    try {
        const link = await Link.findOne({ id: req.params.linkId });
        if (!link) return res.status(404).json({ error: 'Link not found' });

        const { fingerprint } = getDeviceId(req);
        const today = new Date().toISOString().split('T')[0];
        let stats = await Stats.findOne();
        if (!stats) stats = await Stats.create({});

        const uniqueKey = fingerprint + '_' + today;
        const uniqueClaims = stats.uniqueClaims || new Map();
        if (!uniqueClaims.has(uniqueKey) || (Date.now() - uniqueClaims.get(uniqueKey) > 48 * 60 * 60 * 1000)) {
            uniqueClaims.set(uniqueKey, Date.now());
            stats.totalClaims = (stats.totalClaims || 0) + 1;
            stats.dailyClaims.set(today, (stats.dailyClaims.get(today) || 0) + 1);
            link.claims = (link.claims || 0) + 1;
            link.dailyClaims.set(today, (link.dailyClaims.get(today) || 0) + 1);
            await link.save();
            await stats.save();
        }
        res.json({ success: true, claims: stats.totalClaims || 0 });
    } catch (error) {
        res.status(500).json({ error: 'Failed to track claim' });
    }
});

app.get('/api/visit-stats/:linkId', async (req, res) => {
    try {
        const link = await Link.findOne({ $or: [{ id: req.params.linkId }, { dashboardId: req.params.linkId }] });
        if (!link) return res.status(404).json({ error: 'Link not found' });

        const today = new Date().toISOString().split('T')[0];
        res.json({
            linkId: link.id,
            name: link.name,
            totalVisits: link.visits || 0,
            totalClaims: link.claims || 0,
            todayVisits: link.dailyVisits?.get(today) || 0,
            todayClaims: link.dailyClaims?.get(today) || 0,
            status: link.status,
            expiryDate: link.expiryDate || null
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

app.get('/api/settings', async (req, res) => {
    try {
        const admin = await User.findOne();
        const popupSettings = await PopupSettings.findOne();
        res.json({
            theme: admin?.theme || 'dark',
            background: popupSettings?.image || null,
            popupSettings: popupSettings || {}
        });
    } catch (error) {
        res.status(500).json({ error: 'Settings error' });
    }
});

app.get('/api/admin/public-secret-key', async (req, res) => {
    try {
        const admin = await User.findOne();
        res.json({ secretKey: admin?.secretKey || 'admin@2024' });
    } catch (e) {
        res.json({ secretKey: 'admin@2024' });
    }
});

// ✅ SMART VERIFY KEY: Case-insensitive, accepts admin@2024 OR 951753 passcode
app.post('/api/admin/verify-secret-key', async (req, res) => {
    try {
        const rawKey = (req.body?.key || '').trim();
        const lowerKey = rawKey.toLowerCase();

        let dbSecret = 'admin@2024';
        try {
            const admin = await User.findOne();
            if (admin && admin.secretKey) {
                dbSecret = admin.secretKey.toLowerCase();
            }
        } catch (e) {}

        if (lowerKey === dbSecret || lowerKey === 'admin@2024' || rawKey === '951753' || rawKey === ADMIN_PASSCODE) {
            res.cookie('gatewayPassed', 'true', { maxAge: 10 * 60 * 1000, httpOnly: false });
            return res.json({ success: true, redirect: '/admin/login.html' });
        }

        return res.json({ success: false, error: 'Invalid secret key' });
    } catch (e) {
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

// Admin Login
app.post('/api/admin/login', deviceAuthLimiter, async (req, res) => {
    try {
        const { passcode } = req.body;
        const { ip, userAgent, fingerprint } = getDeviceId(req);

        if (!passcode) return res.status(400).json({ error: 'Passcode required' });
        const admin = await User.findOne();
        if (!admin) return res.status(500).json({ error: 'Admin not found' });

        const isValid = bcrypt.compareSync(passcode, admin.passcode);
        if (!isValid) {
            await blockDevice(req, 'Invalid passcode attempt', 120);
            return res.status(401).json({ error: 'Invalid passcode' });
        }

        admin.fingerprint = fingerprint;
        admin.ip = ip;
        await admin.save();

        const jwtToken = generateToken('admin');
        const csrfToken = generateCSRFToken();
        await createSession(jwtToken, 'admin', csrfToken, ip, userAgent);

        res.cookie('adminToken', jwtToken, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({ success: true, csrfToken, step: 'complete' });
    } catch (e) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// Admin Links API
app.get('/api/links', authMiddleware, async (req, res) => {
    try {
        const links = await Link.find().sort({ created: -1 });
        res.json(links);
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch links' });
    }
});

app.post('/api/links', authMiddleware, async (req, res) => {
    try {
        const { name, video, claim, headline } = req.body;
        if (!name) return res.status(400).json({ error: 'Name required' });

        const newLink = new Link({
            id: 'link_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex'),
            name: name.substring(0, 100),
            video: video || 'https://youtu.be/dQw4w9WgXcQ',
            claim: claim || '#',
            headline: headline || '🎬 Watch Video',
            status: 'active'
        });
        await newLink.save();
        res.json(newLink);
    } catch (e) {
        res.status(500).json({ error: 'Failed to create link' });
    }
});

app.delete('/api/links/:id', authMiddleware, async (req, res) => {
    try {
        await Link.findOneAndDelete({ id: req.params.id });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Failed to delete' });
    }
});

app.get('/api/all-stats', authMiddleware, async (req, res) => {
    try {
        const links = await Link.find();
        const stats = await Stats.findOne();
        res.json({
            global: {
                totalVisitors: stats?.totalVisitors || 0,
                totalClaims: stats?.totalClaims || 0
            },
            links
        });
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

app.post('/api/admin/logout', authMiddleware, async (req, res) => {
    try {
        const token = req.cookies?.adminToken;
        if (token) await Session.findOneAndUpdate({ token }, { isActive: false });
        res.clearCookie('adminToken');
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Logout failed' });
    }
});

// ==================== UNIVERSAL FILE RESOLVER ====================
// Automatically finds file whether in root / or admin / or backend /
function sendAppFile(res, fileName) {
    const candidates = [
        path.join(__dirname, '..', fileName),
        path.join(__dirname, '..', 'admin', fileName),
        path.join(__dirname, fileName),
        path.join(__dirname, 'admin', fileName)
    ];

    for (const p of candidates) {
        if (fs.existsSync(p)) {
            return res.sendFile(p);
        }
    }

    const base = path.basename(fileName);
    const rootBase = path.join(__dirname, '..', base);
    if (fs.existsSync(rootBase)) {
        return res.sendFile(rootBase);
    }

    res.status(404).send(`File ${fileName} not found on server.`);
}

// ==================== PAGE ROUTES ====================
app.get('/', (req, res) => res.redirect('/admin/secret-gateway'));

app.get('/admin/secret-gateway', (req, res) => {
    sendAppFile(res, 'secret-gateway.html');
});

// Direct Login Page Access (No Referer Check to prevent infinite redirect loops)
app.get('/admin/login.html', (req, res) => {
    sendAppFile(res, 'login.html');
});

// Admin Dashboard Access
app.get(['/admin/index.html', '/admin', '/admin/668379d1.html'], (req, res) => {
    const token = req.cookies?.adminToken;
    if (!token || !verifyToken(token)) {
        return res.redirect('/admin/login.html');
    }
    sendAppFile(res, '668379d1.html');
});

app.get('/uid', (req, res) => {
    sendAppFile(res, 'uid-checker.html');
});

app.get('/v/:id', (req, res) => {
    sendAppFile(res, 'video-lock.html');
});

app.get('/user-dashboard/:id?', (req, res) => {
    sendAppFile(res, 'user-dashboard.html');
});

app.get('/manifest.json', (req, res) => {
    sendAppFile(res, 'manifest.json');
});

app.get('/sw.js', (req, res) => {
    sendAppFile(res, 'sw.js');
});

// ==================== START SERVER ====================
app.listen(port, '0.0.0.0', () => {
    console.log(`🚀 Secure Server running on port ${port}`);
});
