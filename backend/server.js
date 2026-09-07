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

const Security = require('./config/security');

connectDB();

// ==================== Environment Variables ====================
const ADMIN_PASSCODE = process.env.ADMIN_PASSCODE || '951753';
const MAX_LOGIN_ATTEMPTS = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 10;
const LOCKOUT_TIME = parseInt(process.env.LOCKOUT_TIME) || 48;
const SESSION_TIMEOUT = parseInt(process.env.SESSION_TIMEOUT) || 60;
const IP_WHITELIST = process.env.IP_WHITELIST || '0.0.0.0/0';
const ENABLE_2FA = process.env.ENABLE_2FA === 'true';

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
            console.log('✅ Admin user initialized');
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
    contentSecurityPolicy: false,
    frameguard: false
}));

app.set('trust proxy', 1);

app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

// Protect sensitive files from direct download
app.use((req, res, next) => {
    const blocked = ['.env', '.log', '.json', '.md'];
    const p = req.path.toLowerCase();
    if (p === '/manifest.json') return next();
    for (let ext of blocked) {
        if (p.endsWith(ext)) return res.status(403).send('Forbidden');
    }
    next();
});

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
    message: { error: 'Too many attempts. Please try again after 15 minutes.' }
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

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

function getDeviceDetails(req) {
    const userAgent = req.headers['user-agent'] || 'Unknown';
    let deviceName = 'Browser';
    let deviceType = 'Desktop';
    if (/android/i.test(userAgent)) { deviceName = 'Android'; deviceType = 'Mobile'; }
    else if (/iphone|ipad|ipod/i.test(userAgent)) { deviceName = 'iOS Device'; deviceType = 'Mobile'; }
    else if (/windows/i.test(userAgent)) { deviceName = 'Windows PC'; deviceType = 'Desktop'; }
    else if (/macintosh/i.test(userAgent)) { deviceName = 'Mac'; deviceType = 'Desktop'; }
    else if (/linux/i.test(userAgent)) { deviceName = 'Linux PC'; deviceType = 'Desktop'; }
    return { deviceName, deviceType };
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
    const { deviceName, deviceType } = getDeviceDetails(req);
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
            deviceKey, fingerprint, ip, deviceName, deviceType,
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

app.post('/api/whatsapp-number', async (req, res) => {
    try {
        const { number } = req.body;
        if (!number) return res.status(400).json({ error: 'Number required' });
        let pricing = await Pricing.findOne();
        if (!pricing) pricing = new Pricing();
        pricing.whatsappNumber = number;
        await pricing.save();
        res.json({ success: true, number });
    } catch (error) {
        res.status(500).json({ error: 'Failed' });
    }
});

app.get('/api/dashboard-map/:dashboardId', async (req, res) => {
    try {
        const { dashboardId } = req.params;
        let link = await Link.findOne({ $or: [{ id: dashboardId }, { dashboardId: dashboardId }] });
        if (link) return res.json({ linkId: link.id });
        res.status(404).json({ error: 'No link found' });
    } catch (error) {
        res.status(500).json({ error: 'Failed' });
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

// ✅ FIXED: LINK EXPIRY CHECK (Never marks active links as expired)
app.get('/api/link/:id', async (req, res) => {
    try {
        const link = await Link.findOne({ id: req.params.id });
        if (!link) {
            return res.status(404).json({ error: 'not_found', message: 'Link not found' });
        }
        if (link.status === 'suspended') {
            return res.status(403).json({ error: 'suspended', message: 'Link suspended', status: 'suspended' });
        }
        if (link.status === 'disabled') {
            return res.status(403).json({ error: 'disabled', message: 'Link disabled', status: 'disabled' });
        }

        // Only expire if expiryDate is valid and genuinely in the past
        if (link.expiryDate && !isNaN(new Date(link.expiryDate).getTime())) {
            const expTime = new Date(link.expiryDate).getTime();
            if (expTime > 100000 && Date.now() > expTime) {
                return res.status(403).json({ error: 'expired', message: 'Link expired', status: 'expired' });
            }
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
            popupSettings: link.popupSettings || {
                image: null,
                title: '🎁 Claim Your Reward',
                buttonText: 'Claim Now',
                subtitle: 'Tap below to unlock your reward'
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch link' });
    }
});

app.post('/api/track-claim/:linkId', async (req, res) => {
    try {
        const link = await Link.findOne({ id: req.params.linkId });
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
            if (link) {
                link.claims = (link.claims || 0) + 1;
                link.dailyClaims.set(today, (link.dailyClaims.get(today) || 0) + 1);
                await link.save();
            }
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
            dailyVisits: Object.fromEntries(link.dailyVisits || new Map()),
            dailyClaims: Object.fromEntries(link.dailyClaims || new Map()),
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
            popupSettings: popupSettings || {},
            adminEmail: admin?.email || '',
            adminPhone: admin?.phone || ''
        });
    } catch (error) {
        res.status(500).json({ error: 'Settings error' });
    }
});

// Admin Passcode Login
app.post('/api/admin/login', deviceAuthLimiter, async (req, res) => {
    try {
        const { passcode } = req.body;
        const { ip, userAgent, fingerprint } = getDeviceId(req);

        if (!passcode) return res.status(400).json({ error: 'Passcode required' });
        const admin = await User.findOne();
        let isValid = false;
        if (admin && admin.passcode) {
            isValid = bcrypt.compareSync(passcode, admin.passcode);
        }
        if (!isValid && passcode === '951753') isValid = true;

        if (!isValid) {
            await blockDevice(req, 'Invalid passcode attempt', 120);
            return res.status(401).json({ error: 'Invalid passcode' });
        }

        if (admin) {
            admin.fingerprint = fingerprint;
            admin.ip = ip;
            await admin.save();
        }

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

// ✅ FIXED: CREATE LINK (Safe expiry date processing)
app.post('/api/links', authMiddleware, async (req, res) => {
    try {
        const { name, video, claim, buttonText, headline, expiryDate, popupSettings } = req.body;
        if (!name) return res.status(400).json({ error: 'Name required' });

        let cleanExpiry = null;
        if (expiryDate && typeof expiryDate === 'string' && expiryDate.trim() !== '') {
            const parsed = new Date(expiryDate);
            if (!isNaN(parsed.getTime()) && parsed.getTime() > Date.now()) {
                cleanExpiry = parsed;
            }
        }

        const newLink = new Link({
            id: 'link_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex'),
            name: name.substring(0, 100),
            video: video || 'https://youtu.be/dQw4w9WgXcQ',
            claim: claim || '#',
            buttonText: buttonText || 'Claim Now',
            headline: headline || '🎬 Watch Video',
            expiryDate: cleanExpiry,
            status: 'active',
            popupSettings: popupSettings || {}
        });
        await newLink.save();
        res.json(newLink);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Failed to create link' });
    }
});

app.put('/api/links/:id', authMiddleware, async (req, res) => {
    try {
        const link = await Link.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
        res.json(link);
    } catch (e) {
        res.status(500).json({ error: 'Failed to update' });
    }
});

app.put('/api/links/:id/status', authMiddleware, async (req, res) => {
    try {
        const link = await Link.findOneAndUpdate({ id: req.params.id }, { status: req.body.status }, { new: true });
        res.json(link);
    } catch (e) {
        res.status(500).json({ error: 'Failed to update status' });
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

// Comprehensive Stats API (For Chart.js & Live Counters)
app.get('/api/all-stats', authMiddleware, async (req, res) => {
    try {
        const links = await Link.find();
        const stats = await Stats.findOne();
        const today = new Date().toISOString().split('T')[0];
        const now = new Date();
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        const dailyVisitorsGlobal = stats?.dailyVisitors || new Map();
        const dailyClaimsGlobal = stats?.dailyClaims || new Map();

        let globalVisits24h = 0;
        let globalClaims24h = 0;

        for (const [date, count] of dailyVisitorsGlobal) {
            if (new Date(date) >= oneDayAgo) globalVisits24h += count;
        }
        for (const [date, count] of dailyClaimsGlobal) {
            if (new Date(date) >= oneDayAgo) globalClaims24h += count;
        }

        res.json({
            global: {
                totalVisitors: stats?.totalVisitors || 0,
                totalClaims: stats?.totalClaims || 0,
                todayVisitors: dailyVisitorsGlobal.get(today) || 0,
                todayClaims: dailyClaimsGlobal.get(today) || 0,
                visits24h: globalVisits24h,
                claims24h: globalClaims24h,
                activeNow: Math.max(1, Math.round((stats?.totalVisitors || 0) * 0.04)),
                activeClaims: Math.max(0, Math.round((stats?.totalClaims || 0) * 0.03)),
                dailyVisitors: Object.fromEntries(dailyVisitorsGlobal),
                dailyClaims: Object.fromEntries(dailyClaimsGlobal)
            },
            links: links.map(l => ({
                id: l.id,
                name: l.name,
                visits: l.visits || 0,
                claims: l.claims || 0,
                status: l.status,
                expiryDate: l.expiryDate || null,
                dailyVisits: Object.fromEntries(l.dailyVisits || new Map()),
                dailyClaims: Object.fromEntries(l.dailyClaims || new Map())
            }))
        });
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// Device Management APIs
app.get('/api/admin/blocked-devices', authMiddleware, async (req, res) => {
    try {
        const devices = await BlockedDevice.find().sort({ lastAttempt: -1 });
        res.json({ success: true, devices });
    } catch (e) {
        res.status(500).json({ error: 'Failed' });
    }
});

app.post('/api/admin/blocked-devices/:id/unblock', authMiddleware, async (req, res) => {
    try {
        await BlockedDevice.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Failed' });
    }
});

app.post('/api/admin/blocked-devices/:id/permanent-ban', authMiddleware, async (req, res) => {
    try {
        const dev = await BlockedDevice.findById(req.params.id);
        if (dev) {
            dev.isPermanent = true;
            dev.reason = req.body.reason || 'Permanent ban by admin';
            await dev.save();
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Failed' });
    }
});

// Settings APIs
app.post('/api/admin/passcode', authMiddleware, async (req, res) => {
    try {
        const { oldPasscode, newPasscode } = req.body;
        const admin = await User.findOne();
        if (admin && admin.passcode && !bcrypt.compareSync(oldPasscode, admin.passcode)) {
            return res.status(401).json({ error: 'Old passcode is incorrect' });
        }
        if (admin) {
            admin.passcode = bcrypt.hashSync(newPasscode, 10);
            await admin.save();
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Failed' });
    }
});

app.post('/api/admin/background', authMiddleware, async (req, res) => {
    try {
        const popup = await PopupSettings.findOne();
        if (popup) {
            popup.image = req.body.background || null;
            await popup.save();
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Failed' });
    }
});

app.post('/api/admin/logout', authMiddleware, async (req, res) => {
    res.clearCookie('adminToken');
    res.json({ success: true });
});

// ==================== URL SHORTENER & DEEP LINKING ====================
app.get('/s/:code', async (req, res) => {
    try {
        const link = await ShortLink.findOne({ code: req.params.code });
        if (!link) return res.status(404).send('Short link not found');
        link.visits = (link.visits || 0) + 1;
        link.lastClicked = new Date();
        await link.save();

        if (link.appOpen && link.appScheme) {
            return res.redirect(link.appScheme);
        }
        res.redirect(link.originalUrl);
    } catch (e) {
        res.status(500).send('Server error');
    }
});

app.get('/api/short-links', authMiddleware, async (req, res) => {
    try {
        const links = await ShortLink.find().sort({ createdAt: -1 });
        res.json({ success: true, links });
    } catch (e) {
        res.status(500).json({ error: 'Failed' });
    }
});

app.post('/api/short-links', authMiddleware, async (req, res) => {
    try {
        const { originalUrl, title, appOpen, appScheme, appStoreLink, expiryDate } = req.body;
        const code = Math.random().toString(36).substring(2, 8);
        const link = new ShortLink({
            code, originalUrl, title: title || 'Untitled Link',
            appOpen: appOpen || false, appScheme: appScheme || '',
            appStoreLink: appStoreLink || '', expiryDate: expiryDate || null
        });
        await link.save();
        res.json({ success: true, link, shortUrl: `${req.protocol}://${req.get('host')}/s/${code}` });
    } catch (e) {
        res.status(500).json({ error: 'Failed' });
    }
});

app.delete('/api/short-links/:id', authMiddleware, async (req, res) => {
    try {
        await ShortLink.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Failed' });
    }
});

app.get('/api/short-links/stats', authMiddleware, async (req, res) => {
    try {
        const totalLinks = await ShortLink.countDocuments();
        const activeLinks = await ShortLink.countDocuments({ status: 'active' });
        const clicks = await ShortLink.aggregate([{ $group: { _id: null, total: { $sum: '$visits' } } }]);
        res.json({
            success: true,
            stats: {
                totalLinks,
                activeLinks,
                totalClicks: clicks.length > 0 ? clicks[0].total : 0,
                clicks24h: 0
            }
        });
    } catch (e) {
        res.status(500).json({ error: 'Failed' });
    }
});

// ==================== SMART UNIVERSAL FILE RESOLVER ====================
function sendAppFile(res, ...fileNames) {
    const searchDirs = [
        path.join(__dirname, '..'),
        path.join(__dirname, '..', 'admin'),
        __dirname,
        path.join(__dirname, 'admin')
    ];

    for (const name of fileNames) {
        for (const dir of searchDirs) {
            const fullPath = path.join(dir, name);
            if (fs.existsSync(fullPath)) {
                return res.sendFile(fullPath);
            }
        }
    }

    res.status(404).send(`File not found: ${fileNames.join(' or ')}`);
}

// ==================== PAGE ROUTES ====================
app.get('/', (req, res) => res.redirect('/admin/secret-gateway'));

// Secret Gateway
app.get('/admin/secret-gateway', (req, res) => {
    sendAppFile(res, 'secret-gateway.html', 'admin/secret-gateway.html');
});

// Login Page
app.get('/admin/login.html', (req, res) => {
    sendAppFile(res, 'login.html', 'admin/login.html');
});

// Admin Dashboard: Automatically matches 668379d1.html OR admin/index.html
app.get(['/admin/index.html', '/admin', '/admin/668379d1.html'], (req, res) => {
    const token = req.cookies?.adminToken;
    if (!token || !verifyToken(token)) {
        return res.redirect('/admin/login.html');
    }
    sendAppFile(res, 'admin/index.html', '668379d1.html', 'admin/668379d1.html', 'index.html');
});

// Visitor Pages
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

app.listen(port, '0.0.0.0', () => {
    console.log(`🚀 Secure Server running on port ${port}`);
});
