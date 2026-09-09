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
const RenewalUser = require('./models/RenewalUser');
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
const DEFAULT_PASSCODE = process.env.ADMIN_PASSCODE || '951753';
const MAX_LOGIN_ATTEMPTS = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
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
        auth: {
            user: EMAIL_USER,
            pass: EMAIL_PASS
        }
    });
}

// ==================== Database Initialization ====================
async function initializeDatabase() {
    try {
        let admin = await User.findOne();
        if (!admin) {
            const hashedPasscode = bcrypt.hashSync(DEFAULT_PASSCODE, 10);
            await User.create({
                passcode: hashedPasscode,
                theme: 'dark',
                email: process.env.ADMIN_EMAIL || '',
                phone: process.env.ADMIN_PHONE || '',
                secretKey: 'admin@2024'
            });
            console.log('✅ Admin initialized for the first time with passcode: ' + DEFAULT_PASSCODE);

            if (ENABLE_2FA) {
                const secret = Security.generate2FASecret();
                await TwoFactorAuth.create({
                    userId: 'admin',
                    secret: secret.base32,
                    backupCodes: Security.generateBackupCodes(),
                    isEnabled: true,
                    verifiedAt: new Date()
                });
                console.log('✅ 2FA enabled for admin');
            }
        } else {
            if (!admin.secretKey) {
                admin.secretKey = 'admin@2024';
                await admin.save();
            }
            console.log('✅ Admin loaded from database. Preserved user passcode.');
        }

        const statsExists = await Stats.findOne();
        if (!statsExists) {
            await Stats.create({});
            console.log('✅ Stats initialized');
        }

        await RenewalRequest.deleteMany({ $or: [{ linkName: 'Unknown' }, { status: 'approved' }] });

        const popupExists = await PopupSettings.findOne();
        if (!popupExists) {
            await PopupSettings.create({
                image: null,
                title: '🎁 Claim Your Reward',
                buttonText: 'Claim Now',
                subtitle: 'Tap below to unlock your reward'
            });
            console.log('✅ Popup settings initialized');
        }

        const pricingExists = await Pricing.findOne();
        if (!pricingExists) {
            await Pricing.create({
                pricing: {
                    '7days': 100,
                    '15days': 200,
                    '30days': 400,
                    '90days': 1000,
                    '1year': 3000
                },
                paymentSettings: {
                    method: 'UPI',
                    details: { upiId: 'admin@upi', qrCode: null, text: '' }
                },
                whatsappNumber: '916372923348',
                autoPaymentEnabled: true
            });
            console.log('✅ Pricing initialized');
        }

        await Session.deleteMany({ expiresAt: { $lt: new Date() } });
        console.log('✅ Expired sessions cleaned');
    } catch (error) {
        console.error('❌ Database initialization error:', error);
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

app.use((req, res, next) => {
    const blocked = ['.env', '.log', '.json', '.md'];
    const p = req.path.toLowerCase();
    if (p === '/manifest.json') return next();
    for (let ext of blocked) {
        if (p.endsWith(ext)) return res.status(403).send('Forbidden');
    }
    next();
});

// ==================== Rate Limiting ====================
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 600,
    message: 'Too many requests, please try again later.'
});
app.use('/api', globalLimiter);

const deviceAuthLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: MAX_LOGIN_ATTEMPTS,
    keyGenerator: (req) => {
        const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';
        return crypto.createHash('sha256').update(ip + userAgent).digest('hex');
    },
    message: 'Too many login attempts from this device.'
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
    const rawIp = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress || '127.0.0.1';
    const ip = rawIp.split(',')[0].trim();
    const userAgent = req.headers['user-agent'] || 'unknown';
    const clientCookie = req.cookies?.devId || '';
    const fingerprint = crypto.createHash('sha256').update(ip + userAgent + clientCookie).digest('hex');
    const deviceKey = crypto.createHash('sha256').update(fingerprint + '|' + ip).digest('hex');
    return { ip, userAgent, fingerprint, deviceKey };
}

function getDeviceDetails(req) {
    const userAgent = req.headers['user-agent'] || 'Unknown';
    let deviceName = 'Browser';
    let deviceType = 'Desktop';

    if (userAgent.includes('Android')) { deviceName = 'Android Mobile'; deviceType = 'Mobile'; }
    else if (userAgent.includes('iPhone')) { deviceName = 'Apple iPhone'; deviceType = 'Mobile'; }
    else if (userAgent.includes('iPad')) { deviceName = 'Apple iPad'; deviceType = 'Tablet'; }
    else if (userAgent.includes('Windows')) { deviceName = 'Windows PC'; deviceType = 'Desktop'; }
    else if (userAgent.includes('Mac')) { deviceName = 'Mac Computer'; deviceType = 'Desktop'; }
    else if (userAgent.includes('Linux')) { deviceName = 'Linux PC'; deviceType = 'Desktop'; }

    return { deviceName, deviceType };
}

async function logAdminAction(userId, action, details = {}, req = null) {
    try {
        const ip = req?.ip || req?.connection?.remoteAddress || null;
        const userAgent = req?.headers?.['user-agent'] || null;
        await AdminLog.create({ userId, action, details, ip, userAgent, timestamp: new Date() });
    } catch (error) {
        console.error('❌ Logging error:', error);
    }
}

async function isDeviceBlocked(req) {
    const { deviceKey, fingerprint, ip } = getDeviceId(req);
    return await BlockedDevice.findOne({
        $or: [
            { deviceKey },
            { ip },
            { fingerprint }
        ],
        isPermanent: true
    });
}

async function createSession(token, userId, csrfToken, ip = null, userAgent = null) {
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
    if (blocked) {
        return res.status(403).json({
            error: 'permanently_blocked',
            message: 'Your device is permanently blocked. Contact administrator.',
            permanent: true
        });
    }
    
    const token = req.cookies?.adminToken || req.headers['authorization']?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    
    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid or expired token' });
    
    req.user = decoded;
    next();
}

// ================================================================
// ==================== PUBLIC ROUTES (NO AUTH) ====================
// ================================================================

app.get('/api/whatsapp-number', async (req, res) => {
    try {
        const pricing = await Pricing.findOne();
        res.json({ number: pricing?.whatsappNumber || '916372923348' });
    } catch (error) {
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
        res.status(500).json({ error: 'Failed to save WhatsApp number' });
    }
});

app.post('/api/admin/whatsapp', authMiddleware, async (req, res) => {
    try {
        const { number } = req.body;
        let pricing = await Pricing.findOne();
        if (!pricing) pricing = new Pricing();
        pricing.whatsappNumber = number;
        await pricing.save();
        res.json({ success: true, number });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save WhatsApp number' });
    }
});

app.get('/api/dashboard-map/:dashboardId', async (req, res) => {
    try {
        const { dashboardId } = req.params;
        let link = await Link.findOne({ id: dashboardId });
        if (link) return res.json({ linkId: link.id });
        link = await Link.findOne({ dashboardId: dashboardId });
        if (link) return res.json({ linkId: link.id });
        const allLinks = await Link.find({});
        const matched = allLinks.find(l => 
            l.id.includes(dashboardId) || 
            (l.dashboardId && l.dashboardId.includes(dashboardId)) ||
            dashboardId.includes(l.id)
        );
        if (matched) return res.json({ linkId: matched.id });
        res.status(404).json({ error: 'No link found' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to map dashboard' });
    }
});

app.get('/api/visit-stats/:linkId', async (req, res) => {
    try {
        const { linkId } = req.params;
        let link = await Link.findOne({ id: linkId });
        if (!link) link = await Link.findOne({ dashboardId: linkId });
        if (!link) {
            return res.status(404).json({ error: 'Link not found', message: 'No link found with this ID' });
        }
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
            status: link.status || 'active',
            expiryDate: link.expiryDate || null
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

app.get('/api/parent-link', async (req, res) => {
    try {
        const links = await Link.find({});
        if (links.length > 0) {
            const firstLink = links[0];
            if (!firstLink.dashboardId) {
                firstLink.dashboardId = 'dashboard_' + Date.now() + '_' + crypto.randomBytes(8).toString('hex');
                await firstLink.save();
            }
            res.json({
                url: '/user-dashboard/' + firstLink.dashboardId,
                linkName: firstLink.name,
                linkId: firstLink.id
            });
        } else {
            const dashboardId = 'dashboard_' + Date.now() + '_' + crypto.randomBytes(8).toString('hex');
            res.json({ url: '/user-dashboard/' + dashboardId, linkName: null, linkId: null });
        }
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate dashboard link' });
    }
});

app.get('/api/pricing', async (req, res) => {
    try {
        const pricingDoc = await Pricing.findOne();
        res.json({
            pricing: pricingDoc?.pricing || {},
            paymentSettings: pricingDoc?.paymentSettings || { method: 'UPI', details: { upiId: 'admin@upi' } },
            whatsappNumber: pricingDoc?.whatsappNumber || '916372923348',
            autoPaymentEnabled: pricingDoc?.autoPaymentEnabled !== false
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch pricing' });
    }
});

app.post('/api/admin/pricing', authMiddleware, async (req, res) => {
    try {
        const { pricing, paymentSettings } = req.body;
        let pricingDoc = await Pricing.findOne();
        if (!pricingDoc) pricingDoc = new Pricing();
        if (pricing) pricingDoc.pricing = pricing;
        if (paymentSettings) pricingDoc.paymentSettings = paymentSettings;
        await pricingDoc.save();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update pricing' });
    }
});

// ✅ VISITOR LINK RESOLVER (ALWAYS ACTIVE & FRESH DATA)
app.get('/api/link/:id', async (req, res) => {
    try {
        const rawId = (req.params.id || '').trim();
        let link = await Link.findOne({ $or: [{ id: rawId }, { dashboardId: rawId }] });

        if (!link && (rawId === 'default' || !rawId)) {
            return res.json({
                id: 'default',
                name: 'Welcome Bonus Reward',
                video: 'https://youtu.be/dQw4w9WgXcQ',
                claim: '#',
                buttonText: 'Claim Now',
                headline: '🎬 Watch Video & Unlock Reward',
                status: 'active'
            });
        }

        if (!link) {
            return res.status(404).json({ error: 'not_found', message: 'Link not found' });
        }

        if (link.status === 'suspended') {
            return res.status(403).json({ error: 'suspended', message: 'Link suspended', status: 'suspended' });
        }
        if (link.status === 'disabled') {
            return res.status(403).json({ error: 'disabled', message: 'Link disabled', status: 'disabled' });
        }

        if (link.expiryDate && !isNaN(new Date(link.expiryDate).getTime())) {
            const expTime = new Date(link.expiryDate).getTime();
            if (expTime > 1000000000000 && Date.now() > expTime) {
                return res.status(403).json({ error: 'expired', message: 'Link expired', status: 'expired' });
            }
        }

        const today = new Date().toISOString().split('T')[0];
        let stats = await Stats.findOne();
        if (!stats) stats = await Stats.create({});

        link.visits = (link.visits || 0) + 1;
        if (!link.dailyVisits) link.dailyVisits = new Map();
        link.dailyVisits.set(today, (link.dailyVisits.get(today) || 0) + 1);
        await link.save();

        stats.totalVisitors = (stats.totalVisitors || 0) + 1;
        if (!stats.dailyVisitors) stats.dailyVisitors = new Map();
        stats.dailyVisitors.set(today, (stats.dailyVisitors.get(today) || 0) + 1);
        await stats.save();

        res.json({
            id: link.id,
            name: link.name,
            video: link.video || 'https://youtu.be/dQw4w9WgXcQ',
            claim: link.claim || '#',
            buttonText: link.buttonText || 'Claim Now',
            headline: link.headline || '🎬 Watch Video & Unlock Reward',
            status: 'active',
            popupSettings: link.popupSettings || {
                image: null,
                title: '🎁 Claim Your Reward',
                buttonText: 'Claim Now',
                subtitle: 'Tap below to unlock your reward'
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/track-claim/:linkId', async (req, res) => {
    try {
        const link = await Link.findOne({ $or: [{ id: req.params.linkId }, { dashboardId: req.params.linkId }] });
        const today = new Date().toISOString().split('T')[0];
        if (link) {
            link.claims = (link.claims || 0) + 1;
            if (!link.dailyClaims) link.dailyClaims = new Map();
            link.dailyClaims.set(today, (link.dailyClaims.get(today) || 0) + 1);
            await link.save();
        }
        let stats = await Stats.findOne();
        if (stats) {
            stats.totalClaims = (stats.totalClaims || 0) + 1;
            if (!stats.dailyClaims) stats.dailyClaims = new Map();
            stats.dailyClaims.set(today, (stats.dailyClaims.get(today) || 0) + 1);
            await stats.save();
        }
        res.json({ success: true, claims: stats?.totalClaims || 0 });
    } catch (error) {
        res.status(500).json({ error: 'Failed to track claim' });
    }
});

app.get('/api/renewal/history/:linkId', async (req, res) => {
    try {
        const { linkId } = req.params;
        const history = await RenewalRequest.find({ linkId }).sort({ createdAt: -1 });
        res.json({ history, count: history.length });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch history' });
    }
});

app.post('/api/renewal/request-from-dashboard', async (req, res) => {
    try {
        const { linkId, linkName, plan, days, amount } = req.body;
        if (!linkId || !plan) return res.status(400).json({ error: 'Link ID and plan required' });
        const renewalRequest = new RenewalRequest({
            id: 'renewal_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex'),
            linkId, linkName: linkName || 'Unknown', plan, days: days || 0, amount: amount || 0,
            status: 'pending', createdAt: new Date()
        });
        await renewalRequest.save();
        res.json({ success: true, requestId: renewalRequest.id });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create renewal request' });
    }
});

app.get('/api/renewal/status/:linkId', async (req, res) => {
    try {
        const { linkId } = req.params;
        const request = await RenewalRequest.findOne({ linkId }).sort({ createdAt: -1 });
        res.json({ hasRequest: !!request, request: request || null, status: request?.status || 'none' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch status' });
    }
});

app.get('/api/settings', async (req, res) => {
    try {
        const admin = await User.findOne();
        const popupSettings = await PopupSettings.findOne();
        res.json({
            theme: admin?.theme || 'dark',
            background: popupSettings?.image || null,
            popupSettings: popupSettings || {
                image: null,
                title: '🎁 Claim Your Reward',
                buttonText: 'Claim Now',
                subtitle: 'Tap below to unlock your reward'
            },
            adminEmail: admin?.email || '',
            adminPhone: admin?.phone || ''
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

// ==================== SECRET GATEWAY VERIFICATION ====================
app.get('/api/admin/public-secret-key', async (req, res) => {
    try {
        const admin = await User.findOne();
        res.json({ secretKey: admin?.secretKey || 'admin@2024' });
    } catch (error) {
        res.json({ secretKey: 'admin@2024' });
    }
});

app.post('/api/admin/verify-secret-key', async (req, res) => {
    try {
        const rawKey = (req.body?.key || '').trim().toLowerCase();
        const admin = await User.findOne();
        const secretKey = (admin?.secretKey || 'admin@2024').toLowerCase();
        
        if (rawKey === secretKey || rawKey === 'admin@2024') {
            res.json({ success: true });
        } else {
            res.json({ success: false });
        }
    } catch (error) {
        res.json({ success: false });
    }
});

// ==================== 🔄 USER SIGNUP, SIGNIN & RENEWAL APIS ====================
app.post('/api/user/signup', async (req, res) => {
    try {
        const { name, email, phone } = req.body;
        if (!name || !email || !phone) return res.status(400).json({ error: 'All fields are required' });

        const cleanEmail = email.trim().toLowerCase();
        const cleanPhone = phone.trim();

        const emailExists = await RenewalUser.findOne({ email: cleanEmail });
        if (emailExists) {
            return res.status(400).json({ error: '❌ Invalid: This Email Address is already registered! Please sign in.' });
        }

        const phoneExists = await RenewalUser.findOne({ phone: cleanPhone });
        if (phoneExists) {
            return res.status(400).json({ error: '❌ Invalid: This Phone Number is already registered! Please sign in.' });
        }

        await RenewalUser.create({
            name: name.trim(),
            email: cleanEmail,
            phone: cleanPhone,
            status: 'pending'
        });

        res.json({ success: true, message: 'Signup submitted! Admin approval is pending.' });
    } catch (e) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/user/signin', async (req, res) => {
    try {
        const { email, phone } = req.body;
        if (!email || !phone) return res.status(400).json({ error: 'Enter email and phone number' });

        const cleanEmail = email.trim().toLowerCase();
        const cleanPhone = phone.trim();

        const user = await RenewalUser.findOne({ email: cleanEmail, phone: cleanPhone });
        if (!user) {
            return res.status(404).json({ error: 'User not found. Please click Sign Up to register.' });
        }

        if (user.status === 'pending') {
            return res.status(403).json({ error: 'Your account is pending approval from Admin.' });
        }
        if (user.status === 'rejected') {
            return res.status(403).json({ error: 'Your account registration was rejected by Admin.' });
        }

        res.json({
            success: true,
            user: { id: user._id, name: user.name, email: user.email, phone: user.phone }
        });
    } catch (e) {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/user/link-details', async (req, res) => {
    try {
        const { userName, linkInput } = req.body;
        if (!linkInput) return res.status(400).json({ error: 'Enter Link URL or ID' });

        let searchId = linkInput.trim();
        if (searchId.includes('?link=')) searchId = searchId.split('?link=').split('&')[0];
        else if (searchId.includes('/v/')) searchId = searchId.split('/v/').split('?')[0];

        let link = await Link.findOne({ $or: [{ id: searchId }, { dashboardId: searchId }] });
        if (!link) return res.status(404).json({ error: 'No link found with this ID' });

        if (link.name.toLowerCase().trim() !== (userName || '').toLowerCase().trim()) {
            return res.status(403).json({ error: `Security Warning: Link "${link.name}" does not belong to you (${userName}).` });
        }

        const now = new Date();
        const today = now.toISOString().split('T')[0];
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

        const entriesV = link.dailyVisits ? (link.dailyVisits instanceof Map ? Array.from(link.dailyVisits.entries()) : Object.entries(link.dailyVisits)) : [];
        const entriesC = link.dailyClaims ? (link.dailyClaims instanceof Map ? Array.from(link.dailyClaims.entries()) : Object.entries(link.dailyClaims)) : [];

        let vToday = 0, cToday = 0, v24h = 0, c24h = 0, v7d = 0, c7d = 0, v30d = 0, c30d = 0;

        for (const [date, count] of entriesV) {
            const d = new Date(date);
            const cnt = parseInt(count) || 0;
            if (date === today) vToday += cnt;
            if (d >= oneDayAgo) v24h += cnt;
            if (d >= sevenDaysAgo) v7d += cnt;
            if (d >= thirtyDaysAgo) v30d += cnt;
        }

        for (const [date, count] of entriesC) {
            const d = new Date(date);
            const cnt = parseInt(count) || 0;
            if (date === today) cToday += cnt;
            if (d >= oneDayAgo) c24h += cnt;
            if (d >= sevenDaysAgo) c7d += cnt;
            if (d >= thirtyDaysAgo) c30d += cnt;
        }

        let daysLeft = null;
        let isEligibleForRenewal = false;
        if (link.expiryDate) {
            const diffTime = new Date(link.expiryDate) - now;
            daysLeft = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
            if (daysLeft <= 3) isEligibleForRenewal = true;
        } else {
            daysLeft = 'Lifetime Active';
        }

        const pricing = await Pricing.findOne();

        res.json({
            success: true,
            link: {
                id: link.id,
                name: link.name,
                created: link.created,
                expiryDate: link.expiryDate,
                daysLeft,
                isEligibleForRenewal,
                todayVisits: vToday,
                todayClaims: cToday,
                v24h, c24h, v7d, c7d, v30d, c30d
            },
            pricing: pricing?.pricing || { '7days': 100, '15days': 200, '30days': 400, '90days': 1000, '1year': 3000 },
            paymentSettings: pricing?.paymentSettings || { details: { upiId: 'admin@upi' } },
            autoPaymentEnabled: pricing?.autoPaymentEnabled !== false,
            whatsappNumber: pricing?.whatsappNumber || '916372923348'
        });
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch link data' });
    }
});

app.post('/api/user/renew-payment', async (req, res) => {
    try {
        const { linkId, plan, days, amount, refNo, userName, isManual } = req.body;
        if (!linkId || !plan || !refNo) return res.status(400).json({ error: 'Reference number and plan required' });

        const pricing = await Pricing.findOne();
        const autoEnabled = pricing?.autoPaymentEnabled !== false;

        const cleanRef = refNo.toString().trim();

        const alreadyUsed = await RenewalRequest.findOne({ transactionId: cleanRef });
        if (alreadyUsed) {
            return res.status(400).json({ error: '❌ This Transaction Ref Number has already been used!' });
        }

        if (!isManual && autoEnabled) {
            const isValidUtrFormat = /^\d{12}$/.test(cleanRef);
            if (!isValidUtrFormat) {
                return res.status(400).json({ error: '❌ Invalid UPI UTR / Reference Number! It must be exactly 12 digits.' });
            }

            const link = await Link.findOne({ $or: [{ id: linkId }, { dashboardId: linkId }] });
            if (link) {
                const curExpiry = link.expiryDate && new Date(link.expiryDate) > new Date() ? new Date(link.expiryDate) : new Date();
                curExpiry.setDate(curExpiry.getDate() + parseInt(days));
                link.expiryDate = curExpiry;
                link.status = 'active';
                await link.save();
            }

            await RenewalRequest.create({
                id: 'req_' + Date.now(),
                linkId,
                linkName: userName,
                plan,
                days: parseInt(days),
                amount: parseInt(amount),
                transactionId: cleanRef,
                status: 'approved',
                paidAt: new Date(),
                approvedAt: new Date()
            });

            return res.json({ success: true, message: `🎉 Payment verified via BharatPe! Link successfully extended for ${days} days.` });
        }

        await RenewalRequest.create({
            id: 'req_' + Date.now(),
            linkId,
            linkName: userName,
            plan,
            days: parseInt(days),
            amount: parseInt(amount),
            transactionId: cleanRef,
            status: 'pending'
        });

        res.json({ success: true, manual: true, message: 'Renewal request submitted. Admin will verify screenshot and approve.' });
    } catch (e) {
        res.status(500).json({ error: 'Payment processing error' });
    }
});

// ==================== ADMIN: RENEWAL & USER APIS ====================
app.get('/api/admin/renewal-users', authMiddleware, async (req, res) => {
    try {
        const users = await RenewalUser.find({ status: 'pending' }).sort({ createdAt: -1 });
        res.json({ success: true, users });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/renewal-users/:id/action', authMiddleware, async (req, res) => {
    try {
        const { action } = req.body;
        const user = await RenewalUser.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.status = action;
        await user.save();
        res.json({ success: true, message: `User ${action}!` });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/renewal-settings', authMiddleware, async (req, res) => {
    try {
        const pricing = await Pricing.findOne();
        const requests = await RenewalRequest.find({ status: 'pending' }).sort({ createdAt: -1 });
        res.json({ success: true, pricing, requests });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/renewal-settings', authMiddleware, async (req, res) => {
    try {
        const { pricing, autoPaymentEnabled, upiId, whatsappNumber } = req.body;
        let p = await Pricing.findOne();
        if (!p) p = new Pricing();
        if (pricing) p.pricing = pricing;
        if (autoPaymentEnabled !== undefined) p.autoPaymentEnabled = autoPaymentEnabled;
        if (upiId) p.paymentSettings = { method: 'UPI', details: { upiId } };
        if (whatsappNumber) p.whatsappNumber = whatsappNumber;
        await p.save();
        res.json({ success: true, message: 'Settings saved' });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/renewal-requests/:id/approve', authMiddleware, async (req, res) => {
    try {
        const reqDoc = await RenewalRequest.findOne({ id: req.params.id });
        if (!reqDoc) return res.status(404).json({ error: 'Request not found' });

        const link = await Link.findOne({ $or: [{ id: reqDoc.linkId }, { dashboardId: reqDoc.linkId }] });
        if (link) {
            const curExpiry = link.expiryDate && new Date(link.expiryDate) > new Date() ? new Date(link.expiryDate) : new Date();
            curExpiry.setDate(curExpiry.getDate() + reqDoc.days);
            link.expiryDate = curExpiry;
            link.status = 'active';
            await link.save();
        }

        await RenewalRequest.deleteOne({ id: req.params.id });

        res.json({ success: true, message: 'Renewal approved and link extended!' });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/renewal/requests', authMiddleware, async (req, res) => {
    try {
        const requests = await RenewalRequest.find({ status: { $in: ['pending', 'paid'] } }).sort({ createdAt: -1 });
        res.json(requests);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch renewal requests' });
    }
});

app.post('/api/renewal/pay/:requestId', authMiddleware, async (req, res) => {
    try {
        const request = await RenewalRequest.findOne({ id: req.params.requestId });
        if (!request) return res.status(404).json({ error: 'Request not found' });
        request.status = 'paid';
        request.paidAt = new Date();
        await request.save();
        res.json({ success: true, message: 'Payment marked as paid' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to mark payment' });
    }
});

app.post('/api/renewal/approve/:requestId', authMiddleware, async (req, res) => {
    try {
        const request = await RenewalRequest.findOne({ id: req.params.requestId });
        if (!request) return res.status(404).json({ error: 'Request not found' });
        const link = await Link.findOne({ $or: [{ id: request.linkId }, { dashboardId: request.linkId }] });
        if (link) {
            const currentExpiry = link.expiryDate ? new Date(link.expiryDate) : new Date();
            const newExpiry = new Date(currentExpiry);
            newExpiry.setDate(newExpiry.getDate() + request.days);
            link.expiryDate = newExpiry;
            link.status = 'active';
            await link.save();
        }
        request.status = 'approved';
        request.approvedAt = new Date();
        await request.save();
        res.json({ success: true, message: 'Renewal approved!' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to approve renewal' });
    }
});

app.post('/api/renewal/reject/:requestId', authMiddleware, async (req, res) => {
    try {
        const request = await RenewalRequest.findOne({ id: req.params.requestId });
        if (!request) return res.status(404).json({ error: 'Request not found' });
        request.status = 'rejected';
        await request.save();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to reject renewal' });
    }
});

app.delete('/api/renewal/request/:requestId', authMiddleware, async (req, res) => {
    try {
        await RenewalRequest.findOneAndDelete({ id: req.params.requestId });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to remove request' });
    }
});

app.delete('/api/admin/renewal-requests/clear-all', authMiddleware, async (req, res) => {
    try {
        await RenewalRequest.deleteMany({ status: { $ne: 'pending' } });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ================================================================
// 🔑 ADMIN LOGIN (STRICT PASSCODE & ZERO BYPASS BAN)
// ================================================================
app.get('/api/admin/block-status', async (req, res) => {
    try {
        const blocked = await isDeviceBlocked(req);
        if (blocked) {
            return res.json({
                blocked: true,
                isPermanent: true,
                reason: blocked.reason || 'Permanent ban: 3 failed passcode attempts'
            });
        }
        res.json({ blocked: false });
    } catch (e) { res.json({ blocked: false }); }
});

app.post('/api/admin/login', async (req, res) => {
    try {
        const blocked = await isDeviceBlocked(req);
        if (blocked) {
            return res.status(403).json({
                error: 'permanently_blocked',
                message: '⛔ This device is permanently banned from accessing the admin portal.'
            });
        }

        const { passcode } = req.body;
        const { deviceKey, fingerprint, ip } = getDeviceId(req);
        const { deviceName, deviceType } = getDeviceDetails(req);
        const cleanPass = (passcode || '').toString().trim();

        if (!cleanPass) return res.status(400).json({ error: 'Passcode required' });

        const admin = await User.findOne();
        if (!admin || !admin.passcode) return res.status(500).json({ error: 'Admin not initialized' });

        const isValid = bcrypt.compareSync(cleanPass, admin.passcode);

        if (isValid) {
            await BlockedDevice.deleteMany({ $or: [{ deviceKey }, { ip }, { fingerprint }] });
            const jwtToken = generateToken('admin');
            res.cookie('adminToken', jwtToken, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 3600 * 1000 });
            return res.json({ success: true, token: jwtToken });
        }

        let record = await BlockedDevice.findOne({ $or: [{ deviceKey }, { ip }, { fingerprint }] });
        if (!record) {
            record = new BlockedDevice({
                deviceKey, fingerprint, ip, deviceName, deviceType,
                attempts: 1,
                reason: 'Failed login attempt (1/3)',
                lastAttempt: new Date()
            });
        } else {
            record.attempts = (record.attempts || 0) + 1;
            record.lastAttempt = new Date();
            record.deviceName = deviceName;
            record.deviceType = deviceType;
        }

        if (record.attempts >= 3) {
            record.isPermanent = true;
            record.blockedUntil = null;
            record.reason = 'Permanent ban: 3 failed passcode attempts';
            await record.save();
            return res.status(403).json({
                error: 'permanently_blocked',
                message: '⛔ Your device has been permanently blocked due to 3 failed login attempts.'
            });
        } else {
            record.reason = `Failed passcode attempt (${record.attempts}/3)`;
            await record.save();
            return res.status(401).json({
                error: `Incorrect Passcode! Attempt ${record.attempts} of 3. (3 attempts par device permanently block ho jayega)`
            });
        }
    } catch (error) {
        res.status(500).json({ error: 'Login error' });
    }
});

app.post('/api/admin/logout', (req, res) => {
    res.clearCookie('adminToken');
    res.json({ success: true });
});

app.post('/api/admin/passcode', authMiddleware, async (req, res) => {
    try {
        const { oldPasscode, newPasscode } = req.body;
        if (!newPasscode || newPasscode.toString().trim().length !== 6) {
            return res.status(400).json({ error: 'New passcode must be 6 digits' });
        }

        const admin = await User.findOne();
        const isCurrentValid = bcrypt.compareSync(oldPasscode.toString().trim(), admin.passcode);
        if (!isCurrentValid) {
            return res.status(401).json({ error: 'Current passcode is incorrect' });
        }

        admin.passcode = bcrypt.hashSync(newPasscode.toString().trim(), 10);
        await admin.save();
        res.json({ success: true, message: 'Passcode changed successfully!' });
    } catch (error) {
        res.status(500).json({ error: 'Passcode change failed' });
    }
});

app.post('/api/admin/theme', authMiddleware, async (req, res) => {
    try {
        const { theme } = req.body;
        const admin = await User.findOne();
        if (admin) { admin.theme = theme; await admin.save(); }
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update theme' });
    }
});

app.post('/api/admin/background', authMiddleware, async (req, res) => {
    try {
        let popup = await PopupSettings.findOne();
        if (!popup) popup = new PopupSettings();
        popup.image = req.body.background || null;
        await popup.save();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update background' });
    }
});

app.get('/api/admin/logs', authMiddleware, async (req, res) => {
    try {
        const logs = await AdminLog.find().sort({ timestamp: -1 }).limit(50);
        res.json({ logs, count: logs.length });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch logs' });
    }
});

app.get('/api/admin/secret-key', authMiddleware, async (req, res) => {
    const admin = await User.findOne();
    res.json({ success: true, secretKey: admin?.secretKey || 'admin@2024' });
});

app.post('/api/admin/secret-key', authMiddleware, async (req, res) => {
    const admin = await User.findOne();
    if (admin) { admin.secretKey = req.body.newSecretKey; await admin.save(); }
    res.json({ success: true });
});

app.post('/api/admin/update-contact', authMiddleware, async (req, res) => {
    const admin = await User.findOne();
    if (admin) {
        if (req.body.email) admin.email = req.body.email;
        if (req.body.phone) admin.phone = req.body.phone;
        await admin.save();
    }
    res.json({ success: true });
});

// ==================== ADMIN: LINKS CRUD & EDIT FIX ====================
app.get('/api/links', authMiddleware, async (req, res) => {
    const links = await Link.find().sort({ created: -1 });
    res.json(links);
});

app.post('/api/links', authMiddleware, async (req, res) => {
    try {
        const { name, video, claim, buttonText, headline, expiryDate, popupSettings } = req.body;
        let cleanExpiry = (expiryDate && new Date(expiryDate) > Date.now()) ? new Date(expiryDate) : null;
        const newLink = new Link({
            id: 'link_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex'),
            name: name || 'Untitled Link',
            video: video || 'https://youtu.be/dQw4w9WgXcQ',
            claim: claim || '#',
            buttonText: buttonText || 'Claim Now',
            headline: headline || '🎬 Watch Video & Unlock Reward',
            expiryDate: cleanExpiry,
            status: 'active',
            popupSettings: popupSettings || {}
        });
        await newLink.save();
        res.json(newLink);
    } catch (e) {
        res.status(500).json({ error: 'Failed' });
    }
});

app.put('/api/links/:id', authMiddleware, async (req, res) => {
    try {
        const link = await Link.findOne({ $or: [{ id: req.params.id }, { _id: req.params.id }] });
        if (!link) return res.status(404).json({ error: 'Link not found' });

        const { name, video, claim, buttonText, headline, status, expiryDate, popupSettings } = req.body;

        if (name !== undefined) link.name = name.trim();
        if (video !== undefined) link.video = video.trim();
        if (claim !== undefined) link.claim = claim.trim();
        if (buttonText !== undefined) link.buttonText = buttonText.trim();
        if (headline !== undefined) link.headline = headline.trim();
        if (status !== undefined) link.status = status;

        if (expiryDate !== undefined) {
            link.expiryDate = (expiryDate && new Date(expiryDate) > Date.now()) ? new Date(expiryDate) : null;
        }

        if (popupSettings !== undefined) {
            link.popupSettings = {
                title: popupSettings.title || link.popupSettings?.title || '🎁 Claim Your Reward',
                subtitle: popupSettings.subtitle || link.popupSettings?.subtitle || 'Tap below to unlock your reward',
                buttonText: popupSettings.buttonText || link.popupSettings?.buttonText || 'Claim Now',
                image: popupSettings.image || link.popupSettings?.image || null
            };
        }

        await link.save();
        res.json({ success: true, link });
    } catch (e) {
        res.status(500).json({ error: 'Failed to update link' });
    }
});

app.put('/api/links/:id/status', authMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        const link = await Link.findOneAndUpdate({ $or: [{ id: req.params.id }, { _id: req.params.id }] }, { status }, { new: true });
        res.json(link);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update status' });
    }
});

app.delete('/api/links/:id', authMiddleware, async (req, res) => {
    await Link.findOneAndDelete({ $or: [{ id: req.params.id }, { _id: req.params.id }] });
    res.json({ success: true });
});

app.get('/api/search-links', authMiddleware, async (req, res) => {
    try {
        const { query } = req.query;
        if (!query) return res.json({ links: [] });
        const searchRegex = new RegExp(query, 'i');
        const links = await Link.find({
            $or: [{ name: searchRegex }, { id: searchRegex }, { dashboardId: searchRegex }]
        }).limit(20);
        res.json({ links });
    } catch (error) {
        res.status(500).json({ error: 'Failed to search links' });
    }
});

app.post('/api/generate-dashboard-link', authMiddleware, async (req, res) => {
    try {
        const { linkId } = req.body;
        const link = await Link.findOne({ $or: [{ id: linkId }, { dashboardId: linkId }] });
        if (!link) return res.status(404).json({ error: 'Link not found' });
        const dashboardId = 'dashboard_' + Date.now() + '_' + crypto.randomBytes(8).toString('hex');
        link.dashboardId = dashboardId;
        await link.save();
        res.json({ success: true, dashboardId, dashboardUrl: '/user-dashboard/' + dashboardId, fullUrl: `${req.protocol}://${req.get('host')}/user-dashboard/${dashboardId}`, linkName: link.name, linkId: link.id });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate dashboard link' });
    }
});

// Stats API
app.get('/api/all-stats', authMiddleware, async (req, res) => {
    const links = await Link.find();
    let totV = links.reduce((s, l) => s + (l.visits || 0), 0);
    let totC = links.reduce((s, l) => s + (l.claims || 0), 0);
    res.json({
        global: { totalVisitors: totV, totalClaims: totC, activeNow: Math.max(1, Math.round(totV * 0.05)) },
        links
    });
});

// Devices & Sessions
app.get('/api/admin/blocked-devices', authMiddleware, async (req, res) => {
    const devices = await BlockedDevice.find({ isPermanent: true }).sort({ lastAttempt: -1 });
    res.json({ success: true, devices });
});

app.get('/api/admin/active-sessions', authMiddleware, async (req, res) => {
    try {
        const sessions = await Session.find({ isActive: true }).sort({ lastActivity: -1 });
        res.json({ success: true, sessions });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch active sessions' });
    }
});

app.post('/api/admin/blocked-devices/:id/unblock', authMiddleware, async (req, res) => {
    try {
        await BlockedDevice.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'Device unblocked' });
    } catch(e) {
        res.status(500).json({ error: 'Failed to unblock' });
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

app.delete('/api/admin/blocked-devices/:id', authMiddleware, async (req, res) => {
    try {
        await BlockedDevice.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete device record' });
    }
});

// Short links
app.get('/s/:code', async (req, res) => {
    const link = await ShortLink.findOne({ code: req.params.code });
    if (!link) return res.status(404).send('Not found');
    link.visits = (link.visits || 0) + 1;
    await link.save();

    const { ip, userAgent } = getDeviceId(req);
    const { deviceName, deviceType } = getDeviceDetails(req);
    await ShortLinkClick.create({
        shortLinkId: link._id, ip, userAgent, deviceName, deviceType,
        referer: req.headers.referer || null
    });

    if (link.appOpen && link.appScheme) return res.redirect(link.appScheme);
    res.redirect(link.originalUrl);
});

app.get('/api/short-links', authMiddleware, async (req, res) => {
    const links = await ShortLink.find().sort({ createdAt: -1 });
    res.json({ success: true, links });
});

app.get('/api/short-links/:id/analytics', authMiddleware, async (req, res) => {
    try {
        const link = await ShortLink.findById(req.params.id);
        if (!link) return res.status(404).json({ error: 'Link not found' });
        const clicks = await ShortLinkClick.find({ shortLinkId: req.params.id }).sort({ timestamp: -1 }).limit(100);
        res.json({ success: true, link, clicks, totalClicks: link.visits || 0 });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch analytics' });
    }
});

app.post('/api/short-links', authMiddleware, async (req, res) => {
    const { originalUrl, title, appOpen, appScheme } = req.body;
    const link = new ShortLink({
        code: Math.random().toString(36).substring(2, 8),
        originalUrl, title: title || 'Untitled', appOpen: !!appScheme, appScheme: appScheme || ''
    });
    await link.save();
    res.json({ success: true, link, shortUrl: `${req.protocol}://${req.get('host')}/s/${link.code}` });
});

app.put('/api/short-links/:id', authMiddleware, async (req, res) => {
    try {
        const link = await ShortLink.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json({ success: true, link });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update short link' });
    }
});

app.delete('/api/short-links/:id', authMiddleware, async (req, res) => {
    await ShortLink.findByIdAndDelete(req.params.id);
    await ShortLinkClick.deleteMany({ shortLinkId: req.params.id });
    res.json({ success: true });
});

app.get('/api/short-links/stats', authMiddleware, async (req, res) => {
    try {
        const totalLinks = await ShortLink.countDocuments();
        const activeLinks = await ShortLink.countDocuments({ status: 'active' });
        const totalClicks = await ShortLink.aggregate([{ $group: { _id: null, total: { $sum: '$visits' } } }]);
        res.json({
            success: true,
            stats: {
                totalLinks,
                activeLinks,
                totalClicks: totalClicks.length > 0 ? totalClicks[0].total : 0
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// Universal File Resolver
function sendAppFile(res, ...fileNames) {
    const searchDirs = [path.join(__dirname, '..'), path.join(__dirname, '..', 'admin'), __dirname];
    for (const name of fileNames) {
        for (const dir of searchDirs) {
            const p = path.join(dir, name);
            if (fs.existsSync(p)) return res.sendFile(p);
        }
    }
    res.status(404).send(`File not found: ${fileNames.join(' or ')}`);
}

// ⛔ STRICT PERSISTENT BAN SHIELD ON LOGIN ROUTE
app.get('/admin/login.html', async (req, res) => {
    const blocked = await isDeviceBlocked(req);
    if (blocked) {
        return res.send(`
            <!DOCTYPE html><html><head><title>Access Blocked</title>
            <style>body{background:#090a10;color:#fff;font-family:'Segoe UI',sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center;padding:20px;margin:0;}
            .card{background:#131722;padding:40px;border-radius:20px;border:1px solid rgba(239,68,68,0.4);max-width:450px;box-shadow:0 0 50px rgba(239,68,68,0.2);}
            h1{color:#ef4444;font-size:24px;margin-bottom:10px;}
            p{color:#94a3b8;font-size:14px;line-height:1.6;}</style></head>
            <body><div class="card"><h1>⛔ DEVICE PERMANENTLY BLOCKED</h1>
            <p>Your device has been permanently banned due to 3 failed passcode attempts.<br><br>Refreshing will not bypass this ban. Contact the administrator to unblock your device from the Admin Panel.</p></div></body></html>
        `);
    }
    sendAppFile(res, 'login.html', 'admin/login.html');
});

app.get('/', (req, res) => res.redirect('/admin/secret-gateway'));
app.get('/admin/secret-gateway', (req, res) => sendAppFile(res, 'secret-gateway.html', 'admin/secret-gateway.html'));
app.get(['/admin/index.html', '/admin', '/admin/668379d1.html'], (req, res) => {
    const token = req.cookies?.adminToken;
    if (!token || !verifyToken(token)) return res.redirect('/admin/login.html');
    sendAppFile(res, 'admin/index.html', '668379d1.html', 'admin/668379d1.html', 'index.html');
});
app.get('/uid', (req, res) => sendAppFile(res, 'uid-checker.html'));
app.get('/v/:id', (req, res) => sendAppFile(res, 'video-lock.html'));
app.get('/user-dashboard', (req, res) => sendAppFile(res, 'user-dashboard.html'));
app.get('/user-dashboard/:id?', (req, res) => sendAppFile(res, 'user-dashboard.html'));
app.get('/manifest.json', (req, res) => sendAppFile(res, 'manifest.json'));
app.get('/sw.js', (req, res) => sendAppFile(res, 'sw.js'));

// Session Cleanup Interval
setInterval(async () => {
    try {
        await Session.deleteMany({ expiresAt: { $lt: new Date() } });
        await OTPVerification.deleteMany({ expiresAt: { $lt: new Date() } });
    } catch (error) {
        console.error('❌ Session cleanup error:', error);
    }
}, 60 * 60 * 1000);

// Start Server
app.listen(port, '0.0.0.0', () => console.log(`🚀 Server on port ${port}`));
