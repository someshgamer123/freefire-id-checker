require('dotenv').config();
const express = require('express');
const app = express();
const port = process.env.PORT || 3000;
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

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

// ==================== Security Module ====================
const Security = require('./config/security');

// Connect to MongoDB
connectDB();

// ==================== Environment Variables ====================
const ADMIN_PASSCODE = process.env.ADMIN_PASSCODE || 'Admin@2024#Secure';
const MAX_LOGIN_ATTEMPTS = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 20;
const LOCKOUT_TIME = parseInt(process.env.LOCKOUT_TIME) || 30;
const SESSION_TIMEOUT = parseInt(process.env.SESSION_TIMEOUT) || 60;
const IP_WHITELIST = process.env.IP_WHITELIST || '0.0.0.0/0';
const ENABLE_2FA = process.env.ENABLE_2FA !== 'false';

// ==================== Initialize Default Data ====================
async function initializeDatabase() {
    try {
        const adminExists = await User.findOne();
        if (!adminExists) {
            const hashedPasscode = bcrypt.hashSync(ADMIN_PASSCODE, 10);
            await User.create({
                passcode: hashedPasscode,
                theme: 'light'
            });
            console.log('✅ Admin user created');

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
        }

        const statsExists = await Stats.findOne();
        if (!statsExists) {
            await Stats.create({});
            console.log('✅ Stats initialized');
        }

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
                    '3days': 50,
                    '7days': 100,
                    '15days': 200,
                    '1month': 500,
                    '3months': 1200,
                    '6months': 2000,
                    '12months': 3500
                },
                paymentSettings: {
                    method: 'UPI',
                    details: { upiId: 'admin@upi', qrCode: null, text: '' }
                },
                whatsappNumber: '919876543210'
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
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net"],
            scriptSrcElem: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            styleSrcAttr: ["'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "http:"],
            connectSrc: ["'self'"],
            frameSrc: ["'self'", "https://www.youtube.com", "https://*.image2url.com", "https://*.terabox.com", "*"],
            mediaSrc: ["'self'", "https:", "http:", "https://*.image2url.com", "https://*.terabox.com", "*"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    frameguard: { action: 'deny' },
    noSniff: true,
    xssFilter: true,
    hidePoweredBy: true
}));

app.use(cors({
    origin: ['http://localhost:3000', 'https://freefire-id-checker.onrender.com'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

// ==================== Rate Limiting ====================
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: 'Too many requests, please try again later.'
});
app.use('/api', globalLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: MAX_LOGIN_ATTEMPTS,
    message: 'Too many login attempts, try after 30 minutes.'
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.use(express.static('.'));

// ==================== JWT & Auth ====================
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
    return { ip, userAgent, fingerprint: crypto.createHash('sha256').update(ip + userAgent).digest('hex') };
}

// ==================== Logging Function ====================
async function logAdminAction(userId, action, details = {}, req = null) {
    try {
        const ip = req?.ip || req?.connection?.remoteAddress || null;
        const userAgent = req?.headers?.['user-agent'] || null;
        await AdminLog.create({ userId, action, details, ip, userAgent, timestamp: new Date() });
    } catch (error) {
        console.error('❌ Logging error:', error);
    }
}

// ==================== Login Attempt Tracking ====================
async function checkLoginAttempts(ip) {
    const record = await LoginAttempt.findOne({ ip });
    if (!record) return { allowed: true, attempts: 0 };
    if (record.lockedUntil && record.lockedUntil > new Date()) {
        const remainingMinutes = Math.ceil((record.lockedUntil - new Date()) / (1000 * 60));
        return { allowed: false, attempts: record.attempts, lockedUntil: record.lockedUntil, remainingMinutes };
    }
    if (record.lockedUntil && record.lockedUntil < new Date()) {
        record.attempts = 0;
        record.lockedUntil = null;
        await record.save();
        return { allowed: true, attempts: 0 };
    }
    return { allowed: record.attempts < MAX_LOGIN_ATTEMPTS, attempts: record.attempts };
}

async function recordLoginAttempt(ip, success) {
    let record = await LoginAttempt.findOne({ ip });
    if (!record) record = new LoginAttempt({ ip });
    if (success) {
        record.attempts = 0;
        record.lockedUntil = null;
    } else {
        record.attempts = (record.attempts || 0) + 1;
        record.lastAttempt = new Date();
        if (record.attempts >= MAX_LOGIN_ATTEMPTS) {
            record.lockedUntil = new Date(Date.now() + LOCKOUT_TIME * 60 * 1000);
        }
    }
    await record.save();
    return record;
}

// ==================== Session Management ====================
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

async function invalidateSession(token) {
    await Session.findOneAndUpdate({ token }, { isActive: false });
}

async function invalidateAllSessions(userId) {
    await Session.updateMany({ userId, isActive: true }, { isActive: false });
}

// ==================== Auth Middleware ====================
async function authMiddleware(req, res, next) {
    const token = req.cookies?.adminToken;
    const csrfToken = req.headers['x-csrf-token'];
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid or expired token' });
    const session = await validateSession(token);
    if (!session) {
        res.clearCookie('adminToken');
        return res.status(401).json({ error: 'Session expired. Please login again.' });
    }
    if (csrfToken !== session.csrfToken) {
        await logAdminAction('admin', 'CSRF_ATTEMPT', { token }, req);
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    const { ip } = getDeviceId(req);
    if (!Security.isIPWhitelisted(ip, IP_WHITELIST)) {
        await logAdminAction('admin', 'IP_BLOCKED', { ip }, req);
        return res.status(403).json({ error: 'Access denied from this IP address' });
    }
    req.user = decoded;
    req.session = session;
    next();
}

// ================================================================
// ==================== PUBLIC ROUTES (NO AUTH) ====================
// ================================================================

app.get('/api/whatsapp-number', async (req, res) => {
    try {
        const pricing = await Pricing.findOne();
        res.json({ number: pricing?.whatsappNumber || '919876543210' });
    } catch (error) {
        res.json({ number: '919876543210' });
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
        console.error('❌ Dashboard map error:', error);
        res.status(500).json({ error: 'Failed to map dashboard' });
    }
});

app.get('/api/visit-stats/:linkId', async (req, res) => {
    try {
        const { linkId } = req.params;
        let link = await Link.findOne({ id: linkId });
        if (!link) link = await Link.findOne({ dashboardId: linkId });
        if (!link) {
            const allLinks = await Link.find({});
            const matched = allLinks.find(l => 
                l.id.includes(linkId) || 
                (l.dashboardId && l.dashboardId.includes(linkId)) ||
                linkId.includes(l.id)
            );
            if (matched) link = matched;
        }
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
            status: link.status,
            expiryDate: link.expiryDate || null
        });
    } catch (error) {
        console.error('❌ Visit stats error:', error);
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
        console.error('❌ Parent link error:', error);
        res.status(500).json({ error: 'Failed to generate dashboard link' });
    }
});

app.get('/api/pricing', async (req, res) => {
    try {
        const pricingDoc = await Pricing.findOne();
        res.json({
            pricing: pricingDoc?.pricing || {},
            paymentSettings: pricingDoc?.paymentSettings || { method: 'UPI', details: { upiId: 'admin@upi' } },
            whatsappNumber: pricingDoc?.whatsappNumber || '919876543210'
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch pricing' });
    }
});

app.get('/api/link/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const link = await Link.findOne({ id });
        if (!link) return res.status(404).json({ error: 'not_found', message: 'Link not found' });
        if (link.status === 'suspended') {
            return res.status(403).json({ error: 'suspended', message: 'Link suspended', status: 'suspended' });
        }
        if (link.status === 'disabled') {
            return res.status(403).json({ error: 'disabled', message: 'Link disabled', status: 'disabled' });
        }
        if (link.expiryDate && new Date() > new Date(link.expiryDate)) {
            return res.status(403).json({ error: 'expired', message: 'Link expired', status: 'expired' });
        }
        if (link.status !== 'active') {
            return res.status(403).json({ error: 'inactive', message: 'Link inactive', status: 'inactive' });
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
        console.error('❌ Fetch link error:', error);
        res.status(500).json({ error: 'Failed to fetch link' });
    }
});

app.post('/api/track-claim/:linkId', async (req, res) => {
    try {
        const { linkId } = req.params;
        const link = await Link.findOne({ id: linkId });
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
        console.error('❌ Track claim error:', error);
        res.status(500).json({ error: 'Failed to track claim' });
    }
});

app.get('/api/renewal/history/:linkId', async (req, res) => {
    try {
        const { linkId } = req.params;
        const history = await RenewalRequest.find({ linkId }).sort({ createdAt: -1 });
        res.json({ history, count: history.length });
    } catch (error) {
        console.error('❌ Renewal history error:', error);
        res.status(500).json({ error: 'Failed to fetch history' });
    }
});

app.post('/api/renewal/request-from-dashboard', async (req, res) => {
    try {
        const { linkId, linkName, plan, days, amount } = req.body;
        if (!linkId || !plan) return res.status(400).json({ error: 'Link ID and plan required' });
        const existing = await RenewalRequest.findOne({ linkId, status: { $in: ['pending', 'paid'] } });
        if (existing) {
            return res.status(400).json({ error: 'You already have a pending renewal request', existingRequest: existing });
        }
        const renewalRequest = new RenewalRequest({
            id: 'renewal_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex'),
            linkId, linkName: linkName || 'Unknown', plan, days: days || 0, amount: amount || 0,
            status: 'pending', createdAt: new Date(), paidAt: null, approvedAt: null, transactionId: null, upiId: 'pending'
        });
        await renewalRequest.save();
        res.json({ success: true, requestId: renewalRequest.id, message: 'Renewal request created successfully' });
    } catch (error) {
        console.error('❌ Renewal request error:', error);
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
            theme: admin?.theme || 'light',
            background: popupSettings?.image || null,
            popupSettings: popupSettings || {
                image: null,
                title: '🎁 Claim Your Reward',
                buttonText: 'Claim Now',
                subtitle: 'Tap below to unlock your reward'
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

app.get('/api/popup-settings/:linkId?', async (req, res) => {
    try {
        const { linkId } = req.params;
        if (linkId) {
            const link = await Link.findOne({ id: linkId });
            if (!link) return res.status(404).json({ error: 'Link not found' });
            return res.json(link.popupSettings || {
                image: null,
                title: '🎁 Claim Your Reward',
                buttonText: 'Claim Now',
                subtitle: 'Tap below to unlock your reward'
            });
        }
        const popupSettings = await PopupSettings.findOne();
        res.json(popupSettings || {
            image: null,
            title: '🎁 Claim Your Reward',
            buttonText: 'Claim Now',
            subtitle: 'Tap below to unlock your reward'
        });
    } catch (error) {
        console.error('❌ Popup settings error:', error);
        res.status(500).json({ error: 'Failed to fetch popup settings' });
    }
});

// ================================================================
// ==================== ADMIN ROUTES (AUTH REQUIRED) ===============
// ================================================================

// ==================== ADMIN LOGIN ====================
app.post('/api/admin/login', authLimiter, async (req, res) => {
    try {
        const { passcode, token } = req.body;
        const { ip, userAgent } = getDeviceId(req);
        
        const attemptCheck = await checkLoginAttempts(ip);
        if (!attemptCheck.allowed) {
            await logAdminAction('admin', 'LOGIN_LOCKED', { 
                ip: ip, 
                remainingMinutes: attemptCheck.remainingMinutes 
            }, req);
            return res.status(429).json({ 
                error: `Too many attempts. Account locked for ${attemptCheck.remainingMinutes} minutes.` 
            });
        }
        
        if (!passcode) {
            return res.status(400).json({ error: 'Passcode required' });
        }
        
        const admin = await User.findOne();
        if (!admin) {
            return res.status(500).json({ error: 'Admin not found' });
        }
        
        const isValid = bcrypt.compareSync(passcode, admin.passcode);
        
        if (!isValid) {
            await recordLoginAttempt(ip, false);
            await logAdminAction('admin', 'LOGIN_FAILED', { ip: ip }, req);
            return res.status(401).json({ error: 'Invalid passcode' });
        }
        
        if (ENABLE_2FA) {
            const twoFactor = await TwoFactorAuth.findOne({ userId: 'admin' });
            if (twoFactor && twoFactor.isEnabled) {
                if (!token) {
                    return res.status(200).json({ 
                        requires2FA: true,
                        message: '2FA token required'
                    });
                }
                
                const isValid2FA = Security.verify2FAToken(twoFactor.secret, token);
                if (!isValid2FA) {
                    await logAdminAction('admin', '2FA_FAILED', { ip: ip }, req);
                    return res.status(401).json({ error: 'Invalid 2FA token' });
                }
            }
        }
        
        await recordLoginAttempt(ip, true);
        
        const jwtToken = generateToken('admin');
        const csrfToken = generateCSRFToken();
        
        await createSession(jwtToken, 'admin', csrfToken, ip, userAgent);
        
        await logAdminAction('admin', 'LOGIN', { ip: ip }, req);
        
        res.cookie('adminToken', jwtToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production' || true,
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/'
        });
        
        res.json({
            success: true,
            csrfToken: csrfToken,
            requires2FA: false
        });
        
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ADMIN LOGOUT
app.post('/api/admin/logout', authMiddleware, async (req, res) => {
    try {
        const token = req.cookies?.adminToken;
        if (token) {
            await invalidateSession(token);
            await logAdminAction('admin', 'LOGOUT', {}, req);
        }
        res.clearCookie('adminToken');
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Logout failed' });
    }
});

// ADMIN PASSCODE CHANGE
app.post('/api/admin/passcode', authMiddleware, async (req, res) => {
    try {
        const { oldPasscode, newPasscode } = req.body;
        if (!oldPasscode || !newPasscode) return res.status(400).json({ error: 'Both passcodes required' });
        const passwordCheck = Security.isStrongPassword(newPasscode);
        if (!passwordCheck.valid) return res.status(400).json({ error: passwordCheck.message });
        const admin = await User.findOne();
        if (!admin) return res.status(500).json({ error: 'Admin not found' });
        const isValid = bcrypt.compareSync(oldPasscode, admin.passcode);
        if (!isValid) {
            await logAdminAction('admin', 'PASSCODE_CHANGE_FAILED', {}, req);
            return res.status(401).json({ error: 'Current passcode is incorrect' });
        }
        admin.passcode = bcrypt.hashSync(newPasscode, 10);
        await admin.save();
        await invalidateAllSessions('admin');
        await logAdminAction('admin', 'PASSCODE_CHANGE', {}, req);
        res.clearCookie('adminToken');
        res.json({ success: true, message: 'Passcode changed. Please login again.' });
    } catch (error) {
        console.error('❌ Passcode change error:', error);
        res.status(500).json({ error: 'Passcode change failed' });
    }
});

// ADMIN THEME
app.post('/api/admin/theme', authMiddleware, async (req, res) => {
    try {
        const { theme } = req.body;
        if (!['light', 'dark'].includes(theme)) return res.status(400).json({ error: 'Invalid theme' });
        const admin = await User.findOne();
        if (admin) { admin.theme = theme; await admin.save(); }
        await logAdminAction('admin', 'THEME_CHANGE', { theme }, req);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update theme' });
    }
});

// ADMIN BACKGROUND
app.post('/api/admin/background', authMiddleware, async (req, res) => {
    try {
        const { background } = req.body;
        if (background && !background.startsWith('data:image') && !background.startsWith('http')) {
            return res.status(400).json({ error: 'Invalid image format' });
        }
        const popupSettings = await PopupSettings.findOne();
        if (popupSettings) { popupSettings.image = background || null; await popupSettings.save(); }
        await logAdminAction('admin', 'BACKGROUND_CHANGE', { hasImage: !!background }, req);
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Background update error:', error);
        res.status(500).json({ error: 'Failed to update background' });
    }
});

// ADMIN LOGS
app.get('/api/admin/logs', authMiddleware, async (req, res) => {
    try {
        const { limit = 50, action, from, to } = req.query;
        const query = {};
        if (action) query.action = action;
        if (from || to) {
            query.timestamp = {};
            if (from) query.timestamp.$gte = new Date(from);
            if (to) query.timestamp.$lte = new Date(to);
        }
        const logs = await AdminLog.find(query).sort({ timestamp: -1 }).limit(parseInt(limit));
        const count = await AdminLog.countDocuments(query);
        res.json({ logs, count, limit: parseInt(limit) });
    } catch (error) {
        console.error('❌ Logs error:', error);
        res.status(500).json({ error: 'Failed to fetch logs' });
    }
});

// ADMIN WHATSAPP
app.post('/api/admin/whatsapp', authMiddleware, async (req, res) => {
    try {
        const { number } = req.body;
        if (!number) return res.status(400).json({ error: 'WhatsApp number required' });
        let pricing = await Pricing.findOne();
        if (!pricing) pricing = new Pricing();
        pricing.whatsappNumber = number;
        await pricing.save();
        await logAdminAction('admin', 'UPDATE_WHATSAPP', { number }, req);
        res.json({ success: true, number });
    } catch (error) {
        console.error('❌ WhatsApp number save error:', error);
        res.status(500).json({ error: 'Failed to save WhatsApp number' });
    }
});

// LINKS CRUD
app.get('/api/links', authMiddleware, async (req, res) => {
    try {
        const links = await Link.find().sort({ created: -1 });
        res.json(links);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch links' });
    }
});

app.post('/api/links', authMiddleware, async (req, res) => {
    try {
        const { name, video, claim, buttonText, headline, expiryDate, popupSettings } = req.body;
        if (!name || name.length < 1 || name.length > 100) {
            return res.status(400).json({ error: 'Invalid link name (1-100 characters)' });
        }
        const urlRegex = /^(https?:\/\/[^\s]+)$/;
        if (video && !urlRegex.test(video)) return res.status(400).json({ error: 'Invalid video URL format' });
        if (claim && claim !== '#' && !urlRegex.test(claim)) return res.status(400).json({ error: 'Invalid claim URL format' });
        const newLink = new Link({
            id: 'link_' + Date.now() + '_' + crypto.randomBytes(8).toString('hex'),
            name: name.substring(0, 100),
            video: video || 'https://youtu.be/dQw4w9WgXcQ',
            claim: claim || '#',
            buttonText: (buttonText || 'Claim Now').substring(0, 50),
            headline: (headline || '').substring(0, 200),
            expiryDate: expiryDate || null,
            status: 'active',
            popupSettings: popupSettings || {
                image: null,
                title: '🎁 Claim Your Reward',
                buttonText: 'Claim Now',
                subtitle: 'Tap below to unlock your reward'
            }
        });
        await newLink.save();
        await logAdminAction('admin', 'CREATE_LINK', { linkId: newLink.id, name: newLink.name }, req);
        res.json(newLink);
    } catch (error) {
        console.error('❌ Create link error:', error);
        res.status(500).json({ error: 'Failed to create link' });
    }
});

app.put('/api/links/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, video, claim, buttonText, headline, status, expiryDate, popupSettings } = req.body;
        const link = await Link.findOne({ id });
        if (!link) return res.status(404).json({ error: 'Link not found' });
        if (name && (name.length < 1 || name.length > 100)) return res.status(400).json({ error: 'Invalid link name' });
        const urlRegex = /^(https?:\/\/[^\s]+)$/;
        if (video && !urlRegex.test(video)) return res.status(400).json({ error: 'Invalid video URL' });
        if (claim && claim !== '#' && !urlRegex.test(claim)) return res.status(400).json({ error: 'Invalid claim URL' });
        const changes = {};
        if (name !== undefined) { link.name = name.substring(0, 100); changes.name = name; }
        if (video !== undefined) { link.video = video; changes.video = video; }
        if (claim !== undefined) { link.claim = claim; changes.claim = claim; }
        if (buttonText !== undefined) { link.buttonText = buttonText.substring(0, 50); changes.buttonText = buttonText; }
        if (headline !== undefined) { link.headline = headline.substring(0, 200); changes.headline = headline; }
        if (status !== undefined && ['active', 'suspended', 'disabled'].includes(status)) {
            link.status = status; changes.status = status;
        }
        if (expiryDate !== undefined) { link.expiryDate = expiryDate; changes.expiryDate = expiryDate; }
        if (popupSettings !== undefined) {
            link.popupSettings = { ...link.popupSettings, ...popupSettings };
            changes.popupSettings = popupSettings;
        }
        await link.save();
        await logAdminAction('admin', 'UPDATE_LINK', { linkId: link.id, changes }, req);
        res.json(link);
    } catch (error) {
        console.error('❌ Update link error:', error);
        res.status(500).json({ error: 'Failed to update link' });
    }
});

app.put('/api/links/:id/status', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        if (!['active', 'suspended', 'disabled'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
        const link = await Link.findOne({ id });
        if (!link) return res.status(404).json({ error: 'Link not found' });
        link.status = status;
        await link.save();
        await logAdminAction('admin', 'UPDATE_STATUS', { linkId: link.id, name: link.name, newStatus: status }, req);
        res.json(link);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update status' });
    }
});

app.delete('/api/links/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const link = await Link.findOne({ id });
        if (link) await logAdminAction('admin', 'DELETE_LINK', { linkId: link.id, name: link.name }, req);
        await Link.findOneAndDelete({ id });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete link' });
    }
});

// ADMIN PRICING
app.post('/api/admin/pricing', authMiddleware, async (req, res) => {
    try {
        const { pricing, paymentSettings } = req.body;
        let pricingDoc = await Pricing.findOne();
        if (!pricingDoc) pricingDoc = new Pricing();
        if (pricing) pricingDoc.pricing = pricing;
        if (paymentSettings) pricingDoc.paymentSettings = paymentSettings;
        pricingDoc.updatedAt = new Date();
        await pricingDoc.save();
        await logAdminAction('admin', 'UPDATE_PRICING', { pricing }, req);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update pricing' });
    }
});

// SEARCH LINKS
app.get('/api/search-links', authMiddleware, async (req, res) => {
    try {
        const { query } = req.query;
        if (!query || query.length < 1) return res.json({ links: [] });
        const searchRegex = new RegExp(query, 'i');
        const links = await Link.find({
            $or: [{ name: searchRegex }, { id: searchRegex }, { dashboardId: searchRegex }]
        }).limit(20).sort({ created: -1 });
        res.json({ links, count: links.length, query });
    } catch (error) {
        console.error('❌ Search links error:', error);
        res.status(500).json({ error: 'Failed to search links' });
    }
});

// GENERATE DASHBOARD LINK
app.post('/api/generate-dashboard-link', authMiddleware, async (req, res) => {
    try {
        const { linkId } = req.body;
        if (!linkId) return res.status(400).json({ error: 'Link ID required' });
        const link = await Link.findOne({ id: linkId });
        if (!link) return res.status(404).json({ error: 'Link not found' });
        const dashboardId = 'dashboard_' + Date.now() + '_' + crypto.randomBytes(8).toString('hex');
        link.dashboardId = dashboardId;
        await link.save();
        const dashboardUrl = '/user-dashboard/' + dashboardId;
        const fullUrl = req.protocol + '://' + req.get('host') + dashboardUrl;
        await logAdminAction('admin', 'CREATE_DASHBOARD_LINK', { linkId, dashboardId }, req);
        res.json({ success: true, dashboardId, dashboardUrl, fullUrl, linkName: link.name, linkId: link.id });
    } catch (error) {
        console.error('❌ Generate dashboard link error:', error);
        res.status(500).json({ error: 'Failed to generate dashboard link' });
    }
});

// ADMIN STATS
app.get('/api/all-stats', authMiddleware, async (req, res) => {
    try {
        const links = await Link.find();
        const stats = await Stats.findOne();
        const today = new Date().toISOString().split('T')[0];
        const linkStats = links.map(link => ({
            id: link.id,
            name: link.name,
            visits: link.visits || 0,
            claims: link.claims || 0,
            dailyVisits: Object.fromEntries(link.dailyVisits || new Map()),
            dailyClaims: Object.fromEntries(link.dailyClaims || new Map()),
            todayVisits: link.dailyVisits?.get(today) || 0,
            todayClaims: link.dailyClaims?.get(today) || 0,
            status: link.status,
            expiryDate: link.expiryDate || null
        }));
        res.json({
            global: {
                totalVisitors: stats?.totalVisitors || 0,
                totalClaims: stats?.totalClaims || 0,
                todayVisitors: stats?.dailyVisitors?.get(today) || 0,
                todayClaims: stats?.dailyClaims?.get(today) || 0,
                dailyVisitors: Object.fromEntries(stats?.dailyVisitors || new Map()),
                dailyClaims: Object.fromEntries(stats?.dailyClaims || new Map())
            },
            links: linkStats
        });
    } catch (error) {
        console.error('❌ Stats error:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// RENEWAL REQUESTS
app.get('/api/renewal/requests', authMiddleware, async (req, res) => {
    try {
        const requests = await RenewalRequest.find({ status: { $in: ['pending', 'paid'] } }).sort({ createdAt: -1 });
        res.json(requests);
    } catch (error) {
        console.error('❌ Renewal requests error:', error);
        res.status(500).json({ error: 'Failed to fetch renewal requests' });
    }
});

app.post('/api/renewal/pay/:requestId', authMiddleware, async (req, res) => {
    try {
        const { requestId } = req.params;
        const request = await RenewalRequest.findOne({ id: requestId });
        if (!request) return res.status(404).json({ error: 'Request not found' });
        if (request.status === 'approved' || request.status === 'rejected') {
            return res.status(400).json({ error: 'Request already processed' });
        }
        request.status = 'paid';
        request.paidAt = new Date();
        await request.save();
        await logAdminAction('admin', 'MARK_PAID', { requestId, linkId: request.linkId }, req);
        res.json({ success: true, message: 'Payment marked as paid' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to mark payment' });
    }
});

app.post('/api/renewal/approve/:requestId', authMiddleware, async (req, res) => {
    try {
        const { requestId } = req.params;
        const request = await RenewalRequest.findOne({ id: requestId });
        if (!request) return res.status(404).json({ error: 'Request not found' });
        if (request.status !== 'paid') return res.status(400).json({ error: 'Payment not confirmed yet' });
        const link = await Link.findOne({ id: request.linkId });
        if (link) {
            const currentExpiry = link.expiryDate ? new Date(link.expiryDate) : new Date();
            const newExpiry = new Date(currentExpiry);
            newExpiry.setDate(newExpiry.getDate() + request.days);
            link.expiryDate = newExpiry.toISOString();
            link.status = 'active';
            await link.save();
        }
        request.status = 'approved';
        request.approvedAt = new Date();
        await request.save();
        await logAdminAction('admin', 'APPROVE_RENEWAL', { requestId, linkId: request.linkId, plan: request.plan }, req);
        res.json({ success: true, message: 'Renewal approved! Link extended.' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to approve renewal' });
    }
});

app.post('/api/renewal/reject/:requestId', authMiddleware, async (req, res) => {
    try {
        const { requestId } = req.params;
        const request = await RenewalRequest.findOne({ id: requestId });
        if (!request) return res.status(404).json({ error: 'Request not found' });
        request.status = 'rejected';
        await request.save();
        await logAdminAction('admin', 'REJECT_RENEWAL', { requestId, linkId: request.linkId }, req);
        res.json({ success: true, message: 'Renewal rejected' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to reject renewal' });
    }
});

app.delete('/api/renewal/request/:requestId', authMiddleware, async (req, res) => {
    try {
        const { requestId } = req.params;
        const request = await RenewalRequest.findOne({ id: requestId });
        if (request) await logAdminAction('admin', 'DELETE_RENEWAL', { requestId, linkId: request.linkId }, req);
        await RenewalRequest.findOneAndDelete({ id: requestId });
        res.json({ success: true, message: 'Request removed' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to remove request' });
    }
});

// ==================== SERVE PAGES ====================
app.get('/uid', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'uid-checker.html'));
});

app.get('/v/:id', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'video-lock.html'));
});

app.get('/user-dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'user-dashboard.html'));
});

app.get('/user-dashboard/:id', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'user-dashboard.html'));
});

app.get('/admin/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'admin', 'login.html'));
});

app.get('/admin/index.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'admin', 'index.html'));
});

app.get('/manifest.json', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'manifest.json'));
});

app.get('/sw.js', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'sw.js'));
});

app.get('/', (req, res) => {
    res.redirect('/admin/login.html');
});

// ==================== Session Cleanup ====================
setInterval(async () => {
    try {
        const result = await Session.deleteMany({ expiresAt: { $lt: new Date() } });
        if (result.deletedCount > 0) console.log(`🧹 Cleaned ${result.deletedCount} expired sessions`);
    } catch (error) {
        console.error('❌ Session cleanup error:', error);
    }
}, 60 * 60 * 1000);

// ==================== START SERVER ====================
app.listen(port, '0.0.0.0', () => {
    console.log('═══════════════════════════════════════════');
    console.log('🔒 SECURE SERVER STARTED SUCCESSFULLY!');
    console.log('═══════════════════════════════════════════');
    console.log(`🔧 Admin Panel: http://localhost:${port}/admin/login.html`);
    console.log(`📊 API: http://localhost:${port}/api/links`);
    console.log(`📊 Stats API: http://localhost:${port}/api/all-stats`);
    console.log('═══════════════════════════════════════════');
    console.log('🔑 ADMIN PASSCODE: 951753');
    console.log('⏰ Session: 7 DAYS');
    console.log('🔐 2FA: ' + (ENABLE_2FA ? '✅ Enabled' : '❌ Disabled'));
    console.log('🛡️ IP Whitelist: ' + IP_WHITELIST);
    console.log('⏰ Session Timeout: ' + SESSION_TIMEOUT + ' minutes');
    console.log('🔒 Max Login Attempts: ' + MAX_LOGIN_ATTEMPTS);
    console.log('📋 Audit Logging: ✅ Enabled');
    console.log('📊 48hr Unique Visitor Tracking: ✅ Enabled');
    console.log('📊 Claim Tracking: Only on Main Claim Button');
    console.log('📱 WhatsApp: Renewal requests via WhatsApp');
    console.log('🔍 Dashboard Map: dashboard_xxx → link_xxx mapping');
    console.log('📹 Video CSP: All media sources allowed');
    console.log('📦 CDN: cdn.jsdelivr.net allowed for html2canvas');
    console.log('🗄️ Database: MongoDB Atlas');
    console.log('═══════════════════════════════════════════');
});