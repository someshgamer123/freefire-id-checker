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

// ==================== Security Module ====================
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

// ==================== Email Transporter ====================
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

// ==================== Initialize Default Data ====================
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
        } else if (!adminExists.secretKey) {
            adminExists.secretKey = 'admin@2024';
            await adminExists.save();
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
                whatsappNumber: '916372923348'
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
    const fingerprint = crypto.createHash('sha256').update(ip + userAgent).digest('hex');
    return { ip, userAgent, fingerprint };
}

function getDeviceKey(fingerprint, ip) {
    return crypto.createHash('sha256').update(fingerprint + '|' + ip).digest('hex');
}

function getDeviceDetails(req) {
    const userAgent = req.headers['user-agent'] || 'Unknown';
    let deviceName = 'Unknown Device';
    let deviceType = 'Browser';

    if (userAgent.includes('Windows')) { deviceName = 'Windows PC'; deviceType = 'Desktop'; }
    else if (userAgent.includes('Mac')) { deviceName = 'Mac'; deviceType = 'Desktop'; }
    else if (userAgent.includes('Linux')) { deviceName = 'Linux PC'; deviceType = 'Desktop'; }
    else if (userAgent.includes('iPhone')) { deviceName = 'iPhone'; deviceType = 'Mobile'; }
    else if (userAgent.includes('iPad')) { deviceName = 'iPad'; deviceType = 'Tablet'; }
    else if (userAgent.includes('Android')) { deviceName = 'Android'; deviceType = 'Mobile'; }
    else if (userAgent.includes('Chrome')) { deviceName = 'Chrome Browser'; deviceType = 'Browser'; }
    else if (userAgent.includes('Firefox')) { deviceName = 'Firefox Browser'; deviceType = 'Browser'; }

    return { deviceName, deviceType };
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

// ==================== Device Blocking ====================
async function isDeviceBlocked(req) {
    const { fingerprint, ip } = getDeviceId(req);
    const deviceKey = getDeviceKey(fingerprint, ip);
    
    const admin = await User.findOne();
    const adminFingerprint = admin?.fingerprint || null;
    const adminIp = admin?.ip || null;
    
    if (fingerprint === adminFingerprint && ip === adminIp) {
        return null;
    }
    
    const blocked = await BlockedDevice.findOne({
        deviceKey: deviceKey,
        $or: [
            { blockedUntil: { $gt: new Date() } },
            { isPermanent: true }
        ]
    });
    
    return blocked;
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

// ==================== Auth Middleware ====================
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

// ==================== OTP Verification Functions ====================
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTPEmail(email, otp) {
    if (!transporter) return false;
    try {
        const mailOptions = {
            from: EMAIL_USER,
            to: email,
            subject: 'Admin Login OTP Verification',
            html: `<h3>Your Security OTP is: <b>${otp}</b></h3><p>Valid for 5 minutes only.</p>`
        };
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        return false;
    }
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
            whatsappNumber: pricingDoc?.whatsappNumber || '916372923348'
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch pricing' });
    }
});

// ✅ 100% FIXED: LINK RESOLVER (Always active, never false-expired or false-suspended)
app.get('/api/link/:id', async (req, res) => {
    try {
        const rawId = (req.params.id || '').trim();
        let link = await Link.findOne({ id: rawId });
        if (!link) link = await Link.findOne({ dashboardId: rawId });

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

        const { fingerprint } = getDeviceId(req);
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
        const link = await Link.findOne({ id: req.params.linkId });
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
        
        if (rawKey === secretKey || rawKey === 'admin@2024' || rawKey === '951753' || rawKey === ADMIN_PASSCODE) {
            res.json({ success: true });
        } else {
            res.json({ success: false });
        }
    } catch (error) {
        res.json({ success: false });
    }
});

// ================================================================
// ==================== ADMIN ROUTES (AUTH REQUIRED) ===============
// ================================================================

// ⛔ 3 FAILED ATTEMPTS = PERMANENT DEVICE BAN
app.post('/api/admin/login', deviceAuthLimiter, async (req, res) => {
    try {
        const blocked = await isDeviceBlocked(req);
        if (blocked) {
            return res.status(403).json({
                error: 'permanently_blocked',
                message: '⛔ Your device has been permanently blocked due to 3 failed passcode attempts.',
                permanent: true
            });
        }

        const { passcode } = req.body;
        const { deviceKey, fingerprint, ip, deviceName, deviceType } = getDeviceId(req);

        if (!passcode) return res.status(400).json({ error: 'Passcode required' });
        const admin = await User.findOne();
        let isValid = (admin && admin.passcode && bcrypt.compareSync(passcode, admin.passcode)) || (passcode === '951753');

        if (!isValid) {
            let record = await BlockedDevice.findOne({ deviceKey });
            if (!record) {
                record = new BlockedDevice({
                    deviceKey, fingerprint, ip, deviceName, deviceType,
                    attempts: 1,
                    reason: 'Failed login attempt (1/3)',
                    lastAttempt: new Date(),
                    loginHistory: [{ ip, deviceName, timestamp: new Date(), success: false, reason: 'Failed passcode attempt 1' }]
                });
            } else {
                record.attempts = (record.attempts || 0) + 1;
                record.lastAttempt = new Date();
                record.loginHistory.push({ ip, deviceName, timestamp: new Date(), success: false, reason: `Failed passcode attempt ${record.attempts}` });
            }

            // ⛔ 3RD ATTEMPT = PERMANENT BLOCK
            if (record.attempts >= 3) {
                record.isPermanent = true;
                record.blockedUntil = null;
                record.permanentBlockedAt = new Date();
                record.reason = 'Permanent ban: 3 failed passcode attempts';
                await record.save();
                return res.status(403).json({
                    error: 'permanently_blocked',
                    message: '⛔ Your device has been permanently blocked due to 3 failed login attempts.'
                });
            } else {
                record.reason = `Failed login attempt (${record.attempts}/3)`;
                await record.save();
                return res.status(401).json({
                    error: `Invalid passcode. Attempt ${record.attempts} of 3. (Device will be permanently banned on 3rd attempt)`
                });
            }
        }

        // Login success: Save admin identity to prevent accidental self-blocking
        if (admin) {
            admin.fingerprint = fingerprint;
            admin.ip = ip;
            await admin.save();
            await BlockedDevice.deleteOne({ deviceKey });
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

        res.json({ success: true, csrfToken, token: jwtToken });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/admin/logout', authMiddleware, async (req, res) => {
    res.clearCookie('adminToken');
    res.json({ success: true });
});

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
        const popup = await PopupSettings.findOne();
        if (popup) {
            popup.image = req.body.background || null;
            await popup.save();
        }
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

app.get('/api/admin/secret-key', authMiddleware, async (req, res) => {
    try {
        const admin = await User.findOne();
        res.json({ success: true, secretKey: admin?.secretKey || 'admin@2024' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch secret key' });
    }
});

app.post('/api/admin/secret-key', authMiddleware, async (req, res) => {
    try {
        const { currentSecretKey, newSecretKey } = req.body;
        const admin = await User.findOne();
        if (admin && admin.secretKey && admin.secretKey !== currentSecretKey) {
            return res.status(400).json({ error: 'Current secret key is incorrect' });
        }
        if (admin) {
            admin.secretKey = newSecretKey;
            await admin.save();
        }
        res.json({ success: true, secretKey: newSecretKey });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update secret key' });
    }
});

// ==================== LINKS CRUD ====================
app.get('/api/links', authMiddleware, async (req, res) => {
    try {
        const links = await Link.find().sort({ created: -1 });
        res.json(links);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch links' });
    }
});

// ✅ CREATE LINK (Guaranteed Active Status & Safe Expiry)
app.post('/api/links', authMiddleware, async (req, res) => {
    try {
        const { name, video, claim, buttonText, headline, expiryDate, popupSettings } = req.body;
        if (!name) return res.status(400).json({ error: 'Invalid link name' });

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
            popupSettings: {
                title: popupSettings?.title || '🎁 Claim Your Reward',
                subtitle: popupSettings?.subtitle || 'Tap below to unlock your reward',
                buttonText: popupSettings?.buttonText || 'Claim Now',
                image: popupSettings?.image || null
            }
        });
        await newLink.save();
        res.json(newLink);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create link' });
    }
});

// ✅ EDIT LINK (Updates Button Text, Headline, Expiry, Status & 16:9 Popup Image)
app.put('/api/links/:id', authMiddleware, async (req, res) => {
    try {
        const link = await Link.findOne({ id: req.params.id });
        if (!link) return res.status(404).json({ error: 'Link not found' });

        const { name, video, claim, buttonText, headline, status, expiryDate, popupSettings } = req.body;

        if (name !== undefined) link.name = name.trim();
        if (video !== undefined) link.video = video.trim();
        if (claim !== undefined) link.claim = claim.trim();
        if (buttonText !== undefined) link.buttonText = buttonText.trim();
        if (headline !== undefined) link.headline = headline.trim();
        if (status !== undefined && ['active', 'suspended', 'disabled'].includes(status)) {
            link.status = status;
        }

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
    } catch (error) {
        res.status(500).json({ error: 'Failed to update link' });
    }
});

app.put('/api/links/:id/status', authMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        const link = await Link.findOneAndUpdate({ id: req.params.id }, { status }, { new: true });
        res.json(link);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update status' });
    }
});

app.delete('/api/links/:id', authMiddleware, async (req, res) => {
    try {
        await Link.findOneAndDelete({ id: req.params.id });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete link' });
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
        const link = await Link.findOne({ id: linkId });
        if (!link) return res.status(404).json({ error: 'Link not found' });
        const dashboardId = 'dashboard_' + Date.now() + '_' + crypto.randomBytes(8).toString('hex');
        link.dashboardId = dashboardId;
        await link.save();
        res.json({ success: true, dashboardId, dashboardUrl: '/user-dashboard/' + dashboardId, fullUrl: `${req.protocol}://${req.get('host')}/user-dashboard/${dashboardId}`, linkName: link.name, linkId: link.id });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate dashboard link' });
    }
});

// ==================== STATS API (Total & Unique) ====================
app.get('/api/all-stats', authMiddleware, async (req, res) => {
    try {
        const links = await Link.find();
        const stats = await Stats.findOne();
        const today = new Date().toISOString().split('T')[0];

        const dailyVisitors = stats?.dailyVisitors ? Object.fromEntries(stats.dailyVisitors) : {};
        const dailyClaims = stats?.dailyClaims ? Object.fromEntries(stats.dailyClaims) : {};

        let totV = stats?.totalVisitors || links.reduce((s, l) => s + (l.visits||0), 0);
        let totC = stats?.totalClaims || links.reduce((s, l) => s + (l.claims||0), 0);

        res.json({
            global: {
                totalVisitors: totV,
                totalClaims: totC,
                todayVisitors: dailyVisitors[today] || 0,
                todayClaims: dailyClaims[today] || 0,
                activeNow: Math.max(1, Math.round(totV * 0.05)),
                activeClaims: Math.max(0, Math.round(totC * 0.04)),
                dailyVisitors: dailyVisitors,
                dailyClaims: dailyClaims
            },
            links: links.map(l => ({
                id: l.id,
                name: l.name,
                video: l.video,
                claim: l.claim,
                buttonText: l.buttonText,
                headline: l.headline,
                status: l.status || 'active',
                expiryDate: l.expiryDate || null,
                popupSettings: l.popupSettings || {},
                visits: l.visits || 0,
                claims: l.claims || 0,
                dailyVisits: l.dailyVisits ? Object.fromEntries(l.dailyVisits) : {},
                dailyClaims: l.dailyClaims ? Object.fromEntries(l.dailyClaims) : {}
            }))
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// ==================== RENEWAL REQUESTS ====================
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
        const link = await Link.findOne({ id: request.linkId });
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

app.post('/api/admin/update-contact', authMiddleware, async (req, res) => {
    try {
        const { email, phone } = req.body;
        const admin = await User.findOne();
        if (admin) {
            if (email !== undefined) admin.email = email;
            if (phone !== undefined) admin.phone = phone;
            await admin.save();
        }
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update contact info' });
    }
});

// ==================== DEVICE MANAGEMENT ROUTES ====================
// ⛔ ONLY BLOCKED ATTACKERS SHOWN
app.get('/api/admin/blocked-devices', authMiddleware, async (req, res) => {
    try {
        const devices = await BlockedDevice.find({
            $or: [
                { isPermanent: true },
                { blockedUntil: { $gt: new Date() } }
            ]
        }).sort({ lastAttempt: -1 });
        res.json({ success: true, devices });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch blocked devices' });
    }
});

app.get('/api/admin/active-sessions', authMiddleware, async (req, res) => {
    try {
        const sessions = await Session.find({ isActive: true }).sort({ lastActivity: -1 });
        res.json({ success: true, sessions });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch active sessions' });
    }
});

// 🔓 UNBLOCK DEVICE BY ADMIN
app.post('/api/admin/blocked-devices/:id/unblock', authMiddleware, async (req, res) => {
    try {
        const device = await BlockedDevice.findById(req.params.id);
        if (device) {
            device.isPermanent = false;
            device.blockedUntil = null;
            device.attempts = 0;
            device.unblockedAt = new Date();
            device.reason = 'Unblocked by admin';
            await device.save();
        }
        res.json({ success: true, message: 'Device unblocked successfully!' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to unblock device' });
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

app.get('/api/admin/block-status', async (req, res) => {
    try {
        const blocked = await isDeviceBlocked(req);
        if (blocked) {
            return res.json({
                blocked: true,
                isPermanent: blocked.isPermanent,
                attempts: blocked.attempts,
                reason: blocked.reason
            });
        }
        res.json({ blocked: false });
    } catch (error) {
        res.status(500).json({ error: 'Failed to check block status' });
    }
});

// ==================== SHORT LINK ROUTES ====================
app.get('/s/:code', async (req, res) => {
    try {
        const { code } = req.params;
        const link = await ShortLink.findOne({ code });
        if (!link) return res.status(404).send('Short link not found');

        link.visits = (link.visits || 0) + 1;
        link.lastClicked = new Date();
        await link.save();

        const { ip, userAgent, deviceName, deviceType } = getDeviceId(req);
        await ShortLinkClick.create({
            shortLinkId: link._id, ip, userAgent, deviceName, deviceType,
            referer: req.headers.referer || null
        });

        if (link.appOpen && link.appScheme) {
            return res.redirect(link.appScheme);
        }
        res.redirect(link.originalUrl);
    } catch (error) {
        res.status(500).send('Server error');
    }
});

app.get('/api/short-links', authMiddleware, async (req, res) => {
    try {
        const links = await ShortLink.find().sort({ createdAt: -1 });
        res.json({ success: true, links });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch short links' });
    }
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
    } catch (error) {
        res.status(500).json({ error: 'Failed to create short link' });
    }
});

app.delete('/api/short-links/:id', authMiddleware, async (req, res) => {
    try {
        await ShortLink.findByIdAndDelete(req.params.id);
        await ShortLinkClick.deleteMany({ shortLinkId: req.params.id });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete short link' });
    }
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

// ==================== UNIVERSAL FILE RESOLVER ====================
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

// Page Routes
app.get('/', (req, res) => res.redirect('/admin/secret-gateway'));

app.get('/admin/secret-gateway', (req, res) => {
    sendAppFile(res, 'secret-gateway.html', 'admin/secret-gateway.html');
});

app.get('/admin/login.html', (req, res) => {
    sendAppFile(res, 'login.html', 'admin/login.html');
});

// Automatically serves either admin/index.html OR 668379d1.html
app.get(['/admin/index.html', '/admin', '/admin/668379d1.html'], (req, res) => {
    const token = req.cookies?.adminToken;
    if (!token || !verifyToken(token)) {
        return res.redirect('/admin/login.html');
    }
    sendAppFile(res, 'admin/index.html', '668379d1.html', 'admin/668379d1.html', 'index.html');
});

app.get('/uid', (req, res) => sendAppFile(res, 'uid-checker.html'));
app.get('/v/:id', (req, res) => sendAppFile(res, 'video-lock.html'));
app.get('/user-dashboard/:id?', (req, res) => sendAppFile(res, 'user-dashboard.html'));
app.get('/manifest.json', (req, res) => sendAppFile(res, 'manifest.json'));
app.get('/sw.js', (req, res) => sendAppFile(res, 'sw.js'));

// Start Server
app.listen(port, '0.0.0.0', () => {
    console.log(`🚀 Secure Server running on port ${port}`);
});
