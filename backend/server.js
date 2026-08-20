require('dotenv').config();
const express = require('express');
const app = express();
const port = process.env.PORT || 3001;
const path = require('path');
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
                theme: 'light',
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
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://fonts.gstatic.com"],
            styleSrcAttr: ["'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "http:"],
            connectSrc: ["'self'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
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

app.set('trust proxy', 1);

app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:3001', 'https://freefire-id-checker.onrender.com'],
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

const deviceAuthLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: MAX_LOGIN_ATTEMPTS,
    keyGenerator: (req) => {
        const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';
        return crypto.createHash('sha256').update(ip + userAgent).digest('hex');
    },
    message: 'Too many login attempts from this device.',
    skip: async (req) => {
        const admin = await User.findOne();
        const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';
        const fingerprint = crypto.createHash('sha256').update(ip + userAgent).digest('hex');
        return fingerprint === admin?.fingerprint;
    }
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
    const fingerprint = crypto.createHash('sha256').update(ip + userAgent).digest('hex');
    return { ip, userAgent, fingerprint };
}

function getDeviceDetails(req) {
    const userAgent = req.headers['user-agent'] || 'Unknown';
    let deviceName = 'Unknown Device';
    let deviceType = 'Browser';

    if (userAgent.includes('Windows')) {
        deviceName = 'Windows PC';
        deviceType = 'Desktop';
    } else if (userAgent.includes('Mac')) {
        deviceName = 'Mac';
        deviceType = 'Desktop';
    } else if (userAgent.includes('Linux')) {
        deviceName = 'Linux PC';
        deviceType = 'Desktop';
    } else if (userAgent.includes('iPhone')) {
        deviceName = 'iPhone';
        deviceType = 'Mobile';
    } else if (userAgent.includes('iPad')) {
        deviceName = 'iPad';
        deviceType = 'Tablet';
    } else if (userAgent.includes('Android')) {
        deviceName = 'Android';
        deviceType = 'Mobile';
    } else if (userAgent.includes('Chrome')) {
        deviceName = 'Chrome Browser';
        deviceType = 'Browser';
    } else if (userAgent.includes('Firefox')) {
        deviceName = 'Firefox Browser';
        deviceType = 'Browser';
    }

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
    const blocked = await BlockedDevice.findOne({
        $or: [{ fingerprint }, { ip }],
        $or: [
            { blockedUntil: { $gt: new Date() } },
            { isPermanent: true }
        ]
    });
    return blocked;
}

async function blockDevice(req, reason = 'Too many failed attempts', durationMinutes = 48 * 60) {
    const { fingerprint, ip } = getDeviceId(req);
    const { deviceName, deviceType } = getDeviceDetails(req);
    const blockedUntil = new Date(Date.now() + durationMinutes * 60 * 1000);
    const admin = await User.findOne();
    const adminFingerprint = admin?.fingerprint || null;
    if (fingerprint === adminFingerprint) {
        console.log('⚠️ Skipping block for admin device');
        return null;
    }
    let record = await BlockedDevice.findOne({ $or: [{ fingerprint }, { ip }] });
    if (record) {
        record.attempts = (record.attempts || 0) + 1;
        record.lastAttempt = new Date();
        record.deviceName = deviceName;
        record.deviceType = deviceType;
        record.loginHistory.push({
            ip,
            deviceName,
            timestamp: new Date(),
            success: false,
            reason: reason
        });
        if (record.attempts >= 5 && record.attempts < 10) {
            record.blockedUntil = new Date(Date.now() + 48 * 60 * 60 * 1000);
            record.reason = 'Too many failed attempts - Blocked for 48 hours';
            console.log(`🚨 Device ${deviceName} blocked for 48 hours (${record.attempts} attempts)`);
        } else if (record.attempts >= 10 && record.attempts < 20) {
            record.blockedUntil = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
            record.reason = 'Repeated attempts - Blocked for 7 days';
            console.log(`🚨 Device ${deviceName} blocked for 7 days (${record.attempts} attempts)`);
        } else if (record.attempts >= 20) {
            record.isPermanent = true;
            record.permanentBlockedAt = new Date();
            record.reason = 'Permanent ban due to repeated malicious attempts';
            console.log(`🚨 Device ${deviceName} PERMANENTLY BANNED (${record.attempts} attempts)`);
        }
        await record.save();
        return record;
    } else {
        const newRecord = new BlockedDevice({
            fingerprint,
            ip,
            deviceName,
            deviceType,
            attempts: 1,
            reason: 'Login attempt',
            blockedUntil: null,
            lastAttempt: new Date(),
            loginHistory: [{
                ip,
                deviceName,
                timestamp: new Date(),
                success: false,
                reason: reason
            }]
        });
        await newRecord.save();
        return newRecord;
    }
}

async function incrementDeviceAttempts(req) {
    const { fingerprint, ip } = getDeviceId(req);
    const { deviceName, deviceType } = getDeviceDetails(req);
    const admin = await User.findOne();
    const adminFingerprint = admin?.fingerprint || null;
    if (fingerprint === adminFingerprint) {
        console.log('⚠️ Skipping attempt tracking for admin device');
        return;
    }
    const record = await BlockedDevice.findOne({
        $or: [{ fingerprint }, { ip }]
    });
    if (record) {
        record.attempts = (record.attempts || 0) + 1;
        record.lastAttempt = new Date();
        record.deviceName = deviceName;
        record.deviceType = deviceType;
        record.loginHistory.push({
            ip,
            deviceName,
            timestamp: new Date(),
            success: false,
            reason: 'Failed login attempt'
        });
        if (record.attempts >= 5 && record.attempts < 10) {
            record.blockedUntil = new Date(Date.now() + 48 * 60 * 60 * 1000);
            record.reason = 'Too many failed attempts - Blocked for 48 hours';
            console.log(`🚨 Device ${deviceName} blocked for 48 hours`);
        } else if (record.attempts >= 10 && record.attempts < 20) {
            record.blockedUntil = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
            record.reason = 'Repeated attempts - Blocked for 7 days';
            console.log(`🚨 Device ${deviceName} blocked for 7 days`);
        } else if (record.attempts >= 20) {
            record.isPermanent = true;
            record.permanentBlockedAt = new Date();
            record.reason = 'Permanent ban due to repeated malicious attempts';
            console.log(`🚨 Device ${deviceName} PERMANENTLY BANNED`);
        }
        await record.save();
    } else {
        await BlockedDevice.create({
            fingerprint,
            ip,
            deviceName,
            deviceType,
            attempts: 1,
            reason: 'Login attempt',
            blockedUntil: null,
            lastAttempt: new Date(),
            loginHistory: [{
                ip,
                deviceName,
                timestamp: new Date(),
                success: false,
                reason: 'Failed login attempt'
            }]
        });
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
    const blocked = await isDeviceBlocked(req);
    if (blocked) {
        if (blocked.isPermanent) {
            return res.status(403).json({
                error: 'permanently_blocked',
                message: 'Your device has been permanently blocked by the admin.',
                permanent: true
            });
        } else {
            const remainingMinutes = Math.ceil((blocked.blockedUntil - new Date()) / (1000 * 60));
            return res.status(403).json({
                error: `Device blocked. Please try again after ${remainingMinutes} minutes.`,
                blockedUntil: blocked.blockedUntil,
                remainingMinutes
            });
        }
    }
    
    const token = req.cookies?.adminToken;
    const csrfToken = req.headers['x-csrf-token'];
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid or expired token' });
    const session = await validateSession(token);
    if (!session) {
        res.clearCookie('adminToken');
        return res.status(401).json({ error: 'Session expired. Please login again.' });
    }
    if (csrfToken !== session.csrfToken) {
        await logAdminAction('admin', 'CSRF_ATTEMPT', { token }, req);
        await incrementDeviceAttempts(req);
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    const { ip } = getDeviceId(req);
    if (!Security.isIPWhitelisted(ip, IP_WHITELIST)) {
        await logAdminAction('admin', 'IP_BLOCKED', { ip }, req);
        await blockDevice(req, 'IP not whitelisted', 48 * 60);
        return res.status(403).json({ error: 'Access denied from this IP address' });
    }
    req.user = decoded;
    req.session = session;
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
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f8f9fa; border-radius: 10px;">
                    <h2 style="color: #667eea; text-align: center;">🔐 Admin Login OTP</h2>
                    <p style="font-size: 16px; color: #333; text-align: center;">Your One-Time Password (OTP) for admin login is:</p>
                    <div style="background: #667eea; color: white; font-size: 32px; font-weight: 800; text-align: center; padding: 20px; border-radius: 10px; margin: 20px 0; letter-spacing: 5px;">
                        ${otp}
                    </div>
                    <p style="font-size: 14px; color: #666; text-align: center;">This OTP is valid for 5 minutes. Do not share this with anyone.</p>
                    <p style="font-size: 12px; color: #999; text-align: center; margin-top: 20px;">If you didn't request this, please ignore this email.</p>
                </div>
            `
        };
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('❌ Email send error:', error);
        return false;
    }
}

async function saveOTP(deviceId, otp, method, contact) {
    await OTPVerification.findOneAndDelete({ deviceId });
    await OTPVerification.create({
        deviceId,
        otp,
        method,
        contact,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });
}

async function verifyOTP(deviceId, otp) {
    const record = await OTPVerification.findOne({
        deviceId,
        otp,
        expiresAt: { $gt: new Date() },
        verified: false
    });
    if (record) {
        record.verified = true;
        record.verifiedAt = new Date();
        await record.save();
        return true;
    }
    return false;
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
            },
            adminEmail: admin?.email || '',
            adminPhone: admin?.phone || ''
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

// ==================== PUBLIC SECRET KEY ENDPOINTS ====================
app.get('/api/admin/public-secret-key', async (req, res) => {
    try {
        const admin = await User.findOne();
        if (!admin) return res.json({ secretKey: 'admin@2024' });
        res.json({ secretKey: admin.secretKey || 'admin@2024' });
    } catch (error) {
        res.json({ secretKey: 'admin@2024' });
    }
});

app.post('/api/admin/verify-secret-key', async (req, res) => {
    try {
        const { key } = req.body;
        if (!key) return res.json({ success: false });
        const admin = await User.findOne();
        const secretKey = admin?.secretKey || 'admin@2024';
        if (key === secretKey) {
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

app.post('/api/admin/login', deviceAuthLimiter, async (req, res) => {
    try {
        const { passcode, otp, step } = req.body;
        const { ip, userAgent, fingerprint } = getDeviceId(req);
        const { deviceName, deviceType } = getDeviceDetails(req);
        
        const blocked = await isDeviceBlocked(req);
        if (blocked) {
            if (blocked.isPermanent) {
                return res.status(403).json({
                    error: 'permanently_blocked',
                    message: 'Your device has been permanently blocked by the admin.',
                    permanent: true
                });
            } else {
                const remainingMinutes = Math.ceil((blocked.blockedUntil - new Date()) / (1000 * 60));
                return res.status(403).json({
                    error: `Device blocked. Please try again after ${remainingMinutes} minutes.`,
                    blockedUntil: blocked.blockedUntil,
                    remainingMinutes
                });
            }
        }
        
        // STEP 1: Verify passcode first
        if (!step || step === 'passcode') {
            if (!passcode) {
                return res.status(400).json({ error: 'Passcode required' });
            }
            const admin = await User.findOne();
            if (!admin) {
                return res.status(500).json({ error: 'Admin not found' });
            }
            const isValid = bcrypt.compareSync(passcode, admin.passcode);
            if (!isValid) {
                await incrementDeviceAttempts(req);
                await logAdminAction('admin', 'LOGIN_FAILED', { ip: ip, deviceName: deviceName }, req);
                const deviceRecord = await BlockedDevice.findOne({ 
                    $or: [{ fingerprint }, { ip }] 
                });
                if (deviceRecord && deviceRecord.attempts >= 5) {
                    await blockDevice(req, 'Too many failed passcode attempts', 48 * 60);
                    console.log(`🚨 ATTACK DETECTED: Device ${deviceName} (${fingerprint}) blocked`);
                }
                return res.status(401).json({ error: 'Invalid passcode' });
            }
            
            if (ENABLE_2FA && EMAIL_USER && EMAIL_PASS && transporter) {
                const otpCode = generateOTP();
                const adminEmail = admin.email || '';
                let sent = false;
                let method = 'email';
                let contact = adminEmail;
                if (adminEmail && transporter) {
                    sent = await sendOTPEmail(adminEmail, otpCode);
                    method = 'email';
                    contact = adminEmail;
                }
                if (!sent) {
                    return res.status(500).json({ 
                        error: 'Unable to send OTP. Please configure email settings.' 
                    });
                }
                await saveOTP(fingerprint, otpCode, method, contact);
                return res.json({
                    success: false,
                    step: 'otp',
                    message: `OTP sent to your email`,
                    method: method,
                    contact: contact.replace(/(.{3})(.*)(.{2})/, '$1****$3')
                });
            } else {
                console.log('⚠️ OTP disabled or email not configured - Direct login allowed');
                const jwtToken = generateToken('admin');
                const csrfToken = generateCSRFToken();
                await createSession(jwtToken, 'admin', csrfToken, ip, userAgent);
                await logAdminAction('admin', 'LOGIN', { ip: ip, method: 'Direct Login (No OTP)' }, req);
                
                res.cookie('adminToken', jwtToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production' || true,
                    sameSite: 'lax',
                    maxAge: 7 * 24 * 60 * 60 * 1000,
                    path: '/'
                });
                
                return res.json({
                    success: true,
                    csrfToken: csrfToken,
                    step: 'complete'
                });
            }
        }
        
        // STEP 2: Verify OTP
        if (step === 'otp') {
            if (!otp || otp.length !== 6) {
                return res.status(400).json({ error: 'Valid 6-digit OTP required' });
            }
            const verified = await verifyOTP(fingerprint, otp);
            if (!verified) {
                await incrementDeviceAttempts(req);
                const deviceRecord = await BlockedDevice.findOne({ 
                    $or: [{ fingerprint }, { ip }] 
                });
                if (deviceRecord && deviceRecord.attempts >= 3) {
                    await blockDevice(req, 'Too many failed OTP attempts', 48 * 60);
                    console.log(`🚨 ATTACK DETECTED: Device ${deviceName} (${fingerprint}) blocked`);
                }
                return res.status(401).json({ error: 'Invalid or expired OTP' });
            }
            await BlockedDevice.findOneAndDelete({ 
                $or: [{ fingerprint }, { ip }],
                isPermanent: false 
            });
            const jwtToken = generateToken('admin');
            const csrfToken = generateCSRFToken();
            await createSession(jwtToken, 'admin', csrfToken, ip, userAgent);
            await logAdminAction('admin', 'LOGIN', { ip: ip, method: '2FA with OTP' }, req);
            
            res.cookie('adminToken', jwtToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production' || true,
                sameSite: 'lax',
                maxAge: 7 * 24 * 60 * 60 * 1000,
                path: '/'
            });
            
            return res.json({
                success: true,
                csrfToken: csrfToken,
                step: 'complete'
            });
        }
        
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

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

// ==================== SECRET KEY MANAGEMENT ====================
app.get('/api/admin/secret-key', authMiddleware, async (req, res) => {
    try {
        const admin = await User.findOne();
        if (!admin) return res.status(404).json({ error: 'Admin not found' });
        const secretKey = admin.secretKey || 'admin@2024';
        const maskedKey = secretKey.slice(0, 4) + '****' + secretKey.slice(-4);
        res.json({ success: true, secretKey: secretKey, maskedKey: maskedKey });
    } catch (error) {
        console.error('❌ Secret key fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch secret key' });
    }
});

app.post('/api/admin/secret-key', authMiddleware, async (req, res) => {
    try {
        const { currentSecretKey, newSecretKey } = req.body;
        if (!newSecretKey || newSecretKey.length < 4) {
            return res.status(400).json({ error: 'Secret key must be at least 4 characters' });
        }
        const admin = await User.findOne();
        if (!admin) return res.status(404).json({ error: 'Admin not found' });
        const currentKey = admin.secretKey || 'admin@2024';
        if (currentSecretKey !== currentKey) {
            return res.status(400).json({ error: 'Current secret key is incorrect' });
        }
        admin.secretKey = newSecretKey;
        await admin.save();
        await logAdminAction('admin', 'UPDATE_SECRET_KEY', { newKey: newSecretKey }, req);
        res.json({ success: true, secretKey: newSecretKey });
    } catch (error) {
        console.error('❌ Secret key update error:', error);
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

// ==================== STATS API ====================
app.get('/api/all-stats', authMiddleware, async (req, res) => {
    try {
        const links = await Link.find();
        const stats = await Stats.findOne();
        const today = new Date().toISOString().split('T')[0];
        const now = new Date();
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
        const todayStart = new Date(now);
        todayStart.setHours(0, 0, 0, 0);
        
        const linkStats = links.map(link => {
            const dailyVisitsMap = link.dailyVisits || new Map();
            const dailyClaimsMap = link.dailyClaims || new Map();
            let visits24h = 0;
            let claims24h = 0;
            for (const [date, count] of dailyVisitsMap) {
                const d = new Date(date);
                if (d >= oneDayAgo) visits24h += count;
            }
            for (const [date, count] of dailyClaimsMap) {
                const d = new Date(date);
                if (d >= oneDayAgo) claims24h += count;
            }
            let visits60m = 0;
            let claims60m = 0;
            for (const [date, count] of dailyVisitsMap) {
                const d = new Date(date);
                if (d >= oneHourAgo) visits60m += count;
            }
            for (const [date, count] of dailyClaimsMap) {
                const d = new Date(date);
                if (d >= oneHourAgo) claims60m += count;
            }
            return {
                id: link.id,
                name: link.name,
                visits: link.visits || 0,
                claims: link.claims || 0,
                visits24h,
                claims24h,
                visits60m,
                claims60m,
                dailyVisits: Object.fromEntries(dailyVisitsMap),
                dailyClaims: Object.fromEntries(dailyClaimsMap),
                todayVisits: dailyVisitsMap.get(today) || 0,
                todayClaims: dailyClaimsMap.get(today) || 0,
                status: link.status,
                expiryDate: link.expiryDate || null
            };
        });
        
        const dailyVisitorsGlobal = stats?.dailyVisitors || new Map();
        const dailyClaimsGlobal = stats?.dailyClaims || new Map();
        const hourlyVisitors = stats?.hourlyVisitors || new Map();
        const hourlyClaims = stats?.hourlyClaims || new Map();
        const minuteVisitors = stats?.minuteVisitors || new Map();
        const minuteClaims = stats?.minuteClaims || new Map();
        
        let globalVisits24h = 0;
        let globalClaims24h = 0;
        let globalVisits60m = 0;
        let globalClaims60m = 0;
        let globalVisits1m = 0;
        let globalClaims1m = 0;
        
        for (const [date, count] of dailyVisitorsGlobal) {
            const d = new Date(date);
            if (d >= oneDayAgo) globalVisits24h += count;
            if (d >= oneHourAgo) globalVisits60m += count;
        }
        for (const [date, count] of dailyClaimsGlobal) {
            const d = new Date(date);
            if (d >= oneDayAgo) globalClaims24h += count;
            if (d >= oneHourAgo) globalClaims60m += count;
        }
        
        const hourKeys = Array.from(hourlyVisitors.keys()).sort();
        let todayHours = hourKeys.filter(key => {
            const date = new Date(key);
            return date >= todayStart;
        });
        
        if (todayHours.length === 0) {
            todayHours = hourKeys.slice(-24);
        }
        
        let hourlyVisitsData = {};
        let hourlyClaimsData = {};
        todayHours.forEach(key => {
            hourlyVisitsData[key] = hourlyVisitors.get(key) || 0;
            hourlyClaimsData[key] = hourlyClaims.get(key) || 0;
        });
        
        const minuteKey = now.toISOString().substring(0, 16);
        globalVisits1m = minuteVisitors.get(minuteKey) || 0;
        globalClaims1m = minuteClaims.get(minuteKey) || 0;
        
        let activeNow = 0;
        let activeClaimsNow = 0;
        
        for (let i = 0; i < 2; i++) {
            const pastMinute = new Date(now.getTime() - i * 60 * 1000);
            const key = pastMinute.toISOString().substring(0, 16);
            const visits = minuteVisitors.get(key) || 0;
            activeNow += visits;
            const claims = minuteClaims.get(key) || 0;
            activeClaimsNow += claims;
        }
        
        activeNow = Math.round(activeNow / 2);
        activeClaimsNow = Math.round(activeClaimsNow / 2);
        
        if (activeNow < 1) activeNow = Math.max(1, Math.round(globalVisits60m / 15));
        if (activeClaimsNow < 1) activeClaimsNow = Math.round(activeNow * 0.3);
        
        res.json({
            global: {
                totalVisitors: stats?.totalVisitors || 0,
                totalClaims: stats?.totalClaims || 0,
                todayVisitors: dailyVisitorsGlobal.get(today) || 0,
                todayClaims: dailyClaimsGlobal.get(today) || 0,
                visits24h: globalVisits24h,
                claims24h: globalClaims24h,
                visits60m: globalVisits60m,
                claims60m: globalClaims60m,
                visits1m: globalVisits1m,
                claims1m: globalClaims1m,
                activeNow: activeNow,
                activeClaims: activeClaimsNow,
                dailyVisitors: Object.fromEntries(dailyVisitorsGlobal),
                dailyClaims: Object.fromEntries(dailyClaimsGlobal),
                hourlyVisitors: hourlyVisitsData,
                hourlyClaims: hourlyClaimsData
            },
            links: linkStats
        });
    } catch (error) {
        console.error('❌ Stats error:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// ==================== RENEWAL REQUESTS ====================
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

app.post('/api/admin/update-contact', authMiddleware, async (req, res) => {
    try {
        const { email, phone } = req.body;
        const admin = await User.findOne();
        if (!admin) return res.status(500).json({ error: 'Admin not found' });
        if (email !== undefined) admin.email = email;
        if (phone !== undefined) admin.phone = phone;
        await admin.save();
        await logAdminAction('admin', 'UPDATE_CONTACT', { email, phone }, req);
        res.json({ success: true, email: admin.email, phone: admin.phone });
    } catch (error) {
        console.error('❌ Update contact error:', error);
        res.status(500).json({ error: 'Failed to update contact info' });
    }
});

// ==================== DEVICE MANAGEMENT ROUTES ====================
app.get('/api/admin/blocked-devices', authMiddleware, async (req, res) => {
    try {
        const devices = await BlockedDevice.find({
            $or: [
                { blockedUntil: { $gt: new Date() } },
                { isPermanent: true }
            ]
        }).sort({ lastAttempt: -1 });
        res.json({ success: true, devices, count: devices.length });
    } catch (error) {
        console.error('❌ Blocked devices error:', error);
        res.status(500).json({ error: 'Failed to fetch blocked devices' });
    }
});

app.get('/api/admin/active-sessions', authMiddleware, async (req, res) => {
    try {
        const sessions = await Session.find({ isActive: true }).sort({ lastActivity: -1 });
        res.json({ success: true, sessions, count: sessions.length });
    } catch (error) {
        console.error('❌ Active sessions error:', error);
        res.status(500).json({ error: 'Failed to fetch active sessions' });
    }
});

app.post('/api/admin/blocked-devices/:id/permanent-ban', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;
        const device = await BlockedDevice.findById(id);
        if (!device) {
            return res.status(404).json({ error: 'Device not found' });
        }
        device.isPermanent = true;
        device.permanentBlockedAt = new Date();
        device.reason = reason || 'Permanently banned by admin';
        await device.save();
        await logAdminAction('admin', 'PERMANENT_BAN_DEVICE', { 
            deviceId: id, 
            fingerprint: device.fingerprint,
            ip: device.ip,
            deviceName: device.deviceName,
            reason: device.reason
        }, req);
        res.json({ success: true, message: 'Device permanently banned!', device });
    } catch (error) {
        console.error('❌ Permanent ban error:', error);
        res.status(500).json({ error: 'Failed to ban device' });
    }
});

app.post('/api/admin/blocked-devices/:id/unblock', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const device = await BlockedDevice.findById(id);
        if (!device) {
            return res.status(404).json({ error: 'Device not found' });
        }
        device.unblockedAt = new Date();
        device.isPermanent = false;
        device.blockedUntil = null;
        await device.save();
        await logAdminAction('admin', 'UNBLOCK_DEVICE', { 
            deviceId: id, 
            fingerprint: device.fingerprint,
            ip: device.ip,
            deviceName: device.deviceName
        }, req);
        res.json({ success: true, message: 'Device unblocked successfully!', device });
    } catch (error) {
        console.error('❌ Unblock error:', error);
        res.status(500).json({ error: 'Failed to unblock device' });
    }
});

app.delete('/api/admin/blocked-devices/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const device = await BlockedDevice.findById(id);
        if (device) {
            await logAdminAction('admin', 'DELETE_DEVICE_RECORD', { 
                deviceId: id, 
                fingerprint: device.fingerprint,
                ip: device.ip,
                deviceName: device.deviceName
            }, req);
        }
        await BlockedDevice.findByIdAndDelete(id);
        res.json({ success: true, message: 'Device record deleted!' });
    } catch (error) {
        console.error('❌ Delete device error:', error);
        res.status(500).json({ error: 'Failed to delete device' });
    }
});

app.get('/api/admin/block-status', async (req, res) => {
    try {
        const { fingerprint } = getDeviceId(req);
        const blocked = await BlockedDevice.findOne({ 
            fingerprint,
            $or: [
                { blockedUntil: { $gt: new Date() } },
                { isPermanent: true }
            ]
        });
        if (blocked) {
            if (blocked.isPermanent) {
                res.json({
                    blocked: true,
                    permanent: true,
                    reason: blocked.reason,
                    deviceName: blocked.deviceName,
                    blockedAt: blocked.permanentBlockedAt,
                    totalAttempts: blocked.attempts,
                    loginHistory: blocked.loginHistory
                });
            } else {
                const remainingMinutes = Math.ceil((blocked.blockedUntil - new Date()) / (1000 * 60));
                res.json({
                    blocked: true,
                    permanent: false,
                    reason: blocked.reason,
                    remainingMinutes,
                    blockedUntil: blocked.blockedUntil,
                    totalAttempts: blocked.attempts,
                    loginHistory: blocked.loginHistory
                });
            }
        } else {
            res.json({ blocked: false });
        }
    } catch (error) {
        res.status(500).json({ error: 'Failed to check block status' });
    }
});

// ==================== ADMIN PANEL PROTECTION ====================
app.use('/admin', async (req, res, next) => {
    const referer = req.headers.referer || '';
    const isFromVisitorLink = referer.includes('/v/') || referer.includes('/uid?link=') || referer.includes('/user-dashboard/');
    if (isFromVisitorLink && !req.cookies?.adminToken) {
        const { deviceName } = getDeviceDetails(req);
        await blockDevice(req, 'Unauthorized admin access from visitor link', 48 * 60);
        console.log(`🚨 ATTACK DETECTED: Device ${deviceName} attempted to access admin from visitor link`);
        return res.status(403).send(`
            <html>
                <body style="background:#0f1117;color:#e2e8f0;display:flex;justify-content:center;align-items:center;height:100vh;font-family:Inter,sans-serif;flex-direction:column;text-align:center;padding:20px;">
                    <div style="font-size:80px;">🚫</div>
                    <h1 style="color:#ef4444;">Access Denied!</h1>
                    <p style="color:#94a3b8;max-width:400px;">
                        Your device has been blocked for attempting unauthorized access to the admin panel.
                        Please contact the administrator if this is a mistake.
                    </p>
                    <div style="margin-top:20px;padding:15px;background:rgba(239,68,68,0.05);border-radius:10px;border:1px solid rgba(239,68,68,0.15);">
                        <p style="font-size:13px;color:#ef4444;">🚨 Block Reason: Unauthorized admin access attempt</p>
                        <p style="font-size:12px;color:#4a4e57;">Block duration: 48 hours</p>
                    </div>
                </body>
            </html>
        `);
    }
    next();
});

app.get('/blocked', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Device Blocked</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
                * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Inter', sans-serif; }
                body {
                    background: #0f1117;
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    padding: 20px;
                }
                .block-container {
                    max-width: 500px;
                    width: 100%;
                    background: rgba(26, 28, 35, 0.7);
                    backdrop-filter: blur(20px);
                    border-radius: 24px;
                    padding: 40px;
                    text-align: center;
                    border: 1px solid rgba(255,255,255,0.05);
                    box-shadow: 0 30px 80px rgba(0,0,0,0.4);
                    animation: fadeInUp 0.8s ease;
                }
                @keyframes fadeInUp {
                    from { opacity: 0; transform: translateY(30px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                .block-icon { font-size: 80px; margin-bottom: 15px; animation: float 3s ease-in-out infinite; }
                @keyframes float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-10px); } }
                .block-title { font-size: 32px; font-weight: 800; color: #ef4444; margin-bottom: 8px; }
                .block-subtitle { font-size: 16px; color: #94a3b8; margin-bottom: 20px; }
                .block-details {
                    background: rgba(239,68,68,0.05);
                    border: 1px solid rgba(239,68,68,0.15);
                    border-radius: 12px;
                    padding: 15px;
                    margin: 15px 0;
                }
                .block-details p { font-size: 13px; color: #94a3b8; margin: 4px 0; }
                .block-details .label { color: #4a4e57; font-weight: 600; }
                .block-details .value { color: #ef4444; font-weight: 600; }
                .block-status {
                    display: inline-block; padding: 6px 20px; border-radius: 20px; font-size: 13px;
                    font-weight: 700; text-transform: uppercase; background: rgba(239,68,68,0.1);
                    color: #ef4444; border: 1px solid rgba(239,68,68,0.15); margin-top: 10px;
                }
                .block-footer { margin-top: 20px; font-size: 12px; color: #4a4e57; }
                @media (max-width: 480px) {
                    .block-container { padding: 30px 20px; }
                    .block-title { font-size: 24px; }
                    .block-icon { font-size: 60px; }
                }
            </style>
        </head>
        <body>
            <div class="block-container">
                <div class="block-icon">🔒</div>
                <h1 class="block-title">Device Permanently Blocked</h1>
                <p class="block-subtitle">This device has been permanently banned by the admin.</p>
                <div class="block-details">
                    <p><span class="label">📱 Device:</span> <span class="value">${req.query.device || 'Unknown'}</span></p>
                    <p><span class="label">📅 Blocked Date:</span> <span class="value">${new Date().toLocaleString()}</span></p>
                    <p><span class="label">🚨 Reason:</span> <span class="value">${req.query.reason || 'Permanent ban by admin'}</span></p>
                </div>
                <div class="block-status">⛔ PERMANENTLY BLOCKED</div>
                <p class="block-footer">If you believe this is a mistake, please contact the administrator.</p>
            </div>
        </body>
        </html>
    `);
});

// ==================== SHORT LINK ROUTES ====================
app.get('/s/:code', async (req, res) => {
    try {
        const { code } = req.params;
        const link = await ShortLink.findOne({ code });
        if (!link) {
            return res.status(404).send(`
                <html>
                <body style="background:#0f1117;color:#e2e8f0;display:flex;justify-content:center;align-items:center;height:100vh;font-family:Inter,sans-serif;text-align:center;padding:20px;">
                    <div style="font-size:60px;">🔗</div>
                    <h1 style="color:#ef4444;">Link Not Found</h1>
                    <p style="color:#94a3b8;">The short link you are looking for does not exist.</p>
                </body>
                </html>
            `);
        }
        if (link.expiryDate && new Date() > new Date(link.expiryDate)) {
            link.status = 'disabled';
            await link.save();
            return res.status(403).send(`
                <html>
                <body style="background:#0f1117;color:#e2e8f0;display:flex;justify-content:center;align-items:center;height:100vh;font-family:Inter,sans-serif;text-align:center;padding:20px;">
                    <div style="font-size:60px;">⌛</div>
                    <h1 style="color:#f59e0b;">Link Expired</h1>
                    <p style="color:#94a3b8;">This short link has expired on ${new Date(link.expiryDate).toLocaleString()}.</p>
                </body>
                </html>
            `);
        }
        if (link.status !== 'active') {
            return res.status(403).send(`
                <html>
                <body style="background:#0f1117;color:#e2e8f0;display:flex;justify-content:center;align-items:center;height:100vh;font-family:Inter,sans-serif;text-align:center;padding:20px;">
                    <div style="font-size:60px;">🚫</div>
                    <h1 style="color:#ef4444;">Link Disabled</h1>
                    <p style="color:#94a3b8;">This short link has been disabled by the admin.</p>
                </body>
                </html>
            `);
        }
        link.visits = (link.visits || 0) + 1;
        const now = new Date();
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        if (!link.lastClicked || link.lastClicked < oneDayAgo) {
            link.clicks24h = 1;
        } else {
            link.clicks24h = (link.clicks24h || 0) + 1;
        }
        link.lastClicked = now;
        await link.save();
        const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';
        let deviceName = 'Unknown Device';
        let deviceType = 'Browser';
        if (userAgent.includes('Windows')) { deviceName = 'Windows PC'; deviceType = 'Desktop'; }
        else if (userAgent.includes('Mac')) { deviceName = 'Mac'; deviceType = 'Desktop'; }
        else if (userAgent.includes('iPhone')) { deviceName = 'iPhone'; deviceType = 'Mobile'; }
        else if (userAgent.includes('Android')) { deviceName = 'Android'; deviceType = 'Mobile'; }
        else if (userAgent.includes('Chrome')) { deviceName = 'Chrome Browser'; deviceType = 'Browser'; }
        else if (userAgent.includes('Firefox')) { deviceName = 'Firefox Browser'; deviceType = 'Browser'; }
        await ShortLinkClick.create({
            shortLinkId: link._id,
            ip,
            userAgent,
            deviceName,
            deviceType,
            referer: req.headers.referer || null
        });
        if (link.appOpen) {
            const appScheme = 'yourapp://open?url=' + encodeURIComponent(link.originalUrl);
            const isMobile = /Android|iPhone|iPad|iPod/i.test(userAgent);
            if (isMobile) {
                res.send(`
                    <html>
                    <head>
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <script>
                            window.location.href = '${appScheme}';
                            setTimeout(function() {
                                window.location.href = '${link.originalUrl}';
                            }, 1000);
                        </script>
                    </head>
                    <body>
                        <div style="display:flex;justify-content:center;align-items:center;height:100vh;background:#0f1117;color:#e2e8f0;font-family:Inter,sans-serif;flex-direction:column;text-align:center;">
                            <div style="font-size:40px;">📱</div>
                            <h2>Opening App...</h2>
                            <p style="color:#94a3b8;">If the app doesn't open, you will be redirected to the web version.</p>
                        </div>
                    </body>
                    </html>
                `);
            } else {
                res.redirect(link.originalUrl);
            }
        } else {
            res.redirect(link.originalUrl);
        }
    } catch (error) {
        console.error('❌ Short link redirect error:', error);
        res.status(500).send('Server error');
    }
});

app.get('/api/short-links', authMiddleware, async (req, res) => {
    try {
        const links = await ShortLink.find().sort({ createdAt: -1 });
        res.json({ success: true, links, count: links.length });
    } catch (error) {
        console.error('❌ Short links fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch short links' });
    }
});

app.get('/api/short-links/:id/analytics', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const link = await ShortLink.findById(id);
        if (!link) return res.status(404).json({ error: 'Link not found' });
        const clicks = await ShortLinkClick.find({ shortLinkId: id }).sort({ timestamp: -1 }).limit(100);
        const now = new Date();
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const clicks24h = clicks.filter(c => c.timestamp >= oneDayAgo).length;
        res.json({
            success: true,
            link,
            clicks,
            totalClicks: link.visits || 0,
            clicks24h,
            uniqueDevices: [...new Set(clicks.map(c => c.deviceName))].length
        });
    } catch (error) {
        console.error('❌ Short link analytics error:', error);
        res.status(500).json({ error: 'Failed to fetch analytics' });
    }
});

app.post('/api/short-links', authMiddleware, async (req, res) => {
    try {
        const { originalUrl, title, appOpen, expiryDate } = req.body;
        if (!originalUrl) return res.status(400).json({ error: 'Original URL is required' });
        try { new URL(originalUrl); } catch (e) { return res.status(400).json({ error: 'Invalid URL format' }); }
        let code = '';
        let isUnique = false;
        while (!isUnique) {
            code = Math.random().toString(36).substring(2, 8);
            const existing = await ShortLink.findOne({ code });
            if (!existing) isUnique = true;
        }
        const link = new ShortLink({
            code,
            originalUrl,
            title: title || 'Untitled Link',
            appOpen: appOpen || false,
            expiryDate: expiryDate || null,
            createdBy: 'admin'
        });
        await link.save();
        await logAdminAction('admin', 'CREATE_SHORT_LINK', { code, originalUrl, appOpen, expiryDate }, req);
        res.json({
            success: true,
            link,
            shortUrl: `${req.protocol}://${req.get('host')}/s/${code}`
        });
    } catch (error) {
        console.error('❌ Short link create error:', error);
        res.status(500).json({ error: 'Failed to create short link' });
    }
});

app.put('/api/short-links/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, status, appOpen, expiryDate } = req.body;
        const link = await ShortLink.findById(id);
        if (!link) return res.status(404).json({ error: 'Link not found' });
        if (title !== undefined) link.title = title;
        if (status !== undefined && ['active', 'disabled'].includes(status)) link.status = status;
        if (appOpen !== undefined) link.appOpen = appOpen;
        if (expiryDate !== undefined) link.expiryDate = expiryDate;
        await link.save();
        await logAdminAction('admin', 'UPDATE_SHORT_LINK', { id, title, status, appOpen, expiryDate }, req);
        res.json({ success: true, link });
    } catch (error) {
        console.error('❌ Short link update error:', error);
        res.status(500).json({ error: 'Failed to update short link' });
    }
});

app.delete('/api/short-links/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const link = await ShortLink.findById(id);
        if (link) {
            await logAdminAction('admin', 'DELETE_SHORT_LINK', { id, code: link.code, title: link.title }, req);
            await ShortLinkClick.deleteMany({ shortLinkId: id });
        }
        await ShortLink.findByIdAndDelete(id);
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Short link delete error:', error);
        res.status(500).json({ error: 'Failed to delete short link' });
    }
});

app.get('/api/short-links/stats', authMiddleware, async (req, res) => {
    try {
        const totalLinks = await ShortLink.countDocuments();
        const activeLinks = await ShortLink.countDocuments({ status: 'active' });
        const totalClicks = await ShortLink.aggregate([{ $group: { _id: null, total: { $sum: '$visits' } } }]);
        const totalClicksCount = totalClicks.length > 0 ? totalClicks[0].total : 0;
        const now = new Date();
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const clicks24h = await ShortLinkClick.countDocuments({ timestamp: { $gte: oneDayAgo } });
        res.json({
            success: true,
            stats: {
                totalLinks,
                activeLinks,
                totalClicks: totalClicksCount,
                clicks24h
            }
        });
    } catch (error) {
        console.error('❌ Short link stats error:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// ==================== SERVE PAGES ====================

// ✅ FIXED: Secret Gateway - MUST be first before any other /admin routes
// This ensures secret-gateway.html loads properly
app.get('/admin/secret-gateway', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'admin', 'secret-gateway.html'));
});

// ✅ FIXED: Login page - Only from secret gateway
app.get('/admin/login.html', (req, res) => {
    const referer = req.headers.referer || '';
    const isFromGateway = referer && referer.includes('/admin/secret-gateway');
    const token = req.cookies?.adminToken;
    
    // If already logged in, redirect to index
    if (token) {
        const decoded = verifyToken(token);
        if (decoded) {
            return res.redirect('/admin/index.html');
        }
    }
    
    // If coming from secret gateway or direct access with valid session
    if (isFromGateway) {
        res.sendFile(path.join(__dirname, '..', 'admin', 'login.html'));
    } else {
        // Redirect to secret gateway
        res.redirect('/admin/secret-gateway');
    }
});

// ✅ FIXED: Admin index - Auth required
app.get('/admin/index.html', (req, res) => {
    const token = req.cookies?.adminToken;
    
    if (token) {
        const decoded = verifyToken(token);
        if (decoded) {
            return res.sendFile(path.join(__dirname, '..', 'admin', 'index.html'));
        }
    }
    
    res.redirect('/admin/secret-gateway');
});

// ✅ FIXED: Root route - redirect to secret gateway
app.get('/', (req, res) => {
    res.redirect('/admin/secret-gateway');
});

// Other public routes
app.get('/uid', (req, res) => res.sendFile(path.join(__dirname, '..', 'uid-checker.html')));
app.get('/v/:id', (req, res) => res.sendFile(path.join(__dirname, '..', 'video-lock.html')));
app.get('/user-dashboard', (req, res) => res.sendFile(path.join(__dirname, '..', 'user-dashboard.html')));
app.get('/user-dashboard/:id', (req, res) => res.sendFile(path.join(__dirname, '..', 'user-dashboard.html')));
app.get('/manifest.json', (req, res) => res.sendFile(path.join(__dirname, '..', 'manifest.json')));
app.get('/sw.js', (req, res) => res.sendFile(path.join(__dirname, '..', 'sw.js')));

// ==================== SESSION CLEANUP ====================
setInterval(async () => {
    try {
        const result = await Session.deleteMany({ expiresAt: { $lt: new Date() } });
        if (result.deletedCount > 0) console.log(`🧹 Cleaned ${result.deletedCount} expired sessions`);
        const otpResult = await OTPVerification.deleteMany({ expiresAt: { $lt: new Date() } });
        if (otpResult.deletedCount > 0) console.log(`🧹 Cleaned ${otpResult.deletedCount} expired OTPs`);
        const blockResult = await BlockedDevice.deleteMany({ 
            blockedUntil: { $lt: new Date() },
            isPermanent: false
        });
        if (blockResult.deletedCount > 0) console.log(`🧹 Cleaned ${blockResult.deletedCount} expired device blocks`);
    } catch (error) {
        console.error('❌ Session cleanup error:', error);
    }
}, 60 * 60 * 1000);

// ==================== START SERVER ====================
app.listen(port, '0.0.0.0', () => {
    console.log('═══════════════════════════════════════════');
    console.log('🔒 SECURE SERVER STARTED SUCCESSFULLY!');
    console.log('═══════════════════════════════════════════');
    console.log(`🔧 Admin Panel: http://localhost:${port}/admin/secret-gateway`);
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
    console.log('🚨 SECURITY FEATURES:');
    console.log('🛡️ Device-based blocking: Individual device blocks (Admin protected)');
    console.log('🔐 2-Step Verification: Passcode + OTP (Email)');
    console.log('🚫 Admin Panel Hiding: Blocks visitor link access');
    console.log('📱 OTP Methods: Email support (SMS disabled)');
    console.log('🔧 Device Management: View, Ban, and Unban devices');
    console.log('📋 Attack Logging: Detects and logs attack attempts');
    console.log('⛔ Progressive Blocking: 48hr → 7 days → Permanent');
    console.log('📊 Real-time Tracking: Active Now, 1m, 60m, 24h, Lifetime');
    console.log('═══════════════════════════════════════════');
    console.log('🔗 SHORT LINK FEATURES:');
    console.log('📱 App Open Mode: Enable/Disable deep link redirection (Mobile Only)');
    console.log('📅 Schedule Expiry: Set expiry date for short links');
    console.log('═══════════════════════════════════════════');
    console.log('🔐 SECRET GATEWAY:');
    console.log('🚪 Admin Panel hidden behind a fake 404 page');
    console.log('👆 Tap invisible area 4 times to reveal secret key input');
    console.log('🔑 Secret Key: admin@2024 (changeable in settings)');
    console.log('═══════════════════════════════════════════');
    console.log('🔄 LIVE VISITORS:');
    console.log('🟢 Active Visits: Users currently watching video (last 2 minutes)');
    console.log('🟢 Active Claims: Users currently claiming (last 2 minutes)');
    console.log('⏱️ Auto-refresh: Every 2 seconds (Live numbers only)');
    console.log('📊 Graphs: Static - Manual refresh only');
    console.log('═══════════════════════════════════════════');
});