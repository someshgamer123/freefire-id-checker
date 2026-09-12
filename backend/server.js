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
const mongoose = require('mongoose');

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

// 🛡️ Security 2FA Inlined (ZERO DEPENDENCY ON 'speakeasy')
const Security = {
    generate2FASecret: () => ({ base32: crypto.randomBytes(20).toString('hex') }),
    generateBackupCodes: () => [
        crypto.randomBytes(4).toString('hex'),
        crypto.randomBytes(4).toString('hex'),
        crypto.randomBytes(4).toString('hex')
    ]
};

connectDB();

// 🔓 Disable strict schema mode & ensure uidChecking field is registered
try {
    if (Link && Link.schema) {
        Link.schema.add({ uidChecking: { type: Boolean, default: true } });
        Link.schema.set('strict', false);
    }
    if (PopupSettings && PopupSettings.schema) {
        PopupSettings.schema.add({ uidChecking: { type: Boolean, default: true } });
        PopupSettings.schema.set('strict', false);
    }
    if (Pricing && Pricing.schema) Pricing.schema.set('strict', false);
    if (User && User.schema) User.schema.set('strict', false);
    if (Session && Session.schema) Session.schema.set('strict', false);
    if (BlockedDevice && BlockedDevice.schema) BlockedDevice.schema.set('strict', false);
    if (ShortLink && ShortLink.schema) ShortLink.schema.set('strict', false);
} catch(e) {}

// ==================== 🕒 24-HOUR UNIQUE VISITOR ACTIVITY MODEL ====================
const VisitorActivity = mongoose.models.VisitorActivity || mongoose.model('VisitorActivity', new mongoose.Schema({
    linkId: { type: String, required: true, index: true },
    visitorKey: { type: String, required: true, index: true },
    type: { type: String, enum: ['visit', 'claim'], required: true, index: true },
    uid: { type: String, default: null },
    lastSeen: { type: Date, default: Date.now, index: true }
}, { timestamps: true }));

// ==================== Environment Variables ====================
const DEFAULT_PASSCODE = process.env.ADMIN_PASSCODE ? process.env.ADMIN_PASSCODE.toString().trim() : '951753';
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

// Helper: Strict single-passcode verification
function verifyPasscode(inputPass, storedPass) {
    if (!inputPass || !storedPass) return false;
    const cleanInput = inputPass.toString().trim();
    const cleanStored = storedPass.toString().trim();

    if (cleanStored.startsWith('$2a$') || cleanStored.startsWith('$2b$') || cleanStored.startsWith('$2y$')) {
        try {
            return bcrypt.compareSync(cleanInput, cleanStored);
        } catch(e) {
            return false;
        }
    }
    return cleanInput === cleanStored;
}

// Helper: Check if UID check is disabled (OFF)
function isUidCheckDisabled(val) {
    if (
        val === false ||
        val === 'false' ||
        val === 0 ||
        val === '0' ||
        val === 'off' ||
        val === 'OFF' ||
        val === 'disabled' ||
        val === 'inactive' ||
        val === 'no' ||
        val === 'NO'
    ) {
        return true;
    }
    return false;
}

// Helper: Extract clean link ID from various URL patterns or query parameters
function extractCleanId(input) {
    if (!input) return '';
    let str = input.toString().trim();
    if (str.includes('?link=')) str = str.split('?link=').split('&')[0];
    else if (str.includes('&link=')) str = str.split('&link=').split('&')[0];
    else if (str.includes('?id=')) str = str.split('?id=').split('&')[0];
    else if (str.includes('&id=')) str = str.split('&id=').split('&')[0];
    else if (str.includes('/v/')) str = str.split('/v/').split('?')[0];
    else if (str.includes('/uid/')) str = str.split('/uid/').split('?')[0];
    try {
        str = decodeURIComponent(str);
    } catch(e) {}
    return str.trim();
}

// Helper: Safe Link Query (Works for both Mongoose and Native MongoDB Collection)
function getLinkQuery(rawId) {
    const cleanId = (rawId || '').toString().trim();
    const orConditions = [{ id: cleanId }, { dashboardId: cleanId }];
    if (mongoose.Types.ObjectId.isValid(cleanId) && cleanId.length === 24) {
        try {
            orConditions.push({ _id: new mongoose.Types.ObjectId(cleanId) });
        } catch(e) {}
        orConditions.push({ _id: cleanId });
    }
    return { $or: orConditions };
}

// Database Initialization & Strict Passcode Sync
async function initializeDatabase() {
    try {
        const activeEnvPass = process.env.ADMIN_PASSCODE ? process.env.ADMIN_PASSCODE.toString().trim() : DEFAULT_PASSCODE;
        let admin = await User.findOne();

        if (!admin) {
            const hashedPasscode = bcrypt.hashSync(activeEnvPass, 10);
            await User.create({
                passcode: hashedPasscode,
                lastEnvPasscode: activeEnvPass,
                theme: 'dark',
                email: process.env.ADMIN_EMAIL || '',
                phone: process.env.ADMIN_PHONE || '',
                secretKey: 'admin@2024'
            });
            console.log('✅ Admin initialized with active passcode');

            if (ENABLE_2FA) {
                const secret = Security.generate2FASecret();
                await TwoFactorAuth.create({
                    userId: 'admin',
                    secret: secret.base32,
                    backupCodes: Security.generateBackupCodes(),
                    isEnabled: true,
                    verifiedAt: new Date()
                });
            }
        } else if (process.env.ADMIN_PASSCODE && admin.lastEnvPasscode !== activeEnvPass) {
            admin.passcode = bcrypt.hashSync(activeEnvPass, 10);
            admin.lastEnvPasscode = activeEnvPass;
            await admin.save();
            console.log('🔄 Admin passcode updated from environment variable ADMIN_PASSCODE');
        }

        const statsExists = await Stats.findOne();
        if (!statsExists) {
            await Stats.create({});
        }

        const popupExists = await PopupSettings.findOne();
        if (!popupExists) {
            await PopupSettings.create({
                image: null,
                title: '🎁 Claim Your Reward',
                buttonText: 'Claim Now',
                subtitle: 'Tap below to unlock your reward',
                uidChecking: true
            });
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
                autoPaymentEnabled: false
            });
        } else if (pricingExists.autoPaymentEnabled !== false) {
            pricingExists.autoPaymentEnabled = false;
            await pricingExists.save();
        }

        await Session.deleteMany({ expiresAt: { $lt: new Date() } }).catch(() => {});
    } catch (error) {
        console.error('❌ Database initialization error:', error);
    }
}

initializeDatabase();

// ==================== Middlewares & Reverse Proxy ====================
app.set('trust proxy', 1);

app.use(helmet({
    contentSecurityPolicy: false,
    frameguard: false,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Admin-Token', 'token']
}));

app.use((req, res, next) => {
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    const blocked = ['.env', '.log', '.json', '.md'];
    const p = req.path.toLowerCase();
    if (p === '/manifest.json') return next();
    for (let ext of blocked) {
        if (p.endsWith(ext)) return res.status(403).send('Forbidden');
    }
    next();
});

// ==================== Health Check ====================
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        uptime: Math.floor(process.uptime()),
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        timestamp: new Date().toISOString()
    });
});

app.get('/ping', (req, res) => res.status(200).send('pong'));

// ==================== Rate Limiting ====================
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX) || 50000,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        return (
            req.path === '/health' ||
            req.path === '/ping' ||
            req.path.endsWith('.css') ||
            req.path.endsWith('.js') ||
            req.path.endsWith('.png') ||
            req.path.endsWith('.jpg') ||
            req.path.endsWith('.ico')
        );
    },
    message: { error: 'Too many requests, please try again later.' }
});
app.use('/api', globalLimiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// JWT Helpers
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

// Safe device ID generator
function getDeviceId(req) {
    let rawIp = req.headers['x-forwarded-for'] || req.ip || req.connection?.remoteAddress || '127.0.0.1';
    if (Array.isArray(rawIp)) rawIp = rawIp[0];
    const ip = typeof rawIp === 'string' ? rawIp.split(',')[0].trim() : '127.0.0.1';
    const userAgent = (req.headers && req.headers['user-agent']) ? req.headers['user-agent'].toString() : 'unknown';
    const clientCookie = req.cookies?.devId || '';
    const fingerprint = crypto.createHash('sha256').update(ip + userAgent + clientCookie).digest('hex');
    const deviceKey = crypto.createHash('sha256').update(fingerprint + '|' + ip).digest('hex');
    return { ip, userAgent, fingerprint, deviceKey };
}

function getDeviceDetails(req) {
    const userAgent = (req.headers && req.headers['user-agent']) ? req.headers['user-agent'].toString() : 'Unknown';
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

// Safe timeout-protected block check
async function isDeviceBlocked(req) {
    try {
        if (mongoose.connection.readyState !== 1) return null;
        const { deviceKey, fingerprint, ip } = getDeviceId(req);
        return await BlockedDevice.findOne({
            $or: [
                { deviceKey },
                { ip },
                { fingerprint }
            ],
            isPermanent: true
        }).maxTimeMS(2000);
    } catch(e) {
        return null;
    }
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
    
    const token = req.cookies?.adminToken || 
                  req.headers['authorization']?.replace('Bearer ', '') ||
                  req.headers['x-admin-token'] ||
                  req.headers['x-token'] ||
                  req.headers['token'] ||
                  req.query.token;

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
        pricing.whatsappNumber = number.toString().trim();
        await pricing.save();
        res.json({ success: true, number: pricing.whatsappNumber });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save WhatsApp number' });
    }
});

app.post('/api/admin/whatsapp', authMiddleware, async (req, res) => {
    try {
        const { number } = req.body;
        let pricing = await Pricing.findOne();
        if (!pricing) pricing = new Pricing();
        pricing.whatsappNumber = (number || '916372923348').toString().trim();
        await pricing.save();
        res.json({ success: true, number: pricing.whatsappNumber });
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
        res.status(404).json({ error: 'No link found' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to map dashboard' });
    }
});

app.get('/api/visit-stats/:linkId', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        const { linkId } = req.params;
        let link = await Link.findOne(getLinkQuery(linkId));
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }
        const today = new Date().toISOString().split('T')[0];
        const isUidOn = !isUidCheckDisabled(link.uidChecking);
        res.json({
            linkId: link.id,
            name: link.name,
            totalVisits: link.visits || 0,
            totalClaims: link.claims || 0,
            todayVisits: link.dailyVisits?.get ? (link.dailyVisits.get(today) || 0) : (link.dailyVisits?.[today] || 0),
            todayClaims: link.dailyClaims?.get ? (link.dailyClaims.get(today) || 0) : (link.dailyClaims?.[today] || 0),
            dailyVisits: Object.fromEntries(link.dailyVisits || new Map()),
            dailyClaims: Object.fromEntries(link.dailyClaims || new Map()),
            status: link.status || 'active',
            expiryDate: link.expiryDate || null,
            uidChecking: isUidOn
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
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        let pricingDoc = await Pricing.findOne().lean();
        if (!pricingDoc) {
            pricingDoc = {
                pricing: { '7days': 100, '15days': 200, '30days': 400, '90days': 1000, '1year': 3000 },
                paymentSettings: { method: 'UPI', details: { upiId: 'admin@upi' } },
                whatsappNumber: '916372923348',
                autoPaymentEnabled: false
            };
        }
        res.json({
            pricing: pricingDoc.pricing || { '7days': 100, '15days': 200, '30days': 400, '90days': 1000, '1year': 3000 },
            paymentSettings: pricingDoc.paymentSettings || { method: 'UPI', details: { upiId: 'admin@upi' } },
            whatsappNumber: pricingDoc.whatsappNumber || '916372923348',
            autoPaymentEnabled: false
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch pricing' });
    }
});

app.post('/api/admin/pricing', authMiddleware, async (req, res) => {
    try {
        const { pricing, paymentSettings, upiId, whatsappNumber } = req.body;
        const updateFields = { autoPaymentEnabled: false };

        if (pricing && typeof pricing === 'object') updateFields.pricing = pricing;
        if (paymentSettings) updateFields.paymentSettings = paymentSettings;
        if (upiId) updateFields['paymentSettings.details.upiId'] = upiId.toString().trim();
        if (whatsappNumber) updateFields.whatsappNumber = whatsappNumber.toString().trim();

        const updatedPricing = await Pricing.findOneAndUpdate(
            {},
            { $set: updateFields },
            { upsert: true, new: true, lean: true }
        );

        res.json({ success: true, pricing: updatedPricing });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update pricing' });
    }
});

// =========================================================================
// 🎯 VISITOR LINK RESOLVER (RETURNS STRICT uidChecking: true / false)
// =========================================================================
app.get('/api/link/:id', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

        let rawId = extractCleanId(req.params.id);
        let link = await Link.findOne(getLinkQuery(rawId)).lean();

        if (!link && (rawId === 'default' || !rawId)) {
            const activeFallback = await Link.findOne({ status: 'active' }).sort({ created: -1 }).lean();
            if (activeFallback) {
                link = activeFallback;
            } else {
                return res.json({
                    id: 'default',
                    name: 'Welcome Bonus Reward',
                    video: 'https://youtu.be/dQw4w9WgXcQ',
                    claim: '#',
                    buttonText: 'Claim Now',
                    headline: '🎬 Watch Video & Unlock Reward',
                    status: 'active',
                    uidChecking: true,
                    popupSettings: {
                        image: null,
                        title: '🎁 Claim Your Reward',
                        buttonText: 'Claim Now',
                        subtitle: 'Tap below to unlock your reward'
                    }
                });
            }
        }

        if (!link) {
            return res.status(404).json({ error: 'not_found', message: 'Link not found' });
        }

        if (link.status === 'suspended' || link.status === 'disabled' || link.status === 'inactive') {
            return res.status(403).json({ error: link.status, message: `Link ${link.status}`, status: link.status });
        }

        if (link.expiryDate && !isNaN(new Date(link.expiryDate).getTime())) {
            const expTime = new Date(link.expiryDate).getTime();
            if (expTime > 1000000000000 && Date.now() > expTime) {
                return res.status(403).json({ error: 'expired', message: 'Link expired', status: 'expired' });
            }
        }

        // 🛡️ 24-Hour Unique Visit Tracking
        const { ip, deviceKey } = getDeviceId(req);
        const visitorKey = deviceKey || ip;
        const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

        const recentVisit = await VisitorActivity.findOne({
            linkId: link.id,
            visitorKey: visitorKey,
            type: 'visit',
            lastSeen: { $gte: twentyFourHoursAgo }
        }).catch(() => null);

        if (!recentVisit) {
            const today = new Date().toISOString().split('T')[0];
            Link.updateOne(
                { _id: link._id },
                { $inc: { visits: 1, [`dailyVisits.${today}`]: 1 } }
            ).catch(() => {});

            Stats.updateOne(
                {},
                { $inc: { totalVisitors: 1, [`dailyVisitors.${today}`]: 1 } }
            ).catch(() => {});
        }

        // Update lastSeen for Real-Time Active Watching
        await VisitorActivity.findOneAndUpdate(
            { linkId: link.id, visitorKey: visitorKey, type: 'visit' },
            { $set: { lastSeen: new Date() } },
            { upsert: true, new: true }
        ).catch(() => {});

        const popup = link.popupSettings || {};
        const bannerImage = popup.image || link.image || link.popupImage || link.popupImageUrl || link.banner || null;

        // 🎯 STRICT BOOLEAN CHECK (BOTH PER-LINK AND GLOBAL)
        const globalPopup = await PopupSettings.findOne().lean().catch(() => null);
        const isGlobalOff = globalPopup && isUidCheckDisabled(globalPopup.uidChecking);
        const isUidOn = (!isUidCheckDisabled(link.uidChecking)) && (!isGlobalOff);

        res.json({
            id: link.id,
            name: link.name,
            video: link.video || 'https://youtu.be/dQw4w9WgXcQ',
            claim: link.claim || '#',
            buttonText: link.buttonText || 'Claim Now',
            headline: link.headline || '🎬 Watch Video & Unlock Reward',
            status: link.status || 'active',
            expiryDate: link.expiryDate || null,
            uidChecking: isUidOn,
            image: bannerImage,
            popupImage: bannerImage,
            popupImageUrl: bannerImage,
            banner: bannerImage,
            popupSettings: {
                image: bannerImage,
                title: popup.title || '🎁 Claim Your Reward',
                buttonText: popup.buttonText || link.buttonText || 'Claim Now',
                subtitle: popup.subtitle || 'Tap below to unlock your reward'
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ✅ SUBMIT PLAYER UID ROUTE
app.post('/api/submit-uid/:linkId', async (req, res) => {
    try {
        const { uid } = req.body;
        const cleanUid = (uid || '').toString().trim();
        if (!cleanUid || cleanUid.length < 5) {
            return res.status(400).json({ error: 'Please enter a valid UID.' });
        }

        const link = await Link.findOne(getLinkQuery(req.params.linkId));
        if (!link) return res.status(404).json({ error: 'Link not found' });

        const { ip, deviceKey } = getDeviceId(req);
        const visitorKey = deviceKey || ip;

        await VisitorActivity.findOneAndUpdate(
            { linkId: link.id, visitorKey: visitorKey, type: 'visit' },
            { $set: { lastSeen: new Date(), uid: cleanUid } },
            { upsert: true, new: true }
        ).catch(() => {});

        res.json({ success: true, message: 'UID submitted successfully', uid: cleanUid });
    } catch (error) {
        res.status(500).json({ error: 'Failed to submit UID' });
    }
});

// ✅ TRACK CLAIM
app.post('/api/track-claim/:linkId', async (req, res) => {
    try {
        const link = await Link.findOne(getLinkQuery(req.params.linkId));
        if (!link) return res.status(404).json({ error: 'Link not found' });

        const { ip, deviceKey } = getDeviceId(req);
        const visitorKey = deviceKey || ip;
        const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

        const recentClaim = await VisitorActivity.findOne({
            linkId: link.id,
            visitorKey: visitorKey,
            type: 'claim',
            lastSeen: { $gte: twentyFourHoursAgo }
        }).catch(() => null);

        if (!recentClaim) {
            const today = new Date().toISOString().split('T')[0];
            link.claims = (link.claims || 0) + 1;
            if (!link.dailyClaims) link.dailyClaims = new Map();
            const currentDaily = link.dailyClaims.get ? (link.dailyClaims.get(today) || 0) : (link.dailyClaims[today] || 0);
            if (link.dailyClaims.set) link.dailyClaims.set(today, currentDaily + 1);
            else link.dailyClaims[today] = currentDaily + 1;
            await link.save().catch(() => {});

            await Stats.updateOne(
                {},
                { $inc: { totalClaims: 1, [`dailyClaims.${today}`]: 1 } }
            ).catch(() => {});
        }

        await VisitorActivity.findOneAndUpdate(
            { linkId: link.id, visitorKey: visitorKey, type: 'claim' },
            { $set: { lastSeen: new Date() } },
            { upsert: true, new: true }
        ).catch(() => {});

        res.json({ success: true, claims: link.claims || 0 });
    } catch (error) {
        res.status(500).json({ error: 'Failed to track claim' });
    }
});

// History Route
app.get('/api/renewal/history/:linkId', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        const { linkId } = req.params;
        const history = await RenewalRequest.find({ linkId }).sort({ createdAt: -1 }).limit(7).lean();
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
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        const { linkId } = req.params;
        const request = await RenewalRequest.findOne({ linkId }).sort({ createdAt: -1 }).lean();
        res.json({ hasRequest: !!request, request: request || null, status: request?.status || 'none' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch status' });
    }
});

app.get('/api/settings', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        const admin = await User.findOne().lean();
        const popupSettings = await PopupSettings.findOne().lean();
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

// ==================== 🔄 USER SIGNUP & SIGNIN ====================
app.post('/api/user/signup', async (req, res) => {
    try {
        const { name, email, phone } = req.body;
        if (!name || !email || !phone) return res.status(400).json({ error: 'All fields are required' });

        const cleanEmail = email.trim().toLowerCase();
        const cleanPhone = phone.trim();

        const emailExists = await RenewalUser.findOne({ email: cleanEmail });
        if (emailExists) {
            return res.status(400).json({ error: 'This Email Address is already registered! Please sign in.' });
        }

        const phoneExists = await RenewalUser.findOne({ phone: cleanPhone });
        if (phoneExists) {
            return res.status(400).json({ error: 'This Phone Number is already registered! Please sign in.' });
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
            return res.status(403).json({ error: 'Your account is pending approval from Administrator.' });
        }
        if (user.status === 'rejected') {
            return res.status(403).json({ error: 'Your account registration was rejected by Administrator.' });
        }

        res.json({
            success: true,
            user: { id: user._id, name: user.name, email: user.email, phone: user.phone }
        });
    } catch (e) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// POST /api/user/link-details
app.post('/api/user/link-details', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        const { userName, linkInput } = req.body;
        const cleanUser = (userName || '').trim();

        const allUserLinks = await Link.find({ 
            name: new RegExp('^' + cleanUser.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i') 
        }).sort({ created: -1 }).lean();

        let link = null;
        let searchId = extractCleanId(linkInput);

        if (searchId && searchId !== cleanUser) {
            link = await Link.findOne(getLinkQuery(searchId));
        }

        if (!link && cleanUser) {
            link = allUserLinks.length > 0 ? allUserLinks[0] : null;
        }

        if (!link && searchId) {
            link = await Link.findOne({ name: new RegExp('^' + searchId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i') }).sort({ created: -1 });
        }

        if (!link) {
            return res.status(404).json({ 
                error: `No active link found for user "${cleanUser}". Please connect your assigned Link ID.`,
                userLinks: allUserLinks
            });
        }

        if (link.name && cleanUser && link.name.toLowerCase().trim() !== cleanUser.toLowerCase()) {
            return res.status(403).json({ error: `Security Warning: Link "${link.id}" is assigned to "${link.name}", not "${cleanUser}".` });
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

        const pricingDoc = await Pricing.findOne().lean();
        const isUidOn = !isUidCheckDisabled(link.uidChecking);

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
                v24h, c24h, v7d, c7d, v30d, c30d,
                uidChecking: isUidOn
            },
            userLinks: allUserLinks,
            pricing: pricingDoc?.pricing || { '7days': 100, '15days': 200, '30days': 400, '90days': 1000, '1year': 3000 },
            paymentSettings: pricingDoc?.paymentSettings || { details: { upiId: 'admin@upi' } },
            autoPaymentEnabled: false,
            whatsappNumber: pricingDoc?.whatsappNumber || '916372923348'
        });
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch link data' });
    }
});

// POST /api/user/renew-payment
app.post('/api/user/renew-payment', async (req, res) => {
    try {
        const { linkId, plan, days, amount, refNo, userName } = req.body;
        if (!linkId || !plan) return res.status(400).json({ error: 'Link ID and plan required' });

        const cleanRef = (refNo || 'Manual-WhatsApp').toString().trim();

        await RenewalRequest.create({
            id: 'req_' + Date.now(),
            linkId,
            linkName: userName || 'Unknown',
            plan,
            days: parseInt(days) || 30,
            amount: parseInt(amount) || 0,
            transactionId: cleanRef,
            status: 'pending'
        });

        res.json({
            success: true,
            manual: true,
            message: 'Renewal request submitted. Administrator will review and approve.'
        });
    } catch (e) {
        res.status(500).json({ error: 'Payment processing error' });
    }
});

// ================================================================
// ==================== 🔗 USER DASHBOARD: SHORT LINKS ====================
// ================================================================
app.get('/api/user/short-links', async (req, res) => {
    try {
        const { userName } = req.query;
        const filter = userName ? { creator: userName } : {};
        const links = await ShortLink.find(filter).sort({ createdAt: -1 }).lean();
        res.json({ success: true, links });
    } catch(e) {
        res.status(500).json({ error: 'Failed to fetch short links' });
    }
});

app.post('/api/user/short-links', async (req, res) => {
    try {
        const { originalUrl, title, userName, appOpen, appScheme } = req.body;
        if (!originalUrl) return res.status(400).json({ error: 'URL required' });
        const link = new ShortLink({
            code: Math.random().toString(36).substring(2, 8),
            originalUrl,
            title: title || 'Untitled',
            creator: userName || 'User',
            appOpen: !!appScheme,
            appScheme: appScheme || ''
        });
        await link.save();
        res.json({ success: true, link, shortUrl: `${req.protocol}://${req.get('host')}/s/${link.code}` });
    } catch(e) {
        res.status(500).json({ error: 'Failed to create short link' });
    }
});

app.delete('/api/user/short-links/:id', async (req, res) => {
    try {
        await ShortLink.findByIdAndDelete(req.params.id);
        await ShortLinkClick.deleteMany({ shortLinkId: req.params.id }).catch(() => {});
        res.json({ success: true });
    } catch(e) {
        res.status(500).json({ error: 'Failed to delete short link' });
    }
});

// ================================================================
// ==================== 👥 ADMIN: USER MANAGEMENT ====================
// ================================================================
app.get('/api/admin/all-users', authMiddleware, async (req, res) => {
    try {
        const users = await RenewalUser.find().sort({ createdAt: -1 }).lean();
        const links = await Link.find().lean();
        const usersWithStats = users.map(u => {
            const cleanName = (u.name || '').toLowerCase().trim();
            const userLinks = links.filter(l => (l.name || '').toLowerCase().trim() === cleanName);
            return {
                ...u,
                totalLinks: userLinks.length
            };
        });
        res.json({ success: true, users: usersWithStats, totalUsers: users.length });
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.delete('/api/admin/users/:id', authMiddleware, async (req, res) => {
    try {
        await RenewalUser.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'User deleted successfully' });
    } catch (e) {
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

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

// ==================== ADMIN: RENEWAL SETTINGS & REQUESTS ====================
app.get('/api/admin/renewal-settings', authMiddleware, async (req, res) => {
    try {
        const pricing = await Pricing.findOne().lean();
        const requests = await RenewalRequest.find({ status: 'pending' }).sort({ createdAt: -1 }).lean();
        res.json({ success: true, pricing, requests });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/renewal-settings', authMiddleware, async (req, res) => {
    try {
        const { pricing, upiId, whatsappNumber, paymentSettings } = req.body;
        const updateData = { autoPaymentEnabled: false };

        if (pricing && typeof pricing === 'object') updateData.pricing = pricing;
        if (paymentSettings) updateData.paymentSettings = paymentSettings;
        if (upiId) updateData['paymentSettings.details.upiId'] = upiId.toString().trim();
        if (whatsappNumber) updateData.whatsappNumber = whatsappNumber.toString().trim();

        const updatedDoc = await Pricing.findOneAndUpdate(
            {},
            { $set: updateData },
            { upsert: true, new: true, lean: true }
        );

        res.json({ success: true, message: 'Settings saved', pricing: updatedDoc });
    } catch (e) {
        res.status(500).json({ error: 'Failed to save renewal settings' });
    }
});

app.post('/api/admin/renewal-requests/:id/approve', authMiddleware, async (req, res) => {
    try {
        const reqDoc = await RenewalRequest.findOne({ id: req.params.id });
        if (!reqDoc) return res.status(404).json({ error: 'Request not found' });

        const link = await Link.findOne(getLinkQuery(reqDoc.linkId));
        if (link) {
            const curExpiry = link.expiryDate && new Date(link.expiryDate) > new Date() ? new Date(link.expiryDate) : new Date();
            curExpiry.setDate(curExpiry.getDate() + (reqDoc.days || 30));
            link.expiryDate = curExpiry;
            link.status = 'active';
            await link.save();
        }

        reqDoc.status = 'approved';
        reqDoc.approvedAt = new Date();
        await reqDoc.save();

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

app.post('/api/renewal/approve/:requestId', authMiddleware, async (req, res) => {
    try {
        const request = await RenewalRequest.findOne({ id: req.params.requestId });
        if (!request) return res.status(404).json({ error: 'Request not found' });
        const link = await Link.findOne(getLinkQuery(request.linkId));
        if (link) {
            const currentExpiry = link.expiryDate && new Date(link.expiryDate) > new Date() ? new Date(link.expiryDate) : new Date();
            currentExpiry.setDate(currentExpiry.getDate() + (request.days || 30));
            link.expiryDate = currentExpiry;
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
        res.json({ success: true, message: 'Renewal rejected successfully' });
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
// 🔑 ADMIN AUTHENTICATION & STRICT PASSCODE SYSTEM
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
        const { passcode } = req.body;
        const cleanPass = (passcode || '').toString().trim();

        if (!cleanPass) return res.status(400).json({ error: 'Passcode required' });

        let admin = await User.findOne();
        const activeEnvPass = process.env.ADMIN_PASSCODE ? process.env.ADMIN_PASSCODE.toString().trim() : DEFAULT_PASSCODE;

        if (!admin || !admin.passcode) {
            const hashed = bcrypt.hashSync(activeEnvPass, 10);
            admin = await User.create({
                passcode: hashed,
                lastEnvPasscode: activeEnvPass,
                theme: 'dark',
                email: process.env.ADMIN_EMAIL || '',
                phone: process.env.ADMIN_PHONE || '',
                secretKey: 'admin@2024'
            });
        } else if (process.env.ADMIN_PASSCODE && admin.lastEnvPasscode !== activeEnvPass) {
            admin.passcode = bcrypt.hashSync(activeEnvPass, 10);
            admin.lastEnvPasscode = activeEnvPass;
            await admin.save();
        }

        const isValid = verifyPasscode(cleanPass, admin.passcode);

        if (isValid) {
            const { deviceKey, fingerprint, ip } = getDeviceId(req);
            const { deviceName, deviceType } = getDeviceDetails(req);
            await BlockedDevice.deleteMany({ $or: [{ deviceKey }, { ip }, { fingerprint }] }).catch(() => {});

            try {
                if (Session) {
                    await Session.create({
                        userId: 'admin',
                        deviceKey,
                        fingerprint,
                        ip,
                        userAgent: (req.headers && req.headers['user-agent']) ? req.headers['user-agent'].toString() : 'Unknown',
                        deviceName,
                        deviceType,
                        isActive: true,
                        lastActivity: new Date(),
                        createdAt: new Date(),
                        expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000)
                    }).catch(() => {});
                }
            } catch(e) {}

            const jwtToken = generateToken('admin');
            res.cookie('adminToken', jwtToken, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 3600 * 1000 });
            return res.json({ success: true, token: jwtToken });
        }

        const blocked = await isDeviceBlocked(req);
        if (blocked) {
            return res.status(403).json({
                error: 'permanently_blocked',
                message: '⛔ This device is permanently banned from accessing the admin portal.'
            });
        }

        const { deviceKey, fingerprint, ip } = getDeviceId(req);
        const { deviceName, deviceType } = getDeviceDetails(req);

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
                error: `Incorrect Passcode! Attempt ${record.attempts} of 3.`
            });
        }
    } catch (error) {
        console.error('Safe login caught:', error);
        res.status(500).json({ error: 'Server authentication error' });
    }
});

app.post('/api/admin/logout', async (req, res) => {
    try {
        const { deviceKey, fingerprint, ip } = getDeviceId(req);
        await Session.deleteMany({ $or: [{ deviceKey }, { ip }, { fingerprint }] }).catch(() => {});
    } catch(e) {}
    res.clearCookie('adminToken');
    res.json({ success: true });
});

app.post('/api/admin/passcode', authMiddleware, async (req, res) => {
    try {
        const { oldPasscode, newPasscode } = req.body;
        const cleanOld = (oldPasscode || '').toString().trim();
        const cleanNew = (newPasscode || '').toString().trim();

        if (!cleanNew || cleanNew.length !== 6) {
            return res.status(400).json({ error: 'New passcode must be 6 digits' });
        }

        const admin = await User.findOne();
        if (!admin) return res.status(404).json({ error: 'Admin not found' });

        const isCurrentValid = verifyPasscode(cleanOld, admin.passcode);
        if (!isCurrentValid) {
            return res.status(401).json({ error: 'Current passcode is incorrect' });
        }

        admin.passcode = bcrypt.hashSync(cleanNew, 10);
        admin.lastEnvPasscode = cleanNew;
        await admin.save();
        res.json({ success: true, message: 'Passcode changed successfully! Old passcode is permanently disabled.' });
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
        if (req.body.background !== undefined) popup.image = req.body.background || null;
        if (req.body.uidChecking !== undefined) {
            popup.uidChecking = !isUidCheckDisabled(req.body.uidChecking);
        }
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

app.post('/api/admin/update-contact', authMiddleware, async (req, res) => {
    const admin = await User.findOne();
    if (admin) {
        if (req.body.email) admin.email = req.body.email;
        if (req.body.phone) admin.phone = req.body.phone;
        await admin.save();
    }
    res.json({ success: true });
});

// ==================== 🔗 ADMIN: LINKS CRUD WITH DIRECT MONGODB PERSISTENCE ====================
app.get('/api/links', authMiddleware, async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        const links = await Link.find().sort({ created: -1 }).lean();
        
        const formatted = links.map(l => {
            const popup = l.popupSettings || {};
            const img = popup.image || l.image || l.popupImage || l.popupImageUrl || l.banner || null;
            const isUidOn = !isUidCheckDisabled(l.uidChecking);
            return {
                ...l,
                uidChecking: isUidOn,
                image: img,
                popupImage: img,
                popupImageUrl: img,
                banner: img,
                popupSettings: {
                    ...popup,
                    image: img,
                    popupImage: img,
                    popupImageUrl: img
                }
            };
        });
        res.json(formatted);
    } catch(e) {
        res.status(500).json({ error: 'Failed to fetch links' });
    }
});

app.get('/api/links/:id', authMiddleware, async (req, res) => {
    try {
        const rawId = extractCleanId(req.params.id);
        const query = getLinkQuery(rawId);
        const l = await Link.findOne(query).lean();
        if (!l) return res.status(404).json({ error: 'Link not found' });
        
        const popup = l.popupSettings || {};
        const img = popup.image || l.image || l.popupImage || l.popupImageUrl || l.banner || null;
        const isUidOn = !isUidCheckDisabled(l.uidChecking);
        res.json({
            ...l,
            uidChecking: isUidOn,
            image: img,
            popupImage: img,
            popupImageUrl: img,
            banner: img,
            popupSettings: {
                ...popup,
                image: img,
                popupImage: img,
                popupImageUrl: img
            }
        });
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch link' });
    }
});

// ➕ CREATE REWARDED TRACKING LINK
app.post('/api/links', authMiddleware, async (req, res) => {
    try {
        const cleanName = (req.body.name || req.body.title || 'Untitled Link').trim();
        const cleanVideo = (req.body.video || req.body.videoUrl || req.body.url || req.body.youtubeUrl || 'https://youtu.be/dQw4w9WgXcQ').trim();
        const cleanClaim = (req.body.claim || req.body.claimUrl || req.body.claimLink || '#').trim();
        const cleanButtonText = (req.body.buttonText || req.body.btnText || 'Claim Now').trim();
        const cleanHeadline = (req.body.headline || req.body.heading || '🎬 Watch Video & Unlock Reward').trim();

        // Check UID Checking from all possible param aliases
        let incomingUidVal = req.body.uidChecking !== undefined ? req.body.uidChecking :
                             (req.body.uidCheck !== undefined ? req.body.uidCheck :
                             (req.body.checkUid !== undefined ? req.body.checkUid :
                             (req.body.isUidChecking !== undefined ? req.body.isUidChecking :
                             (req.body.enableUid !== undefined ? req.body.enableUid :
                             (req.body.uid !== undefined ? req.body.uid :
                             (req.body.uid_checking !== undefined ? req.body.uid_checking : undefined))))));

        let cleanUidChecking = true;
        if (incomingUidVal !== undefined) {
            cleanUidChecking = !isUidCheckDisabled(incomingUidVal);
        }

        const rawExpiry = req.body.expiryDate || req.body.expiry || req.body.expDate || req.body.expireDate;
        let cleanExpiry = null;
        if (rawExpiry && !isNaN(new Date(rawExpiry).getTime())) {
            cleanExpiry = new Date(rawExpiry);
        }

        let incomingImage = req.body.popupImage || 
                            req.body.image || 
                            req.body.popupImageUrl || 
                            req.body.banner || 
                            req.body.bannerImage || 
                            req.body.bannerUrl || 
                            req.body.popupImg || 
                            req.body.img;

        let parsedPopup = req.body.popupSettings;
        if (typeof parsedPopup === 'string') {
            try { parsedPopup = JSON.parse(parsedPopup); } catch(e) { parsedPopup = {}; }
        }
        parsedPopup = parsedPopup || {};

        if (!incomingImage && parsedPopup.image) {
            incomingImage = parsedPopup.image;
        }

        const finalBanner = incomingImage && incomingImage.trim().length > 4 ? incomingImage.trim() : null;

        const finalPopup = {
            title: parsedPopup.title || req.body.popupTitle || '🎁 Claim Your Reward',
            subtitle: parsedPopup.subtitle || req.body.popupSubtitle || 'Tap below to unlock your reward',
            buttonText: parsedPopup.buttonText || req.body.popupButtonText || cleanButtonText,
            image: finalBanner
        };

        const newLink = new Link({
            id: 'link_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex'),
            name: cleanName,
            video: cleanVideo,
            claim: cleanClaim,
            buttonText: cleanButtonText,
            headline: cleanHeadline,
            expiryDate: cleanExpiry,
            uidChecking: cleanUidChecking,
            status: 'active',
            image: finalBanner,
            popupImage: finalBanner,
            popupImageUrl: finalBanner,
            banner: finalBanner,
            popupSettings: finalPopup
        });

        newLink.set('uidChecking', cleanUidChecking, { strict: false });
        await newLink.save({ validateBeforeSave: false });

        // 🛡️ Direct Raw MongoDB Write Guarantee:
        try {
            await Link.collection.updateOne({ _id: newLink._id }, { $set: { uidChecking: cleanUidChecking } });
        } catch(err) {}

        res.json({
            ...newLink.toObject(),
            uidChecking: cleanUidChecking,
            image: finalBanner,
            popupImage: finalBanner,
            popupImageUrl: finalBanner,
            banner: finalBanner,
            popupSettings: finalPopup
        });
    } catch (e) {
        console.error('❌ Error creating link:', e);
        res.status(500).json({ error: 'Failed to create link' });
    }
});

// Helper: Handle Link Update logic across PUT / POST / PATCH
async function handleLinkUpdate(req, res) {
    try {
        const rawId = extractCleanId(req.params.id);
        const query = getLinkQuery(rawId);
        const link = await Link.findOne(query);
        if (!link) return res.status(404).json({ error: 'Link not found' });

        // 🎯 Direct Toggle action support
        if (req.path.includes('toggle') || req.body.action === 'toggle' || req.body.toggle === true) {
            const currentVal = !isUidCheckDisabled(link.uidChecking);
            const newVal = !currentVal;
            link.uidChecking = newVal;
            await link.save();
            await Link.collection.updateMany(query, { $set: { uidChecking: newVal } });
            return res.json({ success: true, uidChecking: newVal, message: `UID checking set to ${newVal ? 'ON' : 'OFF'}` });
        }

        const updateData = {};

        if (req.body.name !== undefined) updateData.name = req.body.name.trim();
        else if (req.body.title !== undefined) updateData.name = req.body.title.trim();

        const incomingVideo = req.body.video !== undefined ? req.body.video :
                              (req.body.videoUrl !== undefined ? req.body.videoUrl :
                              (req.body.url !== undefined ? req.body.url : req.body.youtubeUrl));
        if (incomingVideo !== undefined) updateData.video = incomingVideo.trim();

        const incomingClaim = req.body.claim !== undefined ? req.body.claim :
                              (req.body.claimUrl !== undefined ? req.body.claimUrl :
                              (req.body.claimLink !== undefined ? req.body.claimLink :
                              (req.body.rewardUrl !== undefined ? req.body.rewardUrl : req.body.targetUrl)));
        if (incomingClaim !== undefined) updateData.claim = incomingClaim.trim();

        const incomingBtn = req.body.buttonText !== undefined ? req.body.buttonText :
                            (req.body.btnText !== undefined ? req.body.btnText : req.body.button_text);
        if (incomingBtn !== undefined) updateData.buttonText = incomingBtn.trim();

        const incomingHeadline = req.body.headline !== undefined ? req.body.headline :
                                 (req.body.heading !== undefined ? req.body.heading : req.body.headLine);
        if (incomingHeadline !== undefined) updateData.headline = incomingHeadline.trim();

        if (req.body.status !== undefined) updateData.status = req.body.status;

        // 🎯 UID CHECKING (CAPTURE ALL POSSIBLE PARAMETER ALIASES)
        let incomingUidVal = req.body.uidChecking !== undefined ? req.body.uidChecking :
                             (req.body.uidCheck !== undefined ? req.body.uidCheck :
                             (req.body.checkUid !== undefined ? req.body.checkUid :
                             (req.body.isUidChecking !== undefined ? req.body.isUidChecking :
                             (req.body.enableUid !== undefined ? req.body.enableUid :
                             (req.body.uid !== undefined ? req.body.uid :
                             (req.body.uid_checking !== undefined ? req.body.uid_checking :
                             (req.body.uidStatus !== undefined ? req.body.uidStatus : undefined)))))));

        let hasUidUpdate = false;
        if (incomingUidVal !== undefined) {
            updateData.uidChecking = !isUidCheckDisabled(incomingUidVal);
            hasUidUpdate = true;
        } else if (req.body.isEditForm || (req.body.name && req.body.video)) {
            // HTML Form Checkbox omission behavior: If unchecked, formData omits it entirely!
            // If full link edit form is submitted without the checkbox, it means UNCHECKED (OFF).
            updateData.uidChecking = false;
            hasUidUpdate = true;
        }

        const incomingExpiry = req.body.expiryDate !== undefined ? req.body.expiryDate :
                               (req.body.expiry !== undefined ? req.body.expiry :
                               (req.body.expDate !== undefined ? req.body.expDate :
                               (req.body.expireDate !== undefined ? req.body.expireDate : req.body.expiry_date)));
        
        if (incomingExpiry !== undefined) {
            if (incomingExpiry && !isNaN(new Date(incomingExpiry).getTime())) {
                updateData.expiryDate = new Date(incomingExpiry);
            } else {
                updateData.expiryDate = null;
            }
        }

        let incomingImage = req.body.popupImage !== undefined ? req.body.popupImage :
                            (req.body.image !== undefined ? req.body.image :
                            (req.body.popupImageUrl !== undefined ? req.body.popupImageUrl :
                            (req.body.banner !== undefined ? req.body.banner :
                            (req.body.bannerImage !== undefined ? req.body.bannerImage :
                            (req.body.bannerUrl !== undefined ? req.body.bannerUrl :
                            (req.body.popupImg !== undefined ? req.body.popupImg : req.body.img))))));

        let parsedPopup = req.body.popupSettings;
        if (typeof parsedPopup === 'string') {
            try { parsedPopup = JSON.parse(parsedPopup); } catch(e) { parsedPopup = {}; }
        }
        if (parsedPopup && typeof parsedPopup === 'object' && parsedPopup.image !== undefined && incomingImage === undefined) {
            incomingImage = parsedPopup.image;
        }

        const currentPopup = link.popupSettings || {};
        const newPopup = {
            title: currentPopup.title || '🎁 Claim Your Reward',
            subtitle: currentPopup.subtitle || 'Tap below to unlock your reward',
            buttonText: currentPopup.buttonText || link.buttonText || 'Claim Now',
            image: currentPopup.image || null
        };

        if (incomingImage !== undefined) {
            const cleanImg = (incomingImage || '').trim();
            const finalImg = cleanImg.length > 4 ? cleanImg : null;
            newPopup.image = finalImg;
            updateData.image = finalImg;
            updateData.popupImage = finalImg;
            updateData.popupImageUrl = finalImg;
            updateData.banner = finalImg;
        }

        if (parsedPopup && typeof parsedPopup === 'object') {
            if (parsedPopup.title !== undefined) newPopup.title = parsedPopup.title.trim();
            if (parsedPopup.subtitle !== undefined) newPopup.subtitle = parsedPopup.subtitle.trim();
            if (parsedPopup.buttonText !== undefined) newPopup.buttonText = parsedPopup.buttonText.trim();
        }
        if (req.body.popupTitle !== undefined) newPopup.title = req.body.popupTitle.trim();
        if (req.body.popupSubtitle !== undefined) newPopup.subtitle = req.body.popupSubtitle.trim();
        if (req.body.popupButtonText !== undefined) newPopup.buttonText = req.body.popupButtonText.trim();

        updateData.popupSettings = newPopup;

        const updatedLink = await Link.findOneAndUpdate(
            query,
            { $set: updateData },
            { new: true, lean: true, strict: false }
        );

        // 🛡️ DIRECT MONGODB NATIVE DRIVER UPDATE GUARANTEE
        if (hasUidUpdate) {
            try {
                await Link.collection.updateMany(query, { $set: { uidChecking: updateData.uidChecking } });
            } catch(err) {}
            try {
                if (mongoose.connection && mongoose.connection.db) {
                    await mongoose.connection.db.collection('links').updateMany(query, { $set: { uidChecking: updateData.uidChecking } });
                }
            } catch(err) {}
        }

        const finalUidState = updateData.uidChecking !== undefined ? updateData.uidChecking : !isUidCheckDisabled(updatedLink.uidChecking);

        res.json({
            success: true,
            link: {
                ...updatedLink,
                uidChecking: finalUidState,
                image: newPopup.image,
                popupImage: newPopup.image,
                popupImageUrl: newPopup.image,
                banner: newPopup.image,
                popupSettings: newPopup
            }
        });
    } catch (e) {
        console.error('❌ Error updating link:', e);
        res.status(500).json({ error: 'Failed to update link', details: e.message });
    }
}

// ✏️ EDIT REWARDED LINK (Supports PUT, POST, PATCH and specific UID routes)
app.put('/api/links/:id', authMiddleware, handleLinkUpdate);
app.post('/api/links/:id', authMiddleware, handleLinkUpdate);
app.patch('/api/links/:id', authMiddleware, handleLinkUpdate);
app.all('/api/links/:id/uid-checking', authMiddleware, handleLinkUpdate);
app.all('/api/links/:id/toggle-uid', authMiddleware, handleLinkUpdate);
app.all('/api/links/:id/uid', authMiddleware, handleLinkUpdate);
app.all('/api/links/:id/toggle', authMiddleware, handleLinkUpdate);

app.put('/api/links/:id/status', authMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        const rawId = extractCleanId(req.params.id);
        const query = getLinkQuery(rawId);
        const link = await Link.findOneAndUpdate(query, { status }, { new: true });
        if (!link) return res.status(404).json({ error: 'Link not found' });
        res.json(link);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update status' });
    }
});

app.delete('/api/links/:id', authMiddleware, async (req, res) => {
    try {
        const rawId = extractCleanId(req.params.id);
        const query = getLinkQuery(rawId);
        await Link.findOneAndDelete(query);
        try {
            await Link.collection.deleteMany(query);
        } catch(e) {}
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete link' });
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
        const rawId = extractCleanId(linkId);
        const link = await Link.findOne(getLinkQuery(rawId));
        if (!link) return res.status(404).json({ error: 'Link not found' });
        const dashboardId = 'dashboard_' + Date.now() + '_' + crypto.randomBytes(8).toString('hex');
        link.dashboardId = dashboardId;
        await link.save();
        res.json({ success: true, dashboardId, dashboardUrl: '/user-dashboard/' + dashboardId, fullUrl: `${req.protocol}://${req.get('host')}/user-dashboard/${dashboardId}`, linkName: link.name, linkId: link.id });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate dashboard link' });
    }
});

// ==================== 📊 STATS API ====================
app.get('/api/all-stats', authMiddleware, async (req, res) => {
    try {
        const links = await Link.find().lean();
        const today = new Date().toISOString().split('T')[0];

        let totV = 0;
        let totC = 0;
        let todayV = 0;
        let todayC = 0;

        links.forEach(l => {
            totV += (l.visits || 0);
            totC += (l.claims || 0);

            if (l.dailyVisits) {
                const dv = l.dailyVisits instanceof Map ? l.dailyVisits.get(today) : l.dailyVisits[today];
                todayV += parseInt(dv) || 0;
            }
            if (l.dailyClaims) {
                const dc = l.dailyClaims instanceof Map ? l.dailyClaims.get(today) : l.dailyClaims[today];
                todayC += parseInt(dc) || 0;
            }
        });

        const threeMinutesAgo = new Date(Date.now() - 3 * 60 * 1000);
        const activeWatching = await VisitorActivity.countDocuments({
            type: 'visit',
            lastSeen: { $gte: threeMinutesAgo }
        }).catch(() => 0);

        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        const activeClaiming = await VisitorActivity.countDocuments({
            type: 'claim',
            lastSeen: { $gte: fiveMinutesAgo }
        }).catch(() => 0);

        res.json({
            global: {
                totalVisitors: totV,
                totalClaims: totC,
                todayVisitors: todayV,
                todayClaims: todayC,
                activeNow: activeWatching,
                activeClaims: activeClaiming
            },
            links: links.map(l => ({
                ...l,
                uidChecking: !isUidCheckDisabled(l.uidChecking)
            }))
        });
    } catch(e) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// ================================================================
// ==================== 🛡️ BLOCKED & ACTIVE DEVICES ====================
// ================================================================
app.get('/api/admin/blocked-devices', authMiddleware, async (req, res) => {
    const devices = await BlockedDevice.find({ isPermanent: true }).sort({ lastAttempt: -1 });
    res.json({ success: true, devices });
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

app.get('/api/admin/active-sessions', authMiddleware, async (req, res) => {
    try {
        const sessions = await Session.find({ isActive: true }).sort({ lastActivity: -1 });
        res.json({ success: true, sessions });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch active sessions' });
    }
});

app.delete('/api/admin/sessions/:id', authMiddleware, async (req, res) => {
    try {
        await Session.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'Session terminated' });
    } catch (e) {
        res.status(500).json({ error: 'Failed to terminate session' });
    }
});

app.post('/api/admin/sessions/:id/block', authMiddleware, async (req, res) => {
    try {
        const session = await Session.findById(req.params.id);
        if (session) {
            await BlockedDevice.create({
                ip: session.ip || '127.0.0.1',
                deviceKey: session.deviceKey || crypto.randomBytes(16).toString('hex'),
                fingerprint: session.fingerprint || crypto.randomBytes(16).toString('hex'),
                deviceName: session.deviceName || 'Admin Device',
                deviceType: session.deviceType || 'Desktop',
                attempts: 3,
                isPermanent: true,
                reason: 'Terminated & blocked by admin from Active Devices list',
                lastAttempt: new Date()
            });
            await Session.findByIdAndDelete(req.params.id);
        }
        res.json({ success: true, message: 'Device blocked permanently and session terminated' });
    } catch (e) {
        res.status(500).json({ error: 'Failed to block device' });
    }
});

// ==================== 🔗 ADMIN SHORT LINKS ====================
app.get('/s/:code', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
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

    // 🎯 SMART REDIRECT CHECK: If short link points to /uid?link=... and UID checking is OFF:
    try {
        const orig = link.originalUrl || '';
        if (orig.includes('/uid') || orig.includes('link=')) {
            const cleanId = extractCleanId(orig);
            if (cleanId) {
                const targetLink = await Link.findOne(getLinkQuery(cleanId)).lean();
                if (targetLink && isUidCheckDisabled(targetLink.uidChecking)) {
                    return res.redirect('/v/' + encodeURIComponent(targetLink.id || cleanId));
                }
            }
        }
    } catch(err) {}

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

// 🛡️ Fail-Safe Resolver for uid-checker.html with Instant Client Redirect Script
function sendUidCheckerFile(res, targetLinkId) {
    const searchDirs = [path.join(__dirname, '..'), path.join(__dirname, '..', 'admin'), __dirname];
    const fileNames = ['uid-checker.html', 'uid.html'];

    for (const name of fileNames) {
        for (const dir of searchDirs) {
            const p = path.join(dir, name);
            if (fs.existsSync(p)) {
                try {
                    let content = fs.readFileSync(p, 'utf8');
                    // Injected script executes at the very first millisecond in the browser:
                    const guardScript = `
<script>
(function() {
    try {
        var p = new URLSearchParams(window.location.search);
        var lid = p.get('link') || p.get('id') || p.get('l') || ${JSON.stringify(targetLinkId || '')};
        if (!lid) {
            var parts = window.location.pathname.split('/');
            var last = parts[parts.length - 1];
            if (last && last !== 'uid' && last !== 'uid.html' && last !== 'uid-checker.html') lid = last;
        }
        if (lid) {
            fetch('/api/link/' + encodeURIComponent(lid))
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d && (d.uidChecking === false || d.uidChecking === 'false' || d.uidChecking === 'off' || d.uidChecking === 0)) {
                    window.location.replace('/v/' + encodeURIComponent(d.id || lid));
                }
            }).catch(function(){});
        }
    } catch(e) {}
})();
</script>
`;
                    if (content.includes('<head>')) {
                        content = content.replace('<head>', '<head>' + guardScript);
                    } else if (content.includes('<body>')) {
                        content = content.replace('<body>', '<body>' + guardScript);
                    } else {
                        content = guardScript + content;
                    }
                    res.setHeader('Content-Type', 'text/html; charset=utf-8');
                    return res.send(content);
                } catch(e) {
                    return res.sendFile(p);
                }
            }
        }
    }
    res.status(404).send('File not found: uid-checker.html');
}

// 🛡️ Safe Resolver for video-lock.html with pre-verified session keys
function sendVideoLockFile(res, targetLinkId) {
    const searchDirs = [path.join(__dirname, '..'), path.join(__dirname, '..', 'admin'), __dirname];
    const fileNames = ['video-lock.html'];

    for (const name of fileNames) {
        for (const dir of searchDirs) {
            const p = path.join(dir, name);
            if (fs.existsSync(p)) {
                try {
                    let content = fs.readFileSync(p, 'utf8');
                    const preVerifyScript = `
<script>
window.__LINK_ID__ = ${JSON.stringify(targetLinkId || '')};
try {
    sessionStorage.setItem('player_uid', 'verified');
    sessionStorage.setItem('uid_verified', 'true');
    localStorage.setItem('player_uid', 'verified');
    localStorage.setItem('uid_verified', 'true');
} catch(e) {}
</script>
`;
                    if (content.includes('<head>')) {
                        content = content.replace('<head>', '<head>' + preVerifyScript);
                    } else if (content.includes('<body>')) {
                        content = content.replace('<body>', '<body>' + preVerifyScript);
                    } else {
                        content = preVerifyScript + content;
                    }
                    res.setHeader('Content-Type', 'text/html; charset=utf-8');
                    return res.send(content);
                } catch(e) {
                    return res.sendFile(p);
                }
            }
        }
    }
    res.status(404).send('File not found: video-lock.html');
}

// ⛔ Persistent Ban Shield on Login Route
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

app.get('/', async (req, res) => {
    // If someone visits /?link=... check UID checking
    let rawParam = (req.query.link || req.query.id || req.query.l || '').toString().trim();
    if (rawParam) {
        let cleanId = extractCleanId(rawParam);
        if (cleanId) {
            const link = await Link.findOne(getLinkQuery(cleanId)).lean();
            if (link && isUidCheckDisabled(link.uidChecking)) {
                return res.redirect('/v/' + encodeURIComponent(link.id || cleanId));
            } else if (link) {
                return res.redirect('/uid?link=' + encodeURIComponent(link.id || cleanId));
            }
        }
    }
    res.redirect('/admin/secret-gateway');
});

app.get('/admin/secret-gateway', (req, res) => sendAppFile(res, 'secret-gateway.html', 'admin/secret-gateway.html'));
app.get(['/admin/index.html', '/admin', '/admin/668379d1.html'], (req, res) => {
    const token = req.cookies?.adminToken;
    if (!token || !verifyToken(token)) return res.redirect('/admin/login.html');
    sendAppFile(res, 'admin/index.html', '668379d1.html', 'admin/668379d1.html', 'index.html');
});

// =========================================================================
// 🎯 SMART DYNAMIC UID & ENTRANCE POPUP ROUTE (USER CLICK HANDLER)
// =========================================================================
app.get(['/uid', '/uid.html', '/uid-checker.html', '/uid/:id'], async (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    let cleanId = '';
    try {
        let rawParam = (req.query.link || req.query.id || req.query.l || req.query.linkId || req.params.id || '').toString().trim();
        cleanId = extractCleanId(rawParam);

        let link = null;
        if (cleanId) {
            link = await Link.findOne(getLinkQuery(cleanId)).lean();
        }
        if (!link) {
            link = await Link.findOne({ status: 'active' }).sort({ created: -1 }).lean();
        }

        const globalPopup = await PopupSettings.findOne().lean().catch(() => null);
        const isGlobalOff = globalPopup && isUidCheckDisabled(globalPopup.uidChecking);
        const isLinkOff = link && isUidCheckDisabled(link.uidChecking);

        // 🔴 AGAR UID CHECKING BUTTON OFF HAI:
        // Screen par "Enter Player UID" wala page 0.1 second ke liye bhi NAHI aayega!
        // Seedha direct 16:9 entrance popup image aur video (/v/:id) par redirect ho jayega!
        if (isLinkOff || isGlobalOff) {
            const targetId = (link && link.id) ? link.id : (cleanId || 'default');
            return res.redirect('/v/' + encodeURIComponent(targetId));
        }
    } catch(err) {
        console.error('Error handling /uid route:', err);
    }

    // 🟢 AGAR UID CHECKING ON HAI:
    // Tabhi "Enter Player UID" wala page screen par aayega
    sendUidCheckerFile(res, cleanId);
});

app.get('/v/:id', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    const cleanId = extractCleanId(req.params.id);
    sendVideoLockFile(res, cleanId);
});

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
app.listen(port, '0.0.0.0', () => console.log(`🚀 Server running on port ${port}`));
