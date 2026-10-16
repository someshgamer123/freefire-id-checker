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

const { OAuth2Client } = require('google-auth-library');
const { doubleCsrf } = require('csrf-csrf');

console.log('✅ Built-in injection protection ENABLED');

let googleClient = null;
if (process.env.GOOGLE_CLIENT_ID) {
    googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
}

let connectDB;
try {
    connectDB = require('./config/db');
} catch(e) {
    connectDB = async () => {
        const uri = process.env.MONGODB_URI || process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/free_redeemcode';
        try {
            await mongoose.connect(uri, { serverSelectionTimeoutMS: 5000 });
            console.log('✅ MongoDB connected successfully');
        } catch(err) {
            console.error('❌ MongoDB connection error:', err.message);
        }
    };
}

mongoose.set('strictQuery', false);

function safeLoadModel(modelName, defaultSchema) {
    try {
        const mod = require(`./models/${modelName}`);
        if (mod) return mod;
    } catch(e) {}
    if (mongoose.models && mongoose.models[modelName]) {
        return mongoose.models[modelName];
    }
    return mongoose.model(modelName, new mongoose.Schema(defaultSchema || {}, { strict: false }));
}

const User = safeLoadModel('User', { passcode: String, lastEnvPasscode: String, theme: { type: String, default: 'dark' }, email: String, phone: String, secretKey: String });

const Link = safeLoadModel('Link', {
    id: String, name: String, title: String, linkName: String,
    userName: String, assignedUser: String, creator: String,
    video: String, claim: String, buttonText: String, headline: String,
    status: { type: String, default: 'active' },
    expiryDate: Date,
    uidChecking: { type: Boolean, default: true },
    claims: { type: Number, default: 0 },
    visits: { type: Number, default: 0 },
    dailyClaims: { type: Object, default: {} },
    dailyVisits: { type: Object, default: {} },
    popupSettings: Object,
    image: String,
    popupImage: String,
    popupImageUrl: String,
    banner: String,
    dashboardId: String,
    created: { type: Date, default: Date.now }
});

const Stats = safeLoadModel('Stats', { totalVisitors: { type: Number, default: 0 }, totalClaims: { type: Number, default: 0 }, dailyVisitors: { type: Object, default: {} }, dailyClaims: { type: Object, default: {} } });
const PopupSettings = safeLoadModel('PopupSettings', { image: String, title: { type: String, default: '🎁 Claim Your Reward' }, buttonText: { type: String, default: 'Claim Now' }, subtitle: { type: String, default: 'Tap below to unlock your reward' }, uidChecking: { type: Boolean, default: true } });
const RenewalRequest = safeLoadModel('RenewalRequest', { id: String, linkId: String, linkName: String, plan: String, days: Number, amount: Number, transactionId: String, status: { type: String, default: 'pending' }, createdAt: { type: Date, default: Date.now }, approvedAt: Date });

// 🆕 RenewalUser — with freeTrialUsed flag
const RenewalUser = safeLoadModel('RenewalUser', {
    name: String, email: String, phone: String, googleId: String,
    authMethod: { type: String, default: 'email' },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    currentPlan: { type: String, default: 'free-trial' },
    planStartDate: Date,
    planExpiryDate: Date,
    lifetimeUnlimited: { type: Boolean, default: false },
    freeTrialUsed: { type: Boolean, default: false },   // 🆕 Track if user already used free trial
    freeTrialActivatedAt: Date,                          // 🆕 When free trial was activated
    linksCreatedThisCycle: { type: Number, default: 0 },
    visitorsThisCycle: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    approvedAt: Date
});

const Pricing = safeLoadModel('Pricing', {});
const Session = safeLoadModel('Session', { userId: { type: String, default: 'admin' }, deviceKey: String, fingerprint: String, ip: String, userAgent: String, deviceName: String, deviceType: String, isActive: { type: Boolean, default: true }, lastActivity: { type: Date, default: Date.now }, createdAt: { type: Date, default: Date.now }, expiresAt: { type: Date, default: () => new Date(Date.now() + 7 * 24 * 3600 * 1000) } });
const AdminLog = safeLoadModel('AdminLog', { action: String, details: Object, timestamp: { type: Date, default: Date.now } });
const LoginAttempt = safeLoadModel('LoginAttempt', { ip: String, attempts: Number, lastAttempt: Date });
const TwoFactorAuth = safeLoadModel('TwoFactorAuth', { userId: String, secret: String, backupCodes: Array, isEnabled: Boolean, verifiedAt: Date });
const BlockedDevice = safeLoadModel('BlockedDevice', { deviceKey: String, fingerprint: String, ip: String, deviceName: String, deviceType: String, attempts: { type: Number, default: 1 }, reason: String, isPermanent: { type: Boolean, default: false }, lastAttempt: { type: Date, default: Date.now } });
const OTPVerification = safeLoadModel('OTPVerification', { phone: String, otp: String, expiresAt: Date });
const ShortLink = safeLoadModel('ShortLink', { code: String, originalUrl: String, title: String, creator: String, visits: { type: Number, default: 0 }, appOpen: Boolean, appScheme: String, createdAt: { type: Date, default: Date.now } });
const ShortLinkClick = safeLoadModel('ShortLinkClick', { shortLinkId: String, ip: String, userAgent: String, deviceName: String, deviceType: String, referer: String, timestamp: { type: Date, default: Date.now } });

const VisitorActivitySchema = new mongoose.Schema({
    linkId: { type: String, required: true, index: true },
    visitorKey: { type: String, required: true, index: true },
    type: { type: String, enum: ['visit', 'claim'], required: true, index: true },
    source: { type: String, enum: ['video', 'popup', 'direct'], default: 'video' },
    uid: { type: String, default: null },
    lastSeen: { type: Date, default: Date.now, index: true }
}, { timestamps: true, strict: false });

VisitorActivitySchema.index({ linkId: 1, visitorKey: 1, type: 1, lastSeen: -1 });
const VisitorActivity = mongoose.models.VisitorActivity || mongoose.model('VisitorActivity', VisitorActivitySchema);

const DEFAULT_PASSCODE = process.env.ADMIN_PASSCODE ? process.env.ADMIN_PASSCODE.toString().trim() : '951753';

const DISPOSABLE_DOMAINS = [
    'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
    'yopmail.com', 'throwaway.email', 'sharklasers.com', 'guerrillamailblock.com',
    'temp-mail.org', 'fakeinbox.com', 'trashmail.com', 'getnada.com',
    'maildrop.cc', 'mohmal.com', 'tempr.email', 'dispostable.com',
    'emailondeck.com', 'mytemp.email', 'burnermail.io', 'mailsac.com'
];

const DEFAULT_PLANS = {
    'free-trial': { name: 'Free Trial', icon: '🎁', durationDays: 3, linkLimit: 1, visitorLimit: 150, price: 0, enabled: true, badge: 'FREE', features: ['1 Active Link', '150 Total Visitors', '3 Days Validity', 'Basic Analytics'] },
    'basic': { name: 'Basic', icon: '📦', durationDays: 14, linkLimit: 5, visitorLimit: 5000, price: 199, enabled: true, badge: '', features: ['5 Active Links', '5,000 Total Visitors', 'Detailed Analytics', '14 Days Validity'] },
    'creator': { name: 'Creator', icon: '⭐', durationDays: 14, linkLimit: 10, visitorLimit: 15000, price: 399, enabled: true, badge: '', features: ['10 Active Links', '15,000 Total Visitors', 'Detailed Analytics', '14 Days Validity'] },
    'pro': { name: 'Pro', icon: '🚀', durationDays: 30, linkLimit: 25, visitorLimit: 50000, price: 799, enabled: true, badge: 'POPULAR', features: ['25 Active Links', '50,000 Total Visitors', 'Advanced Analytics', 'Custom Link Names', '30 Days Validity'] },
    'business': { name: 'Business', icon: '💼', durationDays: 90, linkLimit: 100, visitorLimit: 200000, price: 1999, enabled: true, badge: 'SAVE 20%', features: ['100 Active Links', '2,00,000 Total Visitors', 'Priority Support', 'Custom Link Names', '90 Days Validity'] },
    'enterprise-vip': { name: 'Enterprise VIP', icon: '👑', durationDays: 365, linkLimit: 'unlimited', visitorLimit: 'unlimited', price: 4999, enabled: true, badge: 'BEST VALUE', features: ['Unlimited Links', 'Unlimited Visitors', 'VIP Support', 'Custom Everything', '1 Year Validity'] }
};

// ==================== Helper Functions ====================
function getISTDate(dateObj) {
    const d = dateObj || new Date();
    const istOffset = 5.5 * 60 * 60 * 1000;
    const istNow = new Date(d.getTime() + istOffset);
    return istNow.toISOString().split('T')[0];
}

function getISTDateMinus(days) {
    const now = new Date();
    const istOffset = 5.5 * 60 * 60 * 1000;
    const istNow = new Date(now.getTime() + istOffset);
    const past = new Date(istNow.getTime() - days * 24 * 60 * 60 * 1000);
    return past.toISOString().split('T')[0];
}

function getDailyValue(mapData, dateStr) {
    if (!mapData) return 0;
    if (typeof mapData.get === 'function') return parseInt(mapData.get(dateStr)) || 0;
    if (typeof mapData === 'object') return parseInt(mapData[dateStr]) || 0;
    return 0;
}

function sumDailyMapBetween(mapData, startStr, endStr) {
    if (!mapData) return 0;
    let total = 0;
    if (typeof mapData.forEach === 'function' && typeof mapData.get === 'function') {
        mapData.forEach((count, date) => {
            if (date >= startStr && date <= endStr) total += parseInt(count) || 0;
        });
        return total;
    }
    if (typeof mapData === 'object') {
        for (const date of Object.keys(mapData)) {
            if (date >= startStr && date <= endStr) total += parseInt(mapData[date]) || 0;
        }
    }
    return total;
}

function parseDateRange(filter, customStart, customEnd) {
    const today = getISTDate();
    let startStr = '1970-01-01';
    let endStr = '2099-12-31';
    const f = (filter || 'all').toString().trim().toLowerCase();

    if (f === 'all' || f === 'alltime' || f === 'lifetime') { startStr = '1970-01-01'; endStr = '2099-12-31'; }
    else if (f === 'today') { startStr = today; endStr = today; }
    else if (f === 'yesterday') { const y = getISTDateMinus(1); startStr = y; endStr = y; }
    else if (f === '7days' || f === '7d' || f === 'last7days') { startStr = getISTDateMinus(6); endStr = today; }
    else if (f === '30days' || f === '30d' || f === 'last30days') { startStr = getISTDateMinus(29); endStr = today; }
    else if (f === 'custom' && customStart && customEnd) {
        startStr = customStart.toString().trim().slice(0, 10);
        endStr = customEnd.toString().trim().slice(0, 10);
    }
    return { startStr, endStr };
}

function verifyPasscode(inputPass, storedPass) {
    if (!inputPass || !storedPass) return false;
    const cleanInput = inputPass.toString().trim();
    const cleanStored = storedPass.toString().trim();
    if (cleanStored.startsWith('$2a$') || cleanStored.startsWith('$2b$') || cleanStored.startsWith('$2y$')) {
        try { return bcrypt.compareSync(cleanInput, cleanStored); } catch(e) { return false; }
    }
    return cleanInput === cleanStored;
}

function isUidCheckDisabled(val) {
    return val === false || val === 'false' || val === 0 || val === '0' || val === 'off' || val === 'OFF' || val === 'disabled' || val === 'inactive' || val === 'no' || val === 'NO';
}

function extractCleanId(input) {
    if (!input) return '';
    let str = input.toString().trim();
    if (str.includes('?link=')) str = (str.split('?link=') || '').split('&')[0];
    else if (str.includes('&link=')) str = (str.split('&link=') || '').split('&')[0];
    else if (str.includes('?id=')) str = (str.split('?id=') || '').split('&')[0];
    else if (str.includes('&id=')) str = (str.split('&id=') || '').split('&')[0];
    else if (str.includes('/user-dashboard/')) str = (str.split('/user-dashboard/') || '').split('?')[0];
    else if (str.includes('/v/')) str = (str.split('/v/') || '').split('?')[0];
    else if (str.includes('/uid/')) str = (str.split('/uid/') || '').split('?')[0];
    try { str = decodeURIComponent(str); } catch(e) {}
    return str.split('#')[0].replace(/\/+$/, '').trim();
}

function getLinkQuery(rawId) {
    const cleanId = (rawId || '').toString().trim();
    const orConditions = [{ id: cleanId }, { dashboardId: cleanId }];
    if (mongoose.Types.ObjectId.isValid(cleanId) && cleanId.length === 24) {
        try { orConditions.push({ _id: new mongoose.Types.ObjectId(cleanId) }); } catch(e) {}
        orConditions.push({ _id: cleanId });
    }
    return { $or: orConditions };
}

// 🆕 Link expired check
function isLinkExpired(link) {
    if (!link) return true;
    if (link.status === 'suspended' || link.status === 'disabled' || link.status === 'inactive') return true;
    if (link.expiryDate && !isNaN(new Date(link.expiryDate).getTime())) {
        const expTime = new Date(link.expiryDate).getTime();
        if (expTime > 1000000000000 && Date.now() > expTime) return true;
    }
    return false;
}

function generateWhatsAppApprovalData(user, req) {
    let cleanPhone = (user.phone || '').replace(/[^0-9]/g, '');
    if (cleanPhone.length === 10) cleanPhone = '91' + cleanPhone;
    else if (cleanPhone.startsWith('0')) cleanPhone = '91' + cleanPhone.replace(/^0+/, '');
    const protocol = (req && req.headers && req.headers['x-forwarded-proto']) || (req && req.protocol) || 'http';
    const host = (req && req.get && req.get('host')) || 'localhost:3001';
    const loginUrl = `${protocol}://${host}/user-dashboard`;
    const message = 
`🎉 *Congratulations ${user.name}!*
Your account has been approved.

🔐 *Login:*
📧 Email: ${user.email}
📱 Phone: ${user.phone}

🔗 ${loginUrl}

Thank you! 🚀`;
    const whatsappUrl = `https://wa.me/${cleanPhone}?text=${encodeURIComponent(message)}`;
    return { message, whatsappUrl, cleanPhone, loginUrl };
}

function isValidEmailFormat(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function isDisposableEmail(email) { const domain = (email || '').split('@')[1]?.toLowerCase(); return DISPOSABLE_DOMAINS.includes(domain); }
function isValidMobile(mobile, countryCode = 'IN') {
    const clean = (mobile || '').replace(/[\s\-\(\)\+]/g, '');
    if (countryCode === 'IN') return /^[6-9]\d{9}$/.test(clean);
    return clean.length >= 10 && clean.length <= 15;
}

async function verifyTurnstile(token, remoteIp) {
    if (!token) return { success: false, error: 'No captcha token' };
    if (!process.env.TURNSTILE_SECRET_KEY) return { success: true, skipped: true };
    try {
        const verifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
        const verifyRes = await fetch(verifyUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret: process.env.TURNSTILE_SECRET_KEY, response: token, remoteip: remoteIp })
        });
        const data = await verifyRes.json();
        return { success: data.success === true, data };
    } catch(e) {
        console.error('Turnstile verify error:', e.message);
        return { success: false, error: 'Verification failed' };
    }
}

// ==================== PLAN HELPERS ====================
async function getPricingDoc() {
    let pricingDoc = await Pricing.findOne();
    if (!pricingDoc) {
        pricingDoc = await Pricing.create({
            plans: DEFAULT_PLANS,
            paymentSettings: { method: 'UPI', showUpi: true, details: { upiId: 'admin@upi' } },
            whatsappNumber: '916372923348',
            autoPaymentEnabled: false
        });
    }
    const currentPlans = pricingDoc.plans || {};
    let needsSave = false;
    for (const key of Object.keys(DEFAULT_PLANS)) {
        if (!currentPlans[key]) {
            currentPlans[key] = DEFAULT_PLANS[key];
            needsSave = true;
        }
    }
    if (needsSave) {
        pricingDoc.plans = currentPlans;
        pricingDoc.markModified('plans');
        await pricingDoc.save();
    }
    return pricingDoc;
}

function getPlanDetails(pricingDoc, planKey) {
    const plans = pricingDoc?.plans || DEFAULT_PLANS;
    return plans[planKey] || DEFAULT_PLANS['free-trial'];
}

function isUnlimited(val) { return val === 'unlimited' || val === -1 || val === 'null' || val === null || val === 'Unlimited'; }

function isPlanExpired(user) {
    if (!user) return false;
    if (user.lifetimeUnlimited === true) return false;
    if (!user.planExpiryDate) return false;
    try {
        return new Date(user.planExpiryDate) < new Date();
    } catch(e) { return false; }
}

// 🆕 Check if user has an active plan (not expired, and not just "no-plan" state)
function userHasActivePlan(user) {
    if (!user) return false;
    if (user.lifetimeUnlimited === true) return true;
    if (!user.planExpiryDate) return false;
    try {
        return new Date(user.planExpiryDate) >= new Date();
    } catch(e) { return false; }
}

async function canUserCreateLink(user) {
    try {
        if (user.lifetimeUnlimited === true) {
            return { allowed: true, currentCount: 0, limit: 'unlimited', lifetimeUnlimited: true };
        }
        if (isPlanExpired(user)) {
            return { allowed: false, currentCount: 0, limit: 0, reason: 'PLAN_EXPIRED' };
        }
        const pricingDoc = await getPricingDoc();
        const planKey = user.currentPlan || 'free-trial';
        const plan = getPlanDetails(pricingDoc, planKey);
        const linkLimit = plan.linkLimit;
        if (isUnlimited(linkLimit)) return { allowed: true, limit: 'unlimited' };

        const userRegex = new RegExp('^' + (user.name || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
        const currentCount = await Link.countDocuments({
            $or: [{ assignedUser: userRegex }, { userName: userRegex }, { creator: userRegex }, { name: userRegex }]
        });
        if (currentCount >= linkLimit) {
            return { allowed: false, currentCount, limit: linkLimit, reason: 'LINK_LIMIT_REACHED' };
        }
        return { allowed: true, currentCount, limit: linkLimit };
    } catch(e) { return { allowed: true }; }
}

async function canUserGetVisitor(user) {
    try {
        if (user.lifetimeUnlimited === true) {
            return { allowed: true, totalVisitors: 0, limit: 'unlimited', lifetimeUnlimited: true };
        }
        if (isPlanExpired(user)) {
            return { allowed: false, totalVisitors: 0, limit: 0, reason: 'PLAN_EXPIRED' };
        }
        const pricingDoc = await getPricingDoc();
        const planKey = user.currentPlan || 'free-trial';
        const plan = getPlanDetails(pricingDoc, planKey);
        const visitorLimit = plan.visitorLimit;
        if (isUnlimited(visitorLimit)) return { allowed: true, limit: 'unlimited' };

        const userRegex = new RegExp('^' + (user.name || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
        const userLinks = await Link.find({
            $or: [{ assignedUser: userRegex }, { userName: userRegex }, { creator: userRegex }, { name: userRegex }]
        }).lean();
        const totalVisitors = userLinks.reduce((sum, l) => sum + (parseInt(l.visits) || 0), 0);
        if (totalVisitors >= visitorLimit) {
            return { allowed: false, totalVisitors, limit: visitorLimit, reason: 'VISITOR_LIMIT_REACHED' };
        }
        return { allowed: true, totalVisitors, limit: visitorLimit };
    } catch(e) { return { allowed: true }; }
}

// ==================== Database Init ====================
async function initializeDatabase() {
    try {
        const activeEnvPass = process.env.ADMIN_PASSCODE ? process.env.ADMIN_PASSCODE.toString().trim() : DEFAULT_PASSCODE;
        let admin = await User.findOne();
        if (!admin) {
            const hashedPasscode = bcrypt.hashSync(activeEnvPass, 10);
            await User.create({
                passcode: hashedPasscode, lastEnvPasscode: activeEnvPass, theme: 'dark',
                email: process.env.ADMIN_EMAIL || '', phone: process.env.ADMIN_PHONE || '', secretKey: 'admin@2024'
            });
        } else if (process.env.ADMIN_PASSCODE && admin.lastEnvPasscode !== activeEnvPass) {
            admin.passcode = bcrypt.hashSync(activeEnvPass, 10);
            admin.lastEnvPasscode = activeEnvPass;
            await admin.save();
        }
        const statsExists = await Stats.findOne();
        if (!statsExists) await Stats.create({});
        const popupExists = await PopupSettings.findOne();
        if (!popupExists) {
            await PopupSettings.create({
                image: null, title: '🎁 Claim Your Reward', buttonText: 'Claim Now',
                subtitle: 'Tap below to unlock your reward', uidChecking: true
            });
        }
        await getPricingDoc();
        if (Session) {
            await Session.deleteMany({ expiresAt: { $lt: new Date() } }).catch(() => {});
        }
    } catch (error) {
        console.error('❌ Database initialization error:', error);
    }
}

connectDB().then((conn) => {
    if (conn) initializeDatabase();
}).catch(() => {});

// ==================== MIDDLEWARE ====================
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, frameguard: false, referrerPolicy: { policy: 'strict-origin-when-cross-origin' } }));
app.use(cors({ origin: true, credentials: true, methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Admin-Token', 'token'] }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

function injectionProtection(req, res, next) {
    try {
        const sanitizeObject = (obj, depth = 0) => {
            if (depth > 10) return obj;
            if (!obj || typeof obj !== 'object') return obj;
            for (const key of Object.keys(obj)) {
                if (key.startsWith('$') || key.includes('..') || key === '__proto__' || key === 'constructor' || key === 'prototype') {
                    delete obj[key];
                    continue;
                }
                if (obj[key] && typeof obj[key] === 'object' && !Array.isArray(obj[key])) sanitizeObject(obj[key], depth + 1);
                if (Array.isArray(obj[key])) obj[key] = obj[key].map(item => { if (item && typeof item === 'object') sanitizeObject(item, depth + 1); return item; });
            }
            return obj;
        };
        if (req.body && typeof req.body === 'object') sanitizeObject(req.body);
        if (req.query && typeof req.query === 'object') sanitizeObject(req.query);
        if (req.params && typeof req.params === 'object') sanitizeObject(req.params);
    } catch(e) {}
    next();
}
app.use(injectionProtection);

app.use((req, res, next) => {
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    const blocked = ['.env', '.log', '.json', '.md'];
    const p = req.path.toLowerCase();
    if (p === '/manifest.json') return next();
    for (let ext of blocked) { if (p.endsWith(ext)) return res.status(403).send('Forbidden'); }
    next();
});

const csrfSecret = process.env.CSRF_SECRET || 'change-this-csrf-secret-32-chars-minimum-xyz-123';
const { generateToken: generateCsrfToken } = doubleCsrf({
    getSecret: () => csrfSecret,
    cookieName: 'csrf-token',
    cookieOptions: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/' },
    size: 64,
    ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
    getTokenFromRequest: (req) => req.headers['x-csrf-token'] || req.body?._csrf
});

app.get('/api/csrf-token', (req, res) => {
    try {
        const token = generateCsrfToken(req, res);
        res.json({ csrfToken: token });
    } catch(e) { res.status(500).json({ error: 'Failed to generate token' }); }
});

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX) || 500,
    standardHeaders: true, legacyHeaders: false,
    skip: (req) => (req.path === '/health' || req.path === '/ping' || req.path.endsWith('.css') || req.path.endsWith('.js') || req.path.endsWith('.png') || req.path.endsWith('.jpg') || req.path.endsWith('.ico')),
    message: { error: 'Too many requests' }
});
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, skipSuccessfulRequests: true });
const claimLimiter = rateLimit({ windowMs: 60 * 1000, max: 30 });

app.use('/api', globalLimiter);

app.get('/health', (req, res) => {
    const dbState = mongoose.connection.readyState;
    const dbStatus = dbState === 1 ? 'connected' : dbState === 2 ? 'connecting' : dbState === 3 ? 'disconnecting' : 'disconnected';
    res.status(dbState === 1 ? 200 : 503).json({
        status: dbState === 1 ? 'healthy' : 'unhealthy',
        database: dbStatus,
        uptime: Math.floor(process.uptime()),
        environment: process.env.NODE_ENV || 'development',
        timestamp: new Date().toISOString()
    });
});

app.get('/ping', (req, res) => res.status(200).send('pong'));

const JWT_SECRET = process.env.JWT_SECRET || 'somu_admin_secret_fixed_key_951753';
const JWT_EXPIRY = '7d';

function generateToken(userId) { return jwt.sign({ id: userId, role: 'admin', timestamp: Date.now() }, JWT_SECRET, { expiresIn: JWT_EXPIRY }); }
function verifyToken(token) { try { return jwt.verify(token, JWT_SECRET); } catch (e) { return null; } }

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
    let deviceName = 'Browser', deviceType = 'Desktop';
    if (userAgent.includes('Android')) { deviceName = 'Android Mobile'; deviceType = 'Mobile'; }
    else if (userAgent.includes('iPhone')) { deviceName = 'Apple iPhone'; deviceType = 'Mobile'; }
    else if (userAgent.includes('iPad')) { deviceName = 'Apple iPad'; deviceType = 'Tablet'; }
    else if (userAgent.includes('Windows')) { deviceName = 'Windows PC'; deviceType = 'Desktop'; }
    else if (userAgent.includes('Mac')) { deviceName = 'Mac Computer'; deviceType = 'Desktop'; }
    else if (userAgent.includes('Linux')) { deviceName = 'Linux PC'; deviceType = 'Desktop'; }
    return { deviceName, deviceType };
}

async function isDeviceBlocked(req) {
    try {
        if (mongoose.connection.readyState !== 1) return null;
        const { deviceKey, fingerprint, ip } = getDeviceId(req);
        if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1' || ip.includes('localhost') || ip.startsWith('192.168.')) return null;
        return await BlockedDevice.findOne({ $or: [{ deviceKey }, { ip }, { fingerprint }], isPermanent: true }).maxTimeMS(1500);
    } catch(e) { return null; }
}

async function authMiddleware(req, res, next) {
    const token = req.cookies?.adminToken || req.headers['authorization']?.replace('Bearer ', '') || req.headers['x-admin-token'] || req.headers['x-token'] || req.headers['token'] || req.query.token;
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid or expired token' });
    req.user = decoded;
    if (Session) {
        const { deviceKey, fingerprint, ip } = getDeviceId(req);
        const { deviceName, deviceType } = getDeviceDetails(req);
        Session.findOneAndUpdate(
            { $or: [{ deviceKey }, { fingerprint }, { ip }] },
            { $set: { lastActivity: new Date(), isActive: true, ip, deviceName, deviceType }, $setOnInsert: { userId: 'admin', deviceKey, fingerprint, createdAt: new Date(), expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000) } },
            { upsert: true }
        ).catch(() => {});
    }
    next();
}

// ==================== ROUTES ====================
app.get(['/admin/unblock-all', '/api/admin/unblock-all'], async (req, res) => {
    res.status(403).send(`<!DOCTYPE html><html><head><title>Forbidden</title><style>body{background:#090a10;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center;padding:20px;margin:0;}.card{background:#131722;padding:40px;border-radius:20px;border:1px solid rgba(239,68,68,0.4);max-width:450px;}h1{color:#ef4444;font-size:22px;margin-bottom:10px;}p{color:#94a3b8;font-size:14px;line-height:1.6;}</style></head><body><div class="card"><h1>⛔ ACCESS DENIED</h1><p>Only an authorized administrator can unblock devices.</p></div></body></html>`);
});

app.get('/api/pricing', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        const pricingDoc = await getPricingDoc();
        const publicPlans = {};
        for (const [key, plan] of Object.entries(pricingDoc.plans || {})) {
            if (plan && plan.enabled !== false) publicPlans[key] = plan;
        }
        res.json({
            plans: publicPlans,
            paymentSettings: {
                method: pricingDoc.paymentSettings?.method || 'UPI',
                showUpi: pricingDoc.paymentSettings?.showUpi !== false,
                details: pricingDoc.paymentSettings?.details || { upiId: 'admin@upi' }
            },
            whatsappNumber: pricingDoc.whatsappNumber || '916372923348',
            autoPaymentEnabled: false
        });
    } catch (error) { res.status(500).json({ error: 'Failed' }); }
});

// ==================== VISITOR LINK RESOLVER ====================
app.get('/api/link/:id', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.setHeader('Surrogate-Control', 'no-store');
        
        let rawId = extractCleanId(req.params.id);
        
        let link = await Link.collection.findOne(getLinkQuery(rawId));

        if (!link && (rawId === 'default' || !rawId)) {
            const allActive = await Link.find({ status: 'active' }).sort({ created: -1 }).limit(1).lean();
            link = allActive[0];
        }
        if (!link) return res.status(404).json({ error: 'not_found', message: 'Link not found', expired: true });

        if (link.status === 'suspended' || link.status === 'disabled' || link.status === 'inactive') {
            return res.status(403).json({ error: link.status, message: `This link has been ${link.status}`, status: link.status, expired: true });
        }
        if (link.expiryDate && !isNaN(new Date(link.expiryDate).getTime())) {
            const expTime = new Date(link.expiryDate).getTime();
            if (expTime > 1000000000000 && Date.now() > expTime) {
                return res.status(403).json({ error: 'expired', message: 'This link has expired', status: 'expired', expired: true });
            }
        }

        // Owner plan check
        const ownerName = link.assignedUser || link.userName || link.name || link.creator;
        if (ownerName) {
            try {
                const ownerUser = await RenewalUser.findOne({ 
                    name: new RegExp('^' + ownerName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i')
                }).lean();
                
                if (ownerUser) {
                    if (isPlanExpired(ownerUser)) {
                        return res.status(403).json({ error: 'plan_expired', message: 'Your plan has expired. Please renew.', status: 'expired', expired: true });
                    }
                    if (ownerUser.lifetimeUnlimited !== true) {
                        const visitorCheck = await canUserGetVisitor(ownerUser);
                        if (!visitorCheck.allowed) {
                            return res.status(403).json({ error: 'visitor_limit_reached', message: 'This link has reached its visitor limit.', status: 'expired', expired: true });
                        }
                    }
                }
            } catch(e) { console.error('Plan/Visitor check error:', e.message); }
        }

        const { ip, deviceKey } = getDeviceId(req);
        const visitorKey = deviceKey || ip;
        const today = getISTDate();

        await Link.collection.updateOne({ _id: link._id },
            { $inc: { visits: 1, [`dailyVisits.${today}`]: 1 } }
        ).catch(err => console.error('Link visit update error:', err));
        await Stats.collection.updateOne({},
            { $inc: { totalVisitors: 1, [`dailyVisitors.${today}`]: 1 } },
            { upsert: true }
        ).catch(err => console.error('Stats visit update error:', err));

        await VisitorActivity.findOneAndUpdate(
            { linkId: link.id, visitorKey: visitorKey, type: 'visit' },
            { $set: { lastSeen: new Date() } }, 
            { upsert: true }
        ).catch(() => {});

        const popup = link.popupSettings || {};
        const bannerImage = popup.image || link.image || link.popupImage || link.popupImageUrl || link.banner || null;
        const videoUrl = link.video || link.videoUrl || link.videoURL || link.youtubeUrl || 'https://youtu.be/dQw4w9WgXcQ';
        const claimUrl = link.claim || link.claimUrl || link.claimLink || link.claimURL || link.url || '#';
        const buttonTxt = link.buttonText || link.btnText || link.button || 'Claim Now';
        const headlineTxt = link.headline || link.heading || link.title_text || '🎬 Watch Video & Unlock Reward';
        
        const globalPopup = await PopupSettings.findOne().lean().catch(() => null);
        const isGlobalOff = globalPopup && isUidCheckDisabled(globalPopup.uidChecking);
        const isUidOn = (!isUidCheckDisabled(link.uidChecking)) && (!isGlobalOff);
        const lName = link.linkName || link.title || link.name || 'Untitled Link';

        res.json({
            id: link.id, linkId: link.id, name: lName, title: lName, linkName: lName,
            userName: link.userName || link.name || '',
            video: videoUrl, claim: claimUrl, buttonText: buttonTxt, headline: headlineTxt,
            status: link.status || 'active', expiryDate: link.expiryDate || null, expired: false,
            uidChecking: isUidOn,
            image: bannerImage, popupImage: bannerImage, popupImageUrl: bannerImage, banner: bannerImage,
            popupSettings: {
                image: bannerImage,
                title: popup.title || link.popupTitle || '🎁 Claim Your Reward',
                buttonText: popup.buttonText || link.popupButtonText || buttonTxt,
                subtitle: popup.subtitle || link.popupSubtitle || 'Tap below to unlock your reward'
            }
        });
    } catch (error) { 
        console.error('Link API error:', error);
        res.status(500).json({ error: 'Server error' }); 
    }
});

app.post('/api/submit-uid/:linkId', async (req, res) => {
    try {
        const { uid } = req.body;
        const cleanUid = (uid || '').toString().trim();
        if (!cleanUid || cleanUid.length < 5) return res.status(400).json({ error: 'Please enter a valid UID.' });
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
    } catch (error) { res.status(500).json({ error: 'Failed' }); }
});

// ==================== CLAIM TRACKING ====================
async function executeClaimTracking(rawLinkId, req) {
    const cleanId = extractCleanId(rawLinkId);
    if (!cleanId) return { success: false, error: 'Link ID missing' };

    const sourceParam = (req.query.source || req.body?.source || '').toString().toLowerCase().trim();
    
    if (sourceParam !== 'video') {
        return { success: true, ignored: true, reason: 'Only main video claim button counts' };
    }

    const link = await Link.findOne(getLinkQuery(cleanId));
    if (!link) return { success: false, error: 'Link not found' };

    const { ip, deviceKey } = getDeviceId(req);
    const visitorKey = deviceKey || ip;
    const today = getISTDate();

    await Link.collection.updateOne({ _id: link._id },
        { $inc: { claims: 1, [`dailyClaims.${today}`]: 1 } }
    ).catch(err => console.error('Link claim update error:', err));
    await Stats.collection.updateOne({},
        { $inc: { totalClaims: 1, [`dailyClaims.${today}`]: 1 } },
        { upsert: true }
    ).catch(err => console.error('Stats claim update error:', err));

    await VisitorActivity.findOneAndUpdate(
        { linkId: link.id, visitorKey: visitorKey, type: 'claim' },
        { $set: { lastSeen: new Date(), source: 'video' } },
        { upsert: true }
    ).catch(() => {});

    return { success: true, linkId: link.id, counted: true };
}

const handleClaimTrackingRequest = async (req, res) => {
    try {
        let rawId = req.params.linkId || req.params.id || req.query.linkId || req.query.link || req.query.id || req.body?.linkId || req.body?.id || req.body?.link;
        const result = await executeClaimTracking(rawId, req);
        if (result.success) return res.json({ success: true, linkId: result.linkId, ignored: !!result.ignored, counted: result.counted !== false });
        else return res.status(404).json({ error: result.error || 'Failed' });
    } catch(err) { return res.status(500).json({ error: 'Failed' }); }
};

app.post('/api/track-claim/:linkId', claimLimiter, handleClaimTrackingRequest);
app.get('/api/track-claim/:linkId', claimLimiter, handleClaimTrackingRequest);
app.post('/api/track-claim', claimLimiter, handleClaimTrackingRequest);
app.all('/api/claim/:linkId', claimLimiter, handleClaimTrackingRequest);
app.all('/api/claim', claimLimiter, handleClaimTrackingRequest);
app.all('/api/track/:linkId', claimLimiter, handleClaimTrackingRequest);
app.all('/api/links/:linkId/claim', claimLimiter, handleClaimTrackingRequest);
app.all('/api/claim-reward/:linkId', claimLimiter, handleClaimTrackingRequest);

// ==================== RENEWAL ====================
app.get('/api/renewal/history/:linkId', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        const { linkId } = req.params;
        const history = await RenewalRequest.find({ linkId }).sort({ createdAt: -1 }).limit(7).lean();
        res.json({ history, count: history.length });
    } catch (error) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/settings', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        const admin = await User.findOne().lean();
        const popupSettings = await PopupSettings.findOne().lean();
        res.json({
            theme: admin?.theme || 'dark',
            background: popupSettings?.image || null,
            popupSettings: popupSettings || { image: null, title: '🎁 Claim Your Reward', buttonText: 'Claim Now', subtitle: 'Tap below to unlock your reward' },
            adminEmail: admin?.email || '',
            adminPhone: admin?.phone || ''
        });
    } catch (error) { res.status(500).json({ error: 'Failed' }); }
});

// ==================== USER AUTH ====================
app.post('/api/user/signup', authLimiter, async (req, res) => {
    try {
        const { name, email, phone, turnstileToken } = req.body;
        if (!name || !email || !phone) return res.status(400).json({ error: 'All fields are required' });
        const cleanName = name.trim();
        const cleanEmail = email.trim().toLowerCase();
        const cleanPhone = phone.trim();
        const { ip } = getDeviceId(req);
        const turnstileResult = await verifyTurnstile(turnstileToken, ip);
        if (!turnstileResult.success && !turnstileResult.skipped) return res.status(400).json({ error: 'Bot detected.' });
        if (!isValidEmailFormat(cleanEmail)) return res.status(400).json({ error: 'Invalid email format' });
        if (isDisposableEmail(cleanEmail)) return res.status(400).json({ error: 'Disposable emails not allowed.' });
        if (!isValidMobile(cleanPhone)) return res.status(400).json({ error: 'Please enter a valid 10-digit Indian mobile number' });

        const emailExists = await RenewalUser.findOne({ email: cleanEmail });
        if (emailExists) return res.status(400).json({ error: 'Email already registered.' });
        const phoneExists = await RenewalUser.findOne({ phone: cleanPhone });
        if (phoneExists) return res.status(400).json({ error: 'Phone already registered.' });

        // 🆕 Create user with NO plan — planExpiryDate null so they can't access until they activate
        await RenewalUser.create({ 
            name: cleanName, 
            email: cleanEmail, 
            phone: cleanPhone, 
            authMethod: 'email', 
            status: 'pending', 
            currentPlan: 'none',    // 🆕 No plan yet
            planExpiryDate: null,    // 🆕 No expiry
            freeTrialUsed: false,
            createdAt: new Date() 
        });
        res.json({ success: true, message: 'Signup submitted!' });
    } catch (e) { res.status(500).json({ error: 'Registration failed' }); }
});

app.post('/api/user/signin', authLimiter, async (req, res) => {
    try {
        const { email, phone, turnstileToken } = req.body;
        if (!email || !phone) return res.status(400).json({ error: 'Enter email and phone' });
        const { ip } = getDeviceId(req);
        const turnstileResult = await verifyTurnstile(turnstileToken, ip);
        if (!turnstileResult.success && !turnstileResult.skipped) return res.status(400).json({ error: 'Bot detected.' });
        const user = await RenewalUser.findOne({ email: email.trim().toLowerCase(), phone: phone.trim() });
        if (!user) return res.status(404).json({ error: 'User not found.' });
        if (user.status === 'pending') return res.status(403).json({ error: 'Pending approval.' });
        if (user.status === 'rejected') return res.status(403).json({ error: 'Registration rejected.' });
        res.json({ success: true, user: { id: user._id, name: user.name, email: user.email, phone: user.phone } });
    } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

app.post('/api/user/google-login', authLimiter, async (req, res) => {
    try {
        const { credential } = req.body;
        if (!credential) return res.status(400).json({ error: 'Google credential missing' });
        if (!googleClient || !process.env.GOOGLE_CLIENT_ID) return res.status(500).json({ error: 'Google login not configured' });
        const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
        const payload = ticket.getPayload();
        if (!payload || !payload.email) return res.status(400).json({ error: 'Invalid Google token' });
        if (!payload.email_verified) return res.status(400).json({ error: 'Google email is not verified' });
        const cleanEmail = payload.email.toLowerCase();
        let user = await RenewalUser.findOne({ email: cleanEmail });
        if (!user) {
            if (isDisposableEmail(cleanEmail)) return res.status(400).json({ error: 'Disposable emails not allowed' });
            // 🆕 Create with NO plan
            user = await RenewalUser.create({
                name: payload.name || 'Google User', 
                email: cleanEmail, 
                phone: '',
                googleId: payload.sub, 
                authMethod: 'google', 
                status: 'approved',
                currentPlan: 'none',      // 🆕 No plan
                planExpiryDate: null,      // 🆕 No expiry
                freeTrialUsed: false,
                createdAt: new Date(), 
                approvedAt: new Date()
            });
        }
        if (user.status === 'rejected') return res.status(403).json({ error: 'Your account has been rejected.' });
        res.json({ success: true, user: { id: user._id, name: user.name, email: user.email, phone: user.phone || '', authMethod: user.authMethod } });
    } catch (e) { res.status(401).json({ error: 'Google authentication failed' }); }
});

// 🆕 FREE PLAN ACTIVATION — user must click "Activate", and only ONCE
app.post('/api/user/select-free-plan', async (req, res) => {
    try {
        const { userName } = req.body;
        if (!userName) return res.status(400).json({ error: 'User name required' });
        const user = await RenewalUser.findOne({ name: new RegExp('^' + userName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i') });
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        // 🆕 Check if free trial already used
        if (user.freeTrialUsed === true) {
            return res.status(403).json({ error: 'Free trial already used. Please purchase a paid plan.' });
        }
        
        const pricingDoc = await getPricingDoc();
        const ftPlan = getPlanDetails(pricingDoc, 'free-trial');
        
        user.currentPlan = 'free-trial';
        user.planStartDate = new Date();
        const expiry = new Date();
        expiry.setDate(expiry.getDate() + (ftPlan.durationDays || 3));
        user.planExpiryDate = expiry;
        user.lifetimeUnlimited = false;
        user.freeTrialUsed = true;                 // 🆕 Mark as used
        user.freeTrialActivatedAt = new Date();    // 🆕 Track activation time
        if (user.status === 'pending') { user.status = 'approved'; user.approvedAt = new Date(); }
        
        user.markModified('freeTrialUsed');
        user.markModified('freeTrialActivatedAt');
        user.markModified('currentPlan');
        user.markModified('planExpiryDate');
        await user.save();
        
        res.json({ success: true, message: 'Free plan activated!', user: { id: user._id, name: user.name, currentPlan: user.currentPlan, planExpiryDate: user.planExpiryDate } });
    } catch (e) { res.status(500).json({ error: 'Failed to activate free plan' }); }
});

// ==================== USER LINK DETAILS ====================
app.post('/api/user/link-details', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        const { userName, linkInput, linkId, id, dashboardId, filter, startDate, endDate } = req.body;
        const cleanUser = (userName || '').trim();
        const userRegex = new RegExp('^' + cleanUser.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');

        let rawInput = linkInput || linkId || id || dashboardId || '';
        let searchId = extractCleanId(rawInput);

        // 🆕 STRICT: Only fetch links where the user is the OWNER
        const allUserLinks = await Link.find({
            $or: [
                { assignedUser: userRegex },
                { userName: userRegex },
                { creator: userRegex }
            ]
        }).sort({ created: -1 }).lean();

        const formattedUserLinks = allUserLinks.map(l => {
            const lTitle = l.linkName || l.title || l.name || 'Untitled Campaign';
            return { id: l.id, name: lTitle, title: lTitle, linkName: lTitle, status: l.status || 'active', expiryDate: l.expiryDate || null, visits: l.visits || 0, claims: l.claims || 0 };
        });

        // 🆕 STRICT: Only allow selecting one of the user's own links
        let link = null;
        if (searchId && searchId !== cleanUser) {
            // Find the link, then verify it belongs to this user
            const candidateLink = await Link.findOne(getLinkQuery(searchId)).lean();
            if (candidateLink) {
                const candidateOwner = (candidateLink.assignedUser || candidateLink.userName || candidateLink.creator || '').toLowerCase().trim();
                const requestedOwner = cleanUser.toLowerCase().trim();
                if (candidateOwner === requestedOwner) {
                    link = candidateLink;
                }
            }
        }
        if (!link && allUserLinks.length > 0) link = allUserLinks[0];
        // 🚫 NO fallback to any random active link — if user has no links, return empty

        // Get owner user record
        const ownerUser = await RenewalUser.findOne({ name: userRegex }).lean();
        const pricingDoc = await getPricingDoc();
        
        // 🆕 Determine plan state — "no-plan" if user has no expiry or plan = none
        const hasPlan = ownerUser ? userHasActivePlan(ownerUser) : false;
        const planIsExpired = ownerUser ? isPlanExpired(ownerUser) : false;
        const isLifetimeUnlimited = ownerUser?.lifetimeUnlimited === true;
        const freeTrialUsed = ownerUser?.freeTrialUsed === true;
        const userCurrentPlan = ownerUser?.currentPlan || 'none';
        
        // 🆕 Plan key for display: 'no-plan' if user has no plan
        let effectivePlanKey = userCurrentPlan;
        if (isLifetimeUnlimited) effectivePlanKey = 'lifetime-unlimited';
        else if (!hasPlan && !planIsExpired) effectivePlanKey = 'no-plan';  // Never had a plan
        else if (planIsExpired) effectivePlanKey = 'no-plan';                // Plan expired
        
        const plan = getPlanDetails(pricingDoc, hasPlan ? userCurrentPlan : 'free-trial');
        const totalUserVisits = allUserLinks.reduce((sum, l) => sum + (parseInt(l.visits) || 0), 0);

        let planDaysLeft = null;
        if (isLifetimeUnlimited) planDaysLeft = 'lifetime';
        else if (ownerUser?.planExpiryDate) {
            const diff = new Date(ownerUser.planExpiryDate) - new Date();
            planDaysLeft = Math.ceil(diff / (1000 * 60 * 60 * 24));
        }

        // 🆕 Plan Usage object
        const planUsage = hasPlan ? {
            planKey: isLifetimeUnlimited ? 'lifetime-unlimited' : userCurrentPlan,
            planName: isLifetimeUnlimited ? 'Lifetime Unlimited' : plan.name,
            durationDays: isLifetimeUnlimited ? '∞' : (plan.durationDays || 0),
            price: isLifetimeUnlimited ? 0 : plan.price,
            badge: isLifetimeUnlimited ? 'VIP' : (plan.badge || ''),
            features: isLifetimeUnlimited ? ['Unlimited Links', 'Unlimited Visitors', 'VIP Support', 'No Expiry', 'All Features'] : (plan.features || []),
            linkLimit: isLifetimeUnlimited ? 'unlimited' : plan.linkLimit,
            visitorLimit: isLifetimeUnlimited ? 'unlimited' : plan.visitorLimit,
            linksUsed: allUserLinks.length,
            visitorsUsed: totalUserVisits,
            linksRemaining: (isLifetimeUnlimited || isUnlimited(plan.linkLimit)) ? 'unlimited' : Math.max(0, plan.linkLimit - allUserLinks.length),
            visitorsRemaining: (isLifetimeUnlimited || isUnlimited(plan.visitorLimit)) ? 'unlimited' : Math.max(0, plan.visitorLimit - totalUserVisits),
            linkLimitReached: isLifetimeUnlimited ? false : (!isUnlimited(plan.linkLimit) && allUserLinks.length >= plan.linkLimit),
            visitorLimitReached: isLifetimeUnlimited ? false : (!isUnlimited(plan.visitorLimit) && totalUserVisits >= plan.visitorLimit),
            lifetimeUnlimited: isLifetimeUnlimited,
            planExpiryDate: ownerUser?.planExpiryDate || null,
            planIsExpired: false,
            planDaysLeft: planDaysLeft
        } : {
            // 🆕 No plan state
            planKey: 'no-plan',
            planName: planIsExpired ? 'Plan Expired' : 'No Plan',
            durationDays: 0,
            price: 0,
            badge: '',
            features: [],
            linkLimit: 0,
            visitorLimit: 0,
            linksUsed: allUserLinks.length,
            visitorsUsed: totalUserVisits,
            linksRemaining: 0,
            visitorsRemaining: 0,
            linkLimitReached: true,
            visitorLimitReached: true,
            lifetimeUnlimited: false,
            planExpiryDate: ownerUser?.planExpiryDate || null,
            planIsExpired: planIsExpired,
            planDaysLeft: 0,
            freeTrialUsed: freeTrialUsed,
            freeTrialAvailable: !freeTrialUsed
        };

        // 🆕 If no link owned by user — return empty state
        if (!link) {
            return res.status(404).json({
                success: false,
                error: `No active link found for user "${cleanUser}".`,
                userLinks: [],           // 🆕 Empty — no random link!
                planUsage,
                plans: pricingDoc?.plans || DEFAULT_PLANS,
                paymentSettings: { method: pricingDoc?.paymentSettings?.method || 'UPI', showUpi: pricingDoc?.paymentSettings?.showUpi !== false, details: pricingDoc?.paymentSettings?.details || { upiId: 'admin@upi' } },
                whatsappNumber: pricingDoc?.whatsappNumber || '916372923348',
                hasAnyLink: false
            });
        }

        // Auto-assign user if link has no owner
        if (cleanUser && (!link.assignedUser || link.assignedUser === '')) {
            await Link.collection.updateOne({ _id: link._id }, { $set: { assignedUser: cleanUser, userName: cleanUser } });
        }

        const today = getISTDate();
        const yesterday = getISTDateMinus(1);
        const dateRangeInfo = parseDateRange(filter, startDate, endDate);
        const dailyVisitsObj = link.dailyVisits || {};
        const dailyClaimsObj = link.dailyClaims || {};

        const mappedRangeVisits = sumDailyMapBetween(dailyVisitsObj, dateRangeInfo.startStr, dateRangeInfo.endStr);
        const mappedRangeClaims = sumDailyMapBetween(dailyClaimsObj, dateRangeInfo.startStr, dateRangeInfo.endStr);
        const vToday = getDailyValue(dailyVisitsObj, today);
        const cToday = getDailyValue(dailyClaimsObj, today);
        const vYesterday = getDailyValue(dailyVisitsObj, yesterday);
        const cYesterday = getDailyValue(dailyClaimsObj, yesterday);
        const sevenDaysAgo = getISTDateMinus(6);
        const thirtyDaysAgo = getISTDateMinus(29);
        const v7d = sumDailyMapBetween(dailyVisitsObj, sevenDaysAgo, today);
        const c7d = sumDailyMapBetween(dailyClaimsObj, sevenDaysAgo, today);
        const v30d = sumDailyMapBetween(dailyVisitsObj, thirtyDaysAgo, today);
        const c30d = sumDailyMapBetween(dailyClaimsObj, thirtyDaysAgo, today);

        let daysLeft = 'Lifetime Active';
        let isEligibleForRenewal = false;
        if (link.expiryDate) {
            const diffTime = new Date(link.expiryDate) - new Date();
            daysLeft = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
            if (daysLeft <= 3) isEligibleForRenewal = true;
        }

        const lName = link.linkName || link.title || link.name || 'Untitled Campaign';
        const isUidOn = !isUidCheckDisabled(link.uidChecking);

        res.json({
            success: true,
            hasAnyLink: true,
            id: link.id, linkId: link.id, name: lName, title: lName, linkName: lName,
            userName: link.userName || link.assignedUser || cleanUser,
            totalVisits: link.visits || 0, visits: link.visits || 0,
            totalClaims: link.claims || 0, claims: link.claims || 0,
            todayVisits: vToday, todayClaims: cToday,
            yesterdayVisits: vYesterday, yesterdayClaims: cYesterday,
            v24h: vToday, c24h: cToday, v7d, c7d, v30d, c30d,
            dateRange: { filter: filter || 'today', start: dateRangeInfo.startStr, end: dateRangeInfo.endStr, visits: mappedRangeVisits, claims: mappedRangeClaims },
            link: {
                id: link.id, linkId: link.id, name: lName, title: lName, linkName: lName,
                userName: link.userName || link.assignedUser || cleanUser,
                created: link.created, expiryDate: link.expiryDate, daysLeft, isEligibleForRenewal,
                totalVisits: link.visits || 0, visits: link.visits || 0,
                totalClaims: link.claims || 0, claims: link.claims || 0,
                todayVisits: vToday, todayClaims: cToday,
                yesterdayVisits: vYesterday, yesterdayClaims: cYesterday,
                v24h: vToday, c24h: cToday, v7d, c7d, v30d, c30d,
                uidChecking: isUidOn,
                dateRange: { filter: filter || 'today', start: dateRangeInfo.startStr, end: dateRangeInfo.endStr, visits: mappedRangeVisits, claims: mappedRangeClaims }
            },
            userLinks: formattedUserLinks, planUsage,
            plans: pricingDoc?.plans || DEFAULT_PLANS,
            paymentSettings: { method: pricingDoc?.paymentSettings?.method || 'UPI', showUpi: pricingDoc?.paymentSettings?.showUpi !== false, details: pricingDoc?.paymentSettings?.details || { upiId: 'admin@upi' } },
            autoPaymentEnabled: false,
            whatsappNumber: pricingDoc?.whatsappNumber || '916372923348'
        });
    } catch (e) {
        console.error('User link details error:', e);
        res.status(500).json({ error: 'Failed to fetch link data' });
    }
});

app.post('/api/user/renew-payment', async (req, res) => {
    try {
        const { linkId, linkName, plan, days, amount, refNo, userName } = req.body;
        if (!linkId || !plan) return res.status(400).json({ error: 'Link ID and plan required' });
        await RenewalRequest.create({
            id: 'req_' + Date.now(), linkId, linkName: linkName || userName || 'Unknown Link',
            plan, days: parseInt(days) || 30, amount: parseInt(amount) || 0,
            transactionId: (refNo || 'Manual-WhatsApp').toString().trim(), status: 'pending'
        });
        res.json({ success: true, message: 'Renewal request submitted.' });
    } catch (e) { res.status(500).json({ error: 'Payment processing error' }); }
});

app.get('/api/user/short-links', async (req, res) => {
    try {
        const { userName } = req.query;
        const filter = userName ? { creator: userName } : {};
        const links = await ShortLink.find(filter).sort({ createdAt: -1 }).lean();
        res.json({ success: true, links });
    } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/user/short-links', async (req, res) => {
    try {
        const { originalUrl, title, userName, appOpen, appScheme } = req.body;
        if (!originalUrl) return res.status(400).json({ error: 'URL required' });
        const link = new ShortLink({ code: Math.random().toString(36).substring(2, 8), originalUrl, title: title || 'Untitled', creator: userName || 'User', appOpen: !!appScheme, appScheme: appScheme || '' });
        await link.save();
        res.json({ success: true, link, shortUrl: `${req.protocol}://${req.get('host')}/s/${link.code}` });
    } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/user/short-links/:id', async (req, res) => {
    try {
        await ShortLink.findByIdAndDelete(req.params.id);
        await ShortLinkClick.deleteMany({ shortLinkId: req.params.id }).catch(() => {});
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

// ==================== ADMIN USER MANAGEMENT ====================
app.get('/api/admin/all-users', authMiddleware, async (req, res) => {
    try {
        const users = await RenewalUser.find().sort({ createdAt: -1 }).lean();
        const links = await Link.find().lean();
        const pricingDoc = await getPricingDoc();
        
        const usersWithStats = users.map(u => {
            const cleanName = (u.name || '').toLowerCase().trim();
            const userLinks = links.filter(l => {
                const ln = (l.name || '').toLowerCase().trim();
                const au = (l.assignedUser || '').toLowerCase().trim();
                const un = (l.userName || '').toLowerCase().trim();
                const cr = (l.creator || '').toLowerCase().trim();
                return ln === cleanName || au === cleanName || un === cleanName || cr === cleanName;
            });
            const totalVisits = userLinks.reduce((sum, l) => sum + (parseInt(l.visits) || 0), 0);
            const totalClaims = userLinks.reduce((sum, l) => sum + (parseInt(l.claims) || 0), 0);
            const waData = generateWhatsAppApprovalData(u, req);
            const plan = getPlanDetails(pricingDoc, u.currentPlan || 'free-trial');
            return {
                ...u,
                totalLinks: userLinks.length,
                totalVisits, totalClaims,
                lifetimeUnlimited: u.lifetimeUnlimited === true,
                currentPlanName: u.lifetimeUnlimited ? 'Lifetime Unlimited' : plan.name,
                planLimit: u.lifetimeUnlimited ? 'unlimited' : plan.linkLimit,
                visitorLimit: u.lifetimeUnlimited ? 'unlimited' : plan.visitorLimit,
                whatsappMessage: waData.message,
                whatsappUrl: waData.whatsappUrl,
                portalLoginUrl: waData.loginUrl
            };
        });
        res.json({ success: true, users: usersWithStats, totalUsers: users.length });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/users/:id/whatsapp-approval', authMiddleware, async (req, res) => {
    try {
        const userId = req.params.id;
        const userQuery = mongoose.Types.ObjectId.isValid(userId) ? { _id: userId } : { id: userId };
        const user = await RenewalUser.findOne(userQuery).lean();
        if (!user) return res.status(404).json({ error: 'User not found' });
        const waData = generateWhatsAppApprovalData(user, req);
        res.json({ success: true, user, ...waData });
    } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/admin/users/:id', authMiddleware, async (req, res) => {
    try {
        const userId = req.params.id;
        const userQuery = mongoose.Types.ObjectId.isValid(userId) ? { _id: userId } : { id: userId };
        const user = await RenewalUser.findOne(userQuery);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const userName = user.name || '';
        let linksAffected = 0;
        if (userName) {
            const userRegex = new RegExp('^' + userName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
            const updateResult = await Link.updateMany(
                { $or: [{ assignedUser: userRegex }, { userName: userRegex }, { creator: userRegex }, { name: userRegex }] },
                { $set: { status: 'disabled', expiryDate: new Date() } }
            );
            linksAffected = updateResult.modifiedCount || updateResult.nModified || 0;
        }
        await RenewalUser.findOneAndDelete(userQuery);
        res.json({ success: true, message: `User "${userName}" removed. ${linksAffected} link(s) disabled.`, linksAffected });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// Lifetime Unlimited toggle
app.post('/api/admin/users/:id/lifetime-unlimited', authMiddleware, async (req, res) => {
    try {
        const { enable } = req.body;
        const userId = req.params.id;
        const userQuery = mongoose.Types.ObjectId.isValid(userId) 
            ? { _id: new mongoose.Types.ObjectId(userId) } 
            : { id: userId };
        
        const user = await RenewalUser.findOne(userQuery).lean();
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        const $set = {};
        
        if (enable === true) {
            $set.lifetimeUnlimited = true;
            $set.currentPlan = 'lifetime-unlimited';
            $set.status = 'approved';
            if (!user.approvedAt) $set.approvedAt = new Date();
        } else {
            $set.lifetimeUnlimited = false;
            if (user.currentPlan === 'lifetime-unlimited') {
                $set.currentPlan = user.freeTrialUsed ? 'none' : 'free-trial';
                if (!user.freeTrialUsed) {
                    const pricingDoc = await getPricingDoc();
                    const ftPlan = getPlanDetails(pricingDoc, 'free-trial');
                    const expiry = new Date();
                    expiry.setDate(expiry.getDate() + (ftPlan.durationDays || 3));
                    $set.planStartDate = new Date();
                    $set.planExpiryDate = expiry;
                }
            }
        }
        
        const updateResult = await RenewalUser.collection.updateOne(
            { _id: user._id },
            { $set: $set }
        );
        
        if (updateResult.matchedCount === 0) {
            return res.status(404).json({ error: 'User not found during update' });
        }
        
        if (enable === true) {
            const userRegex = new RegExp('^' + (user.name || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
            await Link.collection.updateMany(
                { $or: [{ assignedUser: userRegex }, { userName: userRegex }, { creator: userRegex }, { name: userRegex }] },
                { $set: { expiryDate: null, status: 'active' } }
            );
        }
        
        const updatedUser = await RenewalUser.findOne({ _id: user._id }).lean();
        
        console.log(`✅ Lifetime Unlimited ${enable ? 'ENABLED' : 'DISABLED'} for: ${user.name}`);
        res.json({ 
            success: true, 
            message: enable ? 'User set to Lifetime Unlimited!' : 'Lifetime Unlimited removed',
            user: {
                _id: updatedUser._id,
                name: updatedUser.name,
                lifetimeUnlimited: updatedUser.lifetimeUnlimited,
                currentPlan: updatedUser.currentPlan,
                status: updatedUser.status
            }
        });
    } catch (e) { 
        console.error('Lifetime toggle error:', e);
        res.status(500).json({ error: 'Failed: ' + e.message }); 
    }
});

app.get('/api/admin/renewal-users', authMiddleware, async (req, res) => {
    try {
        const users = await RenewalUser.find().sort({ createdAt: -1 }).lean();
        const usersWithWa = users.map(u => ({ ...u, ...generateWhatsAppApprovalData(u, req) }));
        res.json({ success: true, users: usersWithWa });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

const handleUserApprovalAction = async (req, res) => {
    try {
        const { action } = req.body;
        const targetAction = (action || 'approved').toString().trim().toLowerCase();
        const userId = req.params.id;
        const userQuery = mongoose.Types.ObjectId.isValid(userId) ? { _id: userId } : { id: userId };
        const user = await RenewalUser.findOne(userQuery);
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.status = targetAction;
        if (targetAction === 'approved') {
            user.approvedAt = new Date();
            // 🆕 Do NOT auto-assign free-trial plan. User must click "Activate Free Plan" themselves.
            if (!user.currentPlan || user.currentPlan === 'none' || user.currentPlan === 'lifetime-unlimited') {
                if (user.lifetimeUnlimited !== true && !user.currentPlan) {
                    user.currentPlan = 'none';
                }
            }
        }
        user.markModified('currentPlan');
        user.markModified('status');
        user.markModified('planExpiryDate');
        await user.save();
        if (targetAction === 'rejected') {
            const userRegex = new RegExp('^' + (user.name || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
            await Link.updateMany(
                { $or: [{ assignedUser: userRegex }, { userName: userRegex }, { creator: userRegex }, { name: userRegex }] },
                { $set: { status: 'suspended' } }
            );
        }
        const waData = generateWhatsAppApprovalData(user, req);
        res.json({ success: true, message: `User ${targetAction}!`, status: targetAction, user, whatsappUrl: waData.whatsappUrl, whatsappMessage: waData.message });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
};

app.post('/api/admin/renewal-users/:id/action', authMiddleware, handleUserApprovalAction);
app.post('/api/admin/users/:id/action', authMiddleware, handleUserApprovalAction);

// ==================== ADMIN RENEWAL ====================
app.get('/api/admin/renewal-settings', authMiddleware, async (req, res) => {
    try {
        const pricingDoc = await getPricingDoc();
        const requests = await RenewalRequest.find({ status: 'pending' }).sort({ createdAt: -1 }).lean();
        res.json({ 
            success: true, 
            pricing: pricingDoc.toObject(),
            plans: pricingDoc.plans,
            paymentSettings: pricingDoc.paymentSettings,
            requests 
        });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/renewal-settings', authMiddleware, async (req, res) => {
    try {
        const { plans, paymentSettings, upiId, whatsappNumber, showUpi } = req.body;
        let pricingDoc = await Pricing.findOne();
        if (!pricingDoc) pricingDoc = new Pricing();
        if (plans && typeof plans === 'object') {
            pricingDoc.plans = { ...pricingDoc.plans, ...plans };
            pricingDoc.markModified('plans');
        }
        if (paymentSettings && typeof paymentSettings === 'object') {
            if (!pricingDoc.paymentSettings) pricingDoc.paymentSettings = {};
            Object.assign(pricingDoc.paymentSettings, paymentSettings);
            pricingDoc.markModified('paymentSettings');
        }
        if (showUpi !== undefined) {
            if (!pricingDoc.paymentSettings) pricingDoc.paymentSettings = {};
            pricingDoc.paymentSettings.showUpi = showUpi !== false;
            pricingDoc.markModified('paymentSettings');
        }
        if (upiId !== undefined) {
            if (!pricingDoc.paymentSettings) pricingDoc.paymentSettings = {};
            if (!pricingDoc.paymentSettings.details) pricingDoc.paymentSettings.details = {};
            pricingDoc.paymentSettings.details.upiId = upiId.toString().trim();
            pricingDoc.markModified('paymentSettings');
        }
        if (whatsappNumber) pricingDoc.whatsappNumber = whatsappNumber.toString().trim();
        pricingDoc.autoPaymentEnabled = false;
        await pricingDoc.save();
        res.json({ success: true, message: 'Settings saved', pricing: pricingDoc.toObject() });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
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

        const ownerName = link ? (link.assignedUser || link.userName || link.name || link.creator) : null;
        if (ownerName && reqDoc.plan) {
            const ownerUser = await RenewalUser.findOne({ 
                name: new RegExp('^' + ownerName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i')
            });
            if (ownerUser) {
                const pricingDoc = await getPricingDoc();
                if (pricingDoc.plans && pricingDoc.plans[reqDoc.plan]) {
                    const planDetails = pricingDoc.plans[reqDoc.plan];
                    ownerUser.currentPlan = reqDoc.plan;
                    ownerUser.planStartDate = new Date();
                    const expiry = new Date();
                    expiry.setDate(expiry.getDate() + (planDetails.durationDays || reqDoc.days || 30));
                    ownerUser.planExpiryDate = expiry;
                    ownerUser.lifetimeUnlimited = false;
                    ownerUser.status = 'approved';
                    if (!ownerUser.approvedAt) ownerUser.approvedAt = new Date();
                    ownerUser.markModified('currentPlan');
                    ownerUser.markModified('planExpiryDate');
                    ownerUser.markModified('lifetimeUnlimited');
                    await ownerUser.save();
                    console.log(`✅ User "${ownerUser.name}" plan updated to: ${reqDoc.plan}`);
                }
            }
        }

        reqDoc.status = 'approved';
        reqDoc.approvedAt = new Date();
        await reqDoc.save();
        res.json({ success: true, message: 'Renewal approved & user plan updated!' });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/renewal/reject/:requestId', authMiddleware, async (req, res) => {
    try {
        const request = await RenewalRequest.findOne({ id: req.params.requestId });
        if (!request) return res.status(404).json({ error: 'Request not found' });
        request.status = 'rejected';
        await request.save();
        res.json({ success: true, message: 'Renewal rejected' });
    } catch (error) { res.status(500).json({ error: 'Failed' }); }
});

// ==================== ADMIN AUTH ====================
app.get('/api/admin/block-status', async (req, res) => {
    try {
        const blocked = await isDeviceBlocked(req);
        if (blocked) return res.json({ blocked: true, isPermanent: true, reason: blocked.reason || 'Permanent ban' });
        res.json({ blocked: false });
    } catch (e) { res.json({ blocked: false }); }
});

app.post('/api/admin/login', authLimiter, async (req, res) => {
    try {
        const { passcode } = req.body;
        const cleanPass = (passcode || '').toString().trim();
        if (!cleanPass) return res.status(400).json({ error: 'Passcode required' });
        const existingBlock = await isDeviceBlocked(req);
        if (existingBlock) return res.status(403).json({ error: 'permanently_blocked', message: '⛔ Device permanently blocked.' });

        let admin = await User.findOne();
        const activeEnvPass = process.env.ADMIN_PASSCODE ? process.env.ADMIN_PASSCODE.toString().trim() : DEFAULT_PASSCODE;
        if (!admin || !admin.passcode) {
            const hashed = bcrypt.hashSync(activeEnvPass, 10);
            admin = await User.create({ passcode: hashed, lastEnvPasscode: activeEnvPass, theme: 'dark', email: process.env.ADMIN_EMAIL || '', phone: process.env.ADMIN_PHONE || '', secretKey: 'admin@2024' });
        } else if (process.env.ADMIN_PASSCODE && admin.lastEnvPasscode !== activeEnvPass) {
            admin.passcode = bcrypt.hashSync(activeEnvPass, 10);
            admin.lastEnvPasscode = activeEnvPass;
            await admin.save();
        }

        const isValid = verifyPasscode(cleanPass, admin.passcode);
        if (isValid) {
            const { deviceKey, fingerprint, ip } = getDeviceId(req);
            const { deviceName, deviceType } = getDeviceDetails(req);
            await BlockedDevice.deleteMany({ $or: [{ deviceKey }, { ip }, { fingerprint }], isPermanent: false }).catch(() => {});
            if (Session) {
                await Session.create({
                    userId: 'admin', deviceKey, fingerprint, ip,
                    userAgent: (req.headers && req.headers['user-agent']) ? req.headers['user-agent'].toString() : 'Unknown',
                    deviceName, deviceType, isActive: true, lastActivity: new Date(), createdAt: new Date(),
                    expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000)
                }).catch(() => {});
            }
            const jwtToken = generateToken('admin');
            res.cookie('adminToken', jwtToken, { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 24 * 3600 * 1000 });
            return res.json({ success: true, token: jwtToken });
        }

        const { deviceKey, fingerprint, ip } = getDeviceId(req);
        const { deviceName, deviceType } = getDeviceDetails(req);
        let record = await BlockedDevice.findOne({ $or: [{ deviceKey }, { ip }, { fingerprint }] });
        if (!record) {
            record = new BlockedDevice({ deviceKey, fingerprint, ip, deviceName, deviceType, attempts: 1, reason: 'Failed login attempt (1/3)', isPermanent: false, lastAttempt: new Date() });
        } else {
            record.attempts = (record.attempts || 0) + 1;
            record.lastAttempt = new Date();
            record.ip = ip; record.deviceName = deviceName; record.deviceType = deviceType;
        }
        if (record.attempts >= 3 && ip !== '127.0.0.1' && ip !== '::1' && !ip.includes('localhost')) {
            record.isPermanent = true;
            record.reason = 'Permanent ban: 3 failed attempts';
            await record.save();
            return res.status(403).json({ error: 'permanently_blocked', message: '⛔ Device permanently blocked.' });
        } else {
            record.reason = `Failed passcode attempt (${record.attempts}/3)`;
            await record.save();
            return res.status(401).json({ error: `Incorrect Passcode! Attempt ${record.attempts} of 3.` });
        }
    } catch (error) { res.status(500).json({ error: 'Server authentication error' }); }
});

app.post('/api/admin/logout', async (req, res) => {
    try {
        const { deviceKey, fingerprint, ip } = getDeviceId(req);
        if (Session) await Session.updateMany({ $or: [{ deviceKey }, { ip }, { fingerprint }] }, { $set: { isActive: false, lastActivity: new Date() } }).catch(() => {});
    } catch(e) {}
    res.clearCookie('adminToken', { path: '/' });
    res.json({ success: true });
});

app.post('/api/admin/passcode', authMiddleware, async (req, res) => {
    try {
        const { oldPasscode, newPasscode } = req.body;
        const cleanOld = (oldPasscode || '').toString().trim();
        const cleanNew = (newPasscode || '').toString().trim();
        if (!cleanNew || cleanNew.length !== 6) return res.status(400).json({ error: 'New passcode must be 6 digits' });
        const admin = await User.findOne();
        if (!admin) return res.status(404).json({ error: 'Admin not found' });
        if (!verifyPasscode(cleanOld, admin.passcode)) return res.status(401).json({ error: 'Current passcode incorrect' });
        admin.passcode = bcrypt.hashSync(cleanNew, 10);
        admin.lastEnvPasscode = cleanNew;
        await admin.save();
        res.json({ success: true, message: 'Passcode changed!' });
    } catch (error) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/theme', authMiddleware, async (req, res) => {
    try {
        const admin = await User.findOne();
        if (admin) { admin.theme = req.body.theme; await admin.save(); }
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/background', authMiddleware, async (req, res) => {
    try {
        let popup = await PopupSettings.findOne();
        if (!popup) popup = new PopupSettings();
        if (req.body.background !== undefined) popup.image = req.body.background || null;
        if (req.body.uidChecking !== undefined) popup.uidChecking = !isUidCheckDisabled(req.body.uidChecking);
        await popup.save();
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Failed' }); }
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

// ==================== ADMIN LINKS CRUD ====================
app.get(['/api/links', '/api/admin/links'], authMiddleware, async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        const links = await Link.find().sort({ created: -1 }).lean();
        const formatted = links.map(l => {
            const popup = l.popupSettings || {};
            const img = popup.image || l.image || l.popupImage || l.popupImageUrl || l.banner || null;
            const isUidOn = !isUidCheckDisabled(l.uidChecking);
            const userName = l.name || l.userName || l.assignedUser || 'User';
            const linkName = l.linkName || l.title || 'Link';
            return {
                ...l, name: userName, userName: userName, assignedUser: userName,
                linkName: linkName, title: linkName,
                claims: l.claims || 0, visits: l.visits || 0,
                uidChecking: isUidOn,
                image: img, popupImage: img, popupImageUrl: img, banner: img,
                popupSettings: { ...popup, image: img }
            };
        });
        res.json(formatted);
    } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.get(['/api/links/:id', '/api/link/:id'], authMiddleware, async (req, res) => {
    try {
        const rawId = extractCleanId(req.params.id);
        const l = await Link.findOne(getLinkQuery(rawId)).lean();
        if (!l) return res.status(404).json({ error: 'Link not found' });
        const popup = l.popupSettings || {};
        const img = popup.image || l.image || l.popupImage || l.popupImageUrl || l.banner || null;
        const isUidOn = !isUidCheckDisabled(l.uidChecking);
        const userName = l.name || l.userName || l.assignedUser || 'User';
        const linkName = l.linkName || l.title || 'Link';
        res.json({
            ...l, name: userName, userName: userName, linkName: linkName, title: linkName,
            claims: l.claims || 0, visits: l.visits || 0, uidChecking: isUidOn,
            image: img, popupImage: img, popupImageUrl: img, banner: img,
            popupSettings: { ...popup, image: img }
        });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/links', authMiddleware, async (req, res) => {
    try {
        const cleanUserName = (req.body.name || req.body.userName || req.body.cCampaignName || 'User').trim();
        const cleanLinkName = (req.body.linkName || req.body.title || req.body.cLinkName || 'Link').trim();
        const cleanVideo = (req.body.video || req.body.videoUrl || req.body.url || 'https://youtu.be/dQw4w9WgXcQ').trim();
        const cleanClaim = (req.body.claim || req.body.claimUrl || req.body.claimLink || '#').trim();
        const cleanButtonText = (req.body.buttonText || req.body.btnText || 'Claim Now').trim();
        const cleanHeadline = (req.body.headline || req.body.heading || '🎬 Watch Video & Unlock Reward').trim();
        let incomingUidVal = req.body.uidChecking ?? req.body.uidCheck ?? req.body.checkUid ?? req.body.enableUid;
        const cleanUidChecking = incomingUidVal !== undefined ? !isUidCheckDisabled(incomingUidVal) : true;
        const rawExpiry = req.body.expiryDate || req.body.expiry || req.body.expDate;
        const cleanExpiry = rawExpiry && !isNaN(new Date(rawExpiry).getTime()) ? new Date(rawExpiry) : null;
        let incomingImage = req.body.popupImage || req.body.image || req.body.banner || req.body.popupSettings?.image;
        const finalBanner = incomingImage && incomingImage.trim().length > 4 ? incomingImage.trim() : null;
        const finalPopup = {
            title: req.body.popupSettings?.title || req.body.popupTitle || '🎁 Claim Your Reward',
            subtitle: req.body.popupSettings?.subtitle || req.body.popupSubtitle || 'Tap below to unlock your reward',
            buttonText: req.body.popupSettings?.buttonText || req.body.popupButtonText || cleanButtonText,
            image: finalBanner
        };
        const newLink = new Link({
            id: 'link_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex'),
            name: cleanUserName, userName: cleanUserName,
            assignedUser: cleanUserName, creator: cleanUserName,
            linkName: cleanLinkName, title: cleanLinkName,
            video: cleanVideo, claim: cleanClaim,
            buttonText: cleanButtonText, headline: cleanHeadline,
            expiryDate: cleanExpiry, uidChecking: cleanUidChecking,
            status: 'active', claims: 0, visits: 0,
            dailyClaims: {}, dailyVisits: {},
            image: finalBanner, popupImage: finalBanner,
            popupImageUrl: finalBanner, banner: finalBanner,
            popupSettings: finalPopup
        });
        await newLink.save();
        res.json({ ...newLink.toObject(), name: cleanUserName, userName: cleanUserName, linkName: cleanLinkName, title: cleanLinkName, uidChecking: cleanUidChecking, claims: 0, visits: 0, image: finalBanner, popupSettings: finalPopup });
    } catch (e) { res.status(500).json({ error: 'Failed to create link' }); }
});

// 🆕 COMPLETELY REWRITTEN: Lifetime Active properly handled
async function handleLinkUpdate(req, res) {
    try {
        let rawId = req.params.id;
        if (!rawId || ['undefined', 'null', 'update', 'edit', 'save'].includes(rawId)) {
            rawId = req.body.id || req.body.linkId || req.body._id;
        }
        const cleanId = extractCleanId(rawId);
        const query = getLinkQuery(cleanId);
        
        const existingLink = await Link.findOne(query).lean();
        if (!existingLink) return res.status(404).json({ error: 'Link not found' });

        if (req.path.includes('toggle') || req.body.action === 'toggle' || req.body.toggle === true) {
            const newVal = !(!isUidCheckDisabled(existingLink.uidChecking));
            await Link.collection.updateOne({ _id: existingLink._id }, { $set: { uidChecking: newVal } });
            return res.json({ success: true, uidChecking: newVal });
        }

        const $set = {};

        if (req.body.name && req.body.name.toString().trim()) {
            const uName = req.body.name.toString().trim();
            $set.name = uName;
            $set.userName = uName;
            $set.assignedUser = uName;
            $set.creator = uName;
        }

        const incomingLinkName = req.body.linkName ?? req.body.title ?? req.body.linkTitle ?? req.body.campaignName;
        if (incomingLinkName !== undefined && incomingLinkName !== null && incomingLinkName.toString().trim() !== '') {
            $set.linkName = incomingLinkName.toString().trim();
            $set.title = incomingLinkName.toString().trim();
        }

        const incomingVideo = req.body.video ?? req.body.videoUrl ?? req.body.url;
        if (incomingVideo !== undefined) $set.video = (incomingVideo || '').toString().trim();
        
        const incomingClaim = req.body.claim ?? req.body.claimUrl ?? req.body.claimLink;
        if (incomingClaim !== undefined) $set.claim = (incomingClaim || '').toString().trim();
        
        const incomingBtn = req.body.buttonText ?? req.body.btnText;
        if (incomingBtn !== undefined) $set.buttonText = (incomingBtn || '').toString().trim();
        
        const incomingHeadline = req.body.headline ?? req.body.heading;
        if (incomingHeadline !== undefined) $set.headline = (incomingHeadline || '').toString().trim();
        
        if (req.body.status !== undefined) $set.status = req.body.status;

        let incomingUidVal = req.body.uidChecking ?? req.body.uidCheck ?? req.body.checkUid ?? req.body.enableUid;
        if (incomingUidVal !== undefined) $set.uidChecking = !isUidCheckDisabled(incomingUidVal);

        // 🆕 CRITICAL: Make Lifetime Active handling — strict
        // If makeLifetime is true OR expiryDate is null/empty/null-string → set to null (lifetime)
        const makeLifetimeFlag = req.body.makeLifetime === true || req.body.lifetimeActive === true;
        const hasExpiryField = ('expiryDate' in req.body) || ('expiry' in req.body) || ('expDate' in req.body);
        
        if (makeLifetimeFlag) {
            $set.expiryDate = null;
            console.log(`✅ Link ${cleanId} set to Lifetime Active`);
        } else if (hasExpiryField) {
            const incomingExpiry = req.body.expiryDate ?? req.body.expiry ?? req.body.expDate;
            if (incomingExpiry === null || incomingExpiry === '' || incomingExpiry === 'null' || incomingExpiry === undefined) {
                $set.expiryDate = null;
            } else if (!isNaN(new Date(incomingExpiry).getTime())) {
                $set.expiryDate = new Date(incomingExpiry);
            } else {
                $set.expiryDate = null;
            }
        }

        const currentPopup = existingLink.popupSettings || {};
        const newPopup = {
            title: req.body.popupSettings?.title || req.body.popupTitle || currentPopup.title || '🎁 Claim Your Reward',
            subtitle: req.body.popupSettings?.subtitle || req.body.popupSubtitle || currentPopup.subtitle || 'Tap below to unlock your reward',
            buttonText: req.body.popupSettings?.buttonText || req.body.popupButtonText || currentPopup.buttonText || 'Claim Now',
            image: currentPopup.image || null
        };

        let incomingImage = req.body.popupImage ?? req.body.image ?? req.body.banner ?? req.body.popupSettings?.image;
        if (incomingImage !== undefined) {
            const cleanImg = (incomingImage || '').toString().trim();
            const finalImg = cleanImg.length > 4 ? cleanImg : null;
            newPopup.image = finalImg;
            $set.image = finalImg;
            $set.popupImage = finalImg;
            $set.popupImageUrl = finalImg;
            $set.banner = finalImg;
        }
        $set.popupSettings = newPopup;

        const updateResult = await Link.collection.updateOne(
            { _id: existingLink._id },
            { $set: $set }
        );

        if (updateResult.matchedCount === 0) {
            return res.status(404).json({ error: 'Link not found during update' });
        }

        if ($set.linkName) {
            await RenewalRequest.updateMany({ linkId: existingLink.id }, { $set: { linkName: $set.linkName } }).catch(() => {});
        }

        const updatedDoc = await Link.findOne({ _id: existingLink._id }).lean();
        const effectiveUserName = updatedDoc.name || updatedDoc.userName || 'User';
        const effectiveLinkName = updatedDoc.linkName || updatedDoc.title || 'Link';
        const finalUidState = !isUidCheckDisabled(updatedDoc.uidChecking);

        res.json({
            success: true, ...updatedDoc, id: updatedDoc.id,
            name: effectiveUserName, userName: effectiveUserName,
            linkName: effectiveLinkName, title: effectiveLinkName,
            claims: updatedDoc.claims || 0, visits: updatedDoc.visits || 0,
            uidChecking: finalUidState,
            expiryDate: updatedDoc.expiryDate || null,
            image: updatedDoc.popupSettings?.image || null,
            popupImage: updatedDoc.popupSettings?.image || null,
            popupImageUrl: updatedDoc.popupSettings?.image || null,
            banner: updatedDoc.popupSettings?.image || null,
            popupSettings: updatedDoc.popupSettings || newPopup
        });
    } catch (e) { 
        console.error('Link update error:', e);
        res.status(500).json({ error: 'Failed to update link: ' + e.message }); 
    }
}

app.put(['/api/links/:id', '/api/link/:id', '/api/links/update/:id', '/api/links/update'], authMiddleware, handleLinkUpdate);
app.post(['/api/links/:id', '/api/link/:id', '/api/links/update/:id', '/api/links/update', '/api/link/update'], authMiddleware, handleLinkUpdate);
app.patch(['/api/links/:id', '/api/link/:id'], authMiddleware, handleLinkUpdate);
app.all('/api/links/:id/uid-checking', authMiddleware, handleLinkUpdate);
app.all('/api/links/:id/toggle-uid', authMiddleware, handleLinkUpdate);
app.all('/api/links/:id/uid', authMiddleware, handleLinkUpdate);
app.all('/api/links/:id/toggle', authMiddleware, handleLinkUpdate);

app.delete(['/api/links/:id', '/api/link/:id'], authMiddleware, async (req, res) => {
    try {
        const query = getLinkQuery(extractCleanId(req.params.id));
        await Link.deleteMany(query);
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Failed' }); }
});

// ==================== ADMIN ALL STATS ====================
app.get('/api/all-stats', authMiddleware, async (req, res) => {
    try {
        const { filter, startDate, endDate } = req.query;
        const links = await Link.find().lean();
        const today = getISTDate();
        const yesterday = getISTDateMinus(1);
        const dateRangeInfo = parseDateRange(filter, startDate, endDate);
        let totV = 0, totC = 0, todayV = 0, todayC = 0, yestV = 0, yestC = 0, rangeV = 0, rangeC = 0;
        const formattedLinks = links.map(l => {
            const v = parseInt(l.visits) || 0;
            const c = parseInt(l.claims) || 0;
            totV += v; totC += c;
            const dailyVisitsObj = l.dailyVisits || {};
            const dailyClaimsObj = l.dailyClaims || {};
            const tv = getDailyValue(dailyVisitsObj, today);
            const tc = getDailyValue(dailyClaimsObj, today);
            const yv = getDailyValue(dailyVisitsObj, yesterday);
            const yc = getDailyValue(dailyClaimsObj, yesterday);
            todayV += tv; todayC += tc; yestV += yv; yestC += yc;
            const lRangeVisits = sumDailyMapBetween(dailyVisitsObj, dateRangeInfo.startStr, dateRangeInfo.endStr);
            const lRangeClaims = sumDailyMapBetween(dailyClaimsObj, dateRangeInfo.startStr, dateRangeInfo.endStr);
            rangeV += lRangeVisits; rangeC += lRangeClaims;
            return {
                ...l,
                name: l.name || l.userName || 'User',
                userName: l.name || l.userName || 'User',
                linkName: l.linkName || l.title || 'Link',
                title: l.linkName || l.title || 'Link',
                claims: c, visits: v,
                todayVisits: tv, todayClaims: tc,
                yesterdayVisits: yv, yesterdayClaims: yc,
                rangeVisits: lRangeVisits, rangeClaims: lRangeClaims,
                uidChecking: !isUidCheckDisabled(l.uidChecking)
            };
        });
        
        const activeWatchingAgg = await VisitorActivity.aggregate([
            { $match: { type: 'visit', lastSeen: { $gte: new Date(Date.now() - 5 * 60 * 1000) } } },
            { $group: { _id: '$visitorKey' } },
            { $count: 'count' }
        ]).catch(() => []);
        const activeWatching = activeWatchingAgg[0]?.count || 0;

        const activeClaimingAgg = await VisitorActivity.aggregate([
            { $match: { type: 'claim', source: 'video', lastSeen: { $gte: new Date(Date.now() - 5 * 60 * 1000) } } },
            { $group: { _id: '$visitorKey' } },
            { $count: 'count' }
        ]).catch(() => []);
        const activeClaiming = activeClaimingAgg[0]?.count || 0;

        res.json({
            global: {
                totalVisitors: totV, totalClaims: totC,
                todayVisitors: todayV, todayClaims: todayC,
                yesterdayVisitors: yestV, yesterdayClaims: yestC,
                activeNow: activeWatching, activeClaims: activeClaiming,
                rangeVisitors: rangeV, rangeClaims: rangeC,
                rangeFilter: filter || 'all',
                startDate: dateRangeInfo.startStr, endDate: dateRangeInfo.endStr
            },
            links: formattedLinks
        });
    } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

// ==================== DEVICES & SESSIONS ====================
app.get('/api/admin/blocked-devices', authMiddleware, async (req, res) => {
    try {
        const devices = await BlockedDevice.find({}).sort({ lastAttempt: -1 }).lean();
        res.json({ success: true, devices });
    } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/blocked-devices/:id/unblock', authMiddleware, async (req, res) => {
    try {
        await BlockedDevice.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'Device unblocked' });
    } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/active-sessions', authMiddleware, async (req, res) => {
    try {
        let allSessions = [];
        if (Session) {
            allSessions = await Session.find({ createdAt: { $gte: new Date(Date.now() - 30 * 24 * 3600 * 1000) } }).sort({ lastActivity: -1 }).lean();
        }
        const uniqueDevices = new Map();
        for (const s of allSessions) {
            const key = s.deviceKey || s.fingerprint || s._id.toString();
            const existing = uniqueDevices.get(key);
            if (!existing || (s.isActive && !existing.isActive) || (new Date(s.lastActivity) > new Date(existing.lastActivity))) {
                uniqueDevices.set(key, s);
            }
        }
        const sessionsList = Array.from(uniqueDevices.values()).sort((a, b) => {
            if (a.isActive !== b.isActive) return a.isActive ? -1 : 1;
            return new Date(b.lastActivity) - new Date(a.lastActivity);
        });
        res.json({ success: true, sessions: sessionsList });
    } catch (error) { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/admin/sessions/:id', authMiddleware, async (req, res) => {
    try {
        if (Session) {
            const sid = req.params.id;
            if (mongoose.Types.ObjectId.isValid(sid)) await Session.updateOne({ _id: sid }, { $set: { isActive: false, lastActivity: new Date() } });
            else await Session.updateOne({ id: sid }, { $set: { isActive: false, lastActivity: new Date() } });
        }
        res.json({ success: true, message: 'Session terminated' });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/sessions/:id/block', authMiddleware, async (req, res) => {
    try {
        let session = null;
        if (Session) {
            const sid = req.params.id;
            if (mongoose.Types.ObjectId.isValid(sid)) session = await Session.findById(sid);
            else session = await Session.findOne({ id: sid });
        }
        if (session) {
            await BlockedDevice.create({
                ip: session.ip || '127.0.0.1',
                deviceKey: session.deviceKey || crypto.randomBytes(16).toString('hex'),
                fingerprint: session.fingerprint || crypto.randomBytes(16).toString('hex'),
                deviceName: session.deviceName || 'Admin Device',
                deviceType: session.deviceType || 'Desktop',
                attempts: 3, isPermanent: true,
                reason: 'Permanently blocked by admin',
                lastAttempt: new Date()
            });
            await Session.updateMany({ $or: [{ deviceKey: session.deviceKey }, { fingerprint: session.fingerprint }, { ip: session.ip }] }, { $set: { isActive: false } }).catch(() => {});
        }
        res.json({ success: true, message: 'Device blocked permanently' });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ==================== SHORT LINKS ====================
app.get('/s/:code', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    const link = await ShortLink.findOne({ code: req.params.code });
    if (!link) return res.status(404).send('Not found');
    link.visits = (link.visits || 0) + 1;
    await link.save();
    const { ip, userAgent } = getDeviceId(req);
    const { deviceName, deviceType } = getDeviceDetails(req);
    await ShortLinkClick.create({ shortLinkId: link._id, ip, userAgent, deviceName, deviceType, referer: req.headers.referer || null });
    if (link.appOpen && link.appScheme) return res.redirect(link.appScheme);
    try {
        const orig = link.originalUrl || '';
        if (orig.includes('/uid') || orig.includes('link=')) {
            const cleanId = extractCleanId(orig);
            if (cleanId) {
                const targetLink = await Link.findOne(getLinkQuery(cleanId)).lean();
                if (targetLink && isUidCheckDisabled(targetLink.uidChecking)) return res.redirect('/v/' + encodeURIComponent(targetLink.id || cleanId));
            }
        }
    } catch(err) {}
    res.redirect(link.originalUrl);
});

app.get('/api/short-links', authMiddleware, async (req, res) => {
    const links = await ShortLink.find().sort({ createdAt: -1 });
    res.json({ success: true, links });
});

app.post('/api/short-links', authMiddleware, async (req, res) => {
    const { originalUrl, title, appOpen, appScheme } = req.body;
    const link = new ShortLink({ code: Math.random().toString(36).substring(2, 8), originalUrl, title: title || 'Untitled', appOpen: !!appScheme, appScheme: appScheme || '' });
    await link.save();
    res.json({ success: true, link, shortUrl: `${req.protocol}://${req.get('host')}/s/${link.code}` });
});

app.delete('/api/short-links/:id', authMiddleware, async (req, res) => {
    await ShortLink.findByIdAndDelete(req.params.id);
    await ShortLinkClick.deleteMany({ shortLinkId: req.params.id });
    res.json({ success: true });
});

// ==================== FILE SERVING ====================
function sendAppFile(res, ...fileNames) {
    const searchDirs = [path.join(__dirname, 'admin'), path.join(__dirname, 'public'), __dirname, path.join(__dirname, '..'), path.join(__dirname, '..', 'admin'), path.join(__dirname, '..', 'public')];
    for (const name of fileNames) {
        for (const dir of searchDirs) {
            const p = path.join(dir, name);
            if (fs.existsSync(p)) return res.sendFile(p);
        }
    }
    res.status(404).send(`File not found: ${fileNames.join(', ')}`);
}

function sendUidCheckerFile(res, targetLinkId) {
    const searchDirs = [path.join(__dirname, 'admin'), path.join(__dirname, 'public'), __dirname, path.join(__dirname, '..'), path.join(__dirname, '..', 'admin'), path.join(__dirname, '..', 'public')];
    const fileNames = ['uid-checker.html', 'uid.html'];
    for (const name of fileNames) {
        for (const dir of searchDirs) {
            const p = path.join(dir, name);
            if (fs.existsSync(p)) {
                try {
                    let content = fs.readFileSync(p, 'utf8');
                    const guardScript = `
<script>
(function() {
    try {
        var p = new URLSearchParams(window.location.search);
        var lid = p.get('link') || p.get('id') || p.get('l') || ${JSON.stringify(targetLinkId || '')};
        if (!lid) { var parts = window.location.pathname.split('/'); var last = parts[parts.length - 1]; if (last && last !== 'uid' && last !== 'uid.html' && last !== 'uid-checker.html') lid = last; }
        if (lid) { 
            fetch('/api/link/' + encodeURIComponent(lid)).then(function(r) { 
                if (r.status === 403 || r.status === 404) { window.location.replace('/expired.html'); return; }
                return r.json(); 
            }).then(function(d) { 
                if (!d) return;
                if (d.expired === true) { window.location.replace('/expired.html'); return; }
                if (d.uidChecking === false || d.uidChecking === 'false' || d.uidChecking === 'off' || d.uidChecking === 0) { 
                    window.location.replace('/v/' + encodeURIComponent(d.id || lid)); 
                } 
            }).catch(function(){}); 
        }
    } catch(e) {}
})();
</script>
`;
                    if (content.includes('<head>')) content = content.replace('<head>', '<head>' + guardScript);
                    else if (content.includes('<body>')) content = content.replace('<body>', '<body>' + guardScript);
                    else content = guardScript + content;
                    res.setHeader('Content-Type', 'text/html; charset=utf-8');
                    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
                    return res.send(content);
                } catch(e) { return res.sendFile(p); }
            }
        }
    }
    res.status(404).send('File not found: uid-checker.html');
}

function sendVideoLockFile(res, targetLinkId) {
    const searchDirs = [path.join(__dirname, 'admin'), path.join(__dirname, 'public'), __dirname, path.join(__dirname, '..'), path.join(__dirname, '..', 'admin'), path.join(__dirname, '..', 'public')];
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
try { sessionStorage.setItem('player_uid', 'verified'); sessionStorage.setItem('uid_verified', 'true'); localStorage.setItem('player_uid', 'verified'); localStorage.setItem('uid_verified', 'true'); } catch(e) {}
</script>
<script>
(function() {
    try {
        var lid = ${JSON.stringify(targetLinkId || '')};
        if (!lid) { var parts = window.location.pathname.split('/'); var last = parts[parts.length - 1]; if (last && last !== 'v') lid = last; }
        if (lid) {
            fetch('/api/link/' + encodeURIComponent(lid)).then(function(r) { 
                if (r.status === 403 || r.status === 404) { window.location.replace('/expired.html'); } 
            }).catch(function(){});
        }
    } catch(e) {}
})();
</script>
`;
                    if (content.includes('<head>')) content = content.replace('<head>', '<head>' + preVerifyScript);
                    else if (content.includes('<body>')) content = content.replace('<body>', '<body>' + preVerifyScript);
                    else content = preVerifyScript + content;
                    res.setHeader('Content-Type', 'text/html; charset=utf-8');
                    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
                    return res.send(content);
                } catch(e) { return res.sendFile(p); }
            }
        }
    }
    res.status(404).send('File not found: video-lock.html');
}

app.get('/admin/login.html', async (req, res) => {
    const blocked = await isDeviceBlocked(req);
    if (blocked) {
        return res.send(`<!DOCTYPE html><html><head><title>Access Blocked</title><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>body{background:#090a10;color:#fff;font-family:'Segoe UI',sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;text-align:center;padding:20px;margin:0;}.card{background:#131722;padding:40px 30px;border-radius:20px;border:1px solid rgba(239,68,68,0.4);max-width:450px;}.icon{font-size:56px;margin-bottom:12px;display:block;}h1{color:#ef4444;font-size:22px;margin-bottom:14px;font-weight:800;}p{color:#94a3b8;font-size:14px;line-height:1.7;margin-bottom:8px;}.note{color:#64748b;font-size:12px;margin-top:16px;padding-top:16px;border-top:1px solid rgba(255,255,255,0.08);}strong{color:#f87171;}</style></head><body><div class="card"><span class="icon">⛔</span><h1>DEVICE PERMANENTLY BLOCKED</h1><p>Your device has been <strong>permanently blocked</strong> due to repeated failed login attempts.</p><p>This ban cannot be removed automatically.</p><p class="note">Only an authorized administrator can unblock this device from the Admin Panel.</p></div></body></html>`);
    }
    sendAppFile(res, 'login.html', 'admin/login.html');
});

app.get('/expired.html', (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Link Expired</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; }
        body {
            background: #080c16;
            color: #f8fafc;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            overflow: hidden;
            position: relative;
        }
        .ambient-glow {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: 
                radial-gradient(circle at 50% 20%, rgba(239, 68, 68, 0.18) 0%, transparent 55%),
                radial-gradient(circle at 85% 85%, rgba(239, 68, 68, 0.08) 0%, transparent 50%);
            z-index: 0; pointer-events: none;
        }
        .expired-card {
            position: relative; z-index: 1;
            background: rgba(17, 23, 38, 0.85);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border-radius: 26px;
            padding: 42px 30px;
            max-width: 440px;
            width: 100%;
            text-align: center;
            border: 1px solid rgba(239, 68, 68, 0.35);
            box-shadow: 0 30px 80px rgba(0, 0, 0, 0.75), 0 0 60px rgba(239, 68, 68, 0.15);
            animation: fadeInUp 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(30px) scale(0.95); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }
        .expired-icon {
            width: 90px; height: 90px;
            margin: 0 auto 18px;
            border-radius: 50%;
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.25), rgba(220, 38, 38, 0.15));
            border: 2px solid rgba(239, 68, 68, 0.5);
            display: flex; align-items: center; justify-content: center;
            font-size: 44px;
            box-shadow: 0 10px 30px rgba(239, 68, 68, 0.3);
            animation: pulse 2s ease-in-out infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); box-shadow: 0 10px 30px rgba(239, 68, 68, 0.3); }
            50% { transform: scale(1.05); box-shadow: 0 15px 40px rgba(239, 68, 68, 0.5); }
        }
        .expired-title {
            font-size: 28px;
            font-weight: 900;
            color: #ef4444;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }
        .expired-subtitle {
            font-size: 14.5px;
            color: #cbd5e1;
            line-height: 1.6;
            margin-bottom: 24px;
        }
        .info-box {
            background: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.25);
            border-radius: 14px;
            padding: 16px;
            margin-bottom: 24px;
            text-align: left;
        }
        .info-row {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 13px;
            color: #cbd5e1;
            margin-bottom: 8px;
        }
        .info-row:last-child { margin-bottom: 0; }
        .info-row .emoji { font-size: 16px; }
        .info-row strong { color: #fff; font-weight: 700; margin-left: auto; }
        .action-btn {
            width: 100%;
            padding: 15px;
            border: none;
            border-radius: 14px;
            font-size: 15px;
            font-weight: 800;
            cursor: pointer;
            background: linear-gradient(135deg, #4f46e5, #7c3aed);
            color: #fff;
            box-shadow: 0 12px 30px rgba(79, 70, 229, 0.4);
            transition: all 0.25s ease;
            text-decoration: none;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        .action-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 18px 40px rgba(79, 70, 229, 0.55);
        }
        .action-btn:active { transform: scale(0.98); }
        @media (max-width: 480px) {
            .expired-card { padding: 32px 22px; }
            .expired-title { font-size: 24px; }
            .expired-icon { width: 76px; height: 76px; font-size: 36px; }
            .expired-subtitle { font-size: 13.5px; }
        }
    </style>
</head>
<body>
    <div class="ambient-glow"></div>
    <div class="expired-card">
        <div class="expired-icon">⏰</div>
        <div class="expired-title">Link Expired</div>
        <div class="expired-subtitle">
            This link is no longer active. Its validity period has ended, or the owner's plan has expired.
        </div>
        <div class="info-box">
            <div class="info-row">
                <span class="emoji">📌</span>
                <span>Status</span>
                <strong style="color:#f87171;">Expired</strong>
            </div>
            <div class="info-row">
                <span class="emoji">🔒</span>
                <span>Access</span>
                <strong>Blocked</strong>
            </div>
            <div class="info-row">
                <span class="emoji">💬</span>
                <span>Support</span>
                <strong>Contact Owner</strong>
            </div>
        </div>
        <button class="action-btn" onclick="window.location.href='/'">
            <span>🏠</span> Return to Home
        </button>
    </div>
</body>
</html>`);
});

app.get('/', async (req, res) => {
    let rawParam = (req.query.link || req.query.id || req.query.l || '').toString().trim();
    if (rawParam) {
        let cleanId = extractCleanId(rawParam);
        if (cleanId) {
            const link = await Link.findOne(getLinkQuery(cleanId)).lean();
            if (link && isLinkExpired(link)) return res.redirect('/expired.html');
            if (link && isUidCheckDisabled(link.uidChecking)) return res.redirect('/v/' + encodeURIComponent(link.id || cleanId));
            else if (link) return res.redirect('/uid?link=' + encodeURIComponent(link.id || cleanId));
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

app.get(['/uid', '/uid.html', '/uid-checker.html', '/uid/:id'], async (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    let cleanId = '';
    try {
        let rawParam = (req.query.link || req.query.id || req.query.l || req.query.linkId || req.params.id || '').toString().trim();
        cleanId = extractCleanId(rawParam);
        let link = cleanId ? await Link.findOne(getLinkQuery(cleanId)).lean() : null;
        if (!link) link = await Link.findOne({ status: 'active' }).sort({ created: -1 }).lean();
        
        if (link && isLinkExpired(link)) return res.redirect('/expired.html');
        
        const globalPopup = await PopupSettings.findOne().lean().catch(() => null);
        const isGlobalOff = globalPopup && isUidCheckDisabled(globalPopup.uidChecking);
        const isLinkOff = link && isUidCheckDisabled(link.uidChecking);
        if (isLinkOff || isGlobalOff) {
            const targetId = (link && link.id) ? link.id : (cleanId || 'default');
            return res.redirect('/v/' + encodeURIComponent(targetId));
        }
    } catch(err) {}
    sendUidCheckerFile(res, cleanId);
});

app.get('/v/:id', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    const cleanId = extractCleanId(req.params.id);
    
    try {
        const link = await Link.findOne(getLinkQuery(cleanId)).lean();
        if (!link) return res.redirect('/expired.html');
        if (isLinkExpired(link)) return res.redirect('/expired.html');
        
        const ownerName = link.assignedUser || link.userName || link.name || link.creator;
        if (ownerName) {
            const ownerUser = await RenewalUser.findOne({ 
                name: new RegExp('^' + ownerName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i')
            }).lean();
            if (ownerUser && isPlanExpired(ownerUser)) return res.redirect('/expired.html');
        }
    } catch(err) {}
    
    sendVideoLockFile(res, cleanId);
});

app.get(['/user-dashboard', '/user-dashboard/:id?'], (req, res) => sendAppFile(res, 'user-dashboard.html'));
app.get('/manifest.json', (req, res) => sendAppFile(res, 'manifest.json'));
app.get('/sw.js', (req, res) => sendAppFile(res, 'sw.js'));

process.on('uncaughtException', (err) => { console.error('❌ Uncaught Exception:', err.message); });
process.on('unhandledRejection', (reason) => { console.error('❌ Unhandled Rejection:', reason); });

setInterval(async () => {
    try {
        if (Session) await Session.deleteMany({ expiresAt: { $lt: new Date() } });
        await OTPVerification.deleteMany({ expiresAt: { $lt: new Date() } });
    } catch (error) { console.error('Cleanup error:', error); }
}, 60 * 60 * 1000);

app.listen(port, '0.0.0.0', () => console.log(`🚀 Server running on port ${port}`));
