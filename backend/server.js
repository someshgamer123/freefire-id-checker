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
const mongoose = require('mongoose');
const { doubleCsrf } = require('csrf-csrf');

console.log('✅ Built-in injection protection ENABLED');

const emailHelper = require('./emailHelper');

const UNIQUE_WINDOW_MS = 48 * 60 * 60 * 1000;
const ACTIVE_WINDOW_MS = 5 * 60 * 1000;

// ============================================================
// ✅ DB config loading
// ============================================================
let connectDB;
try {
    connectDB = require('./config/db');
} catch(e1) {
    try {
        connectDB = require('./db');
    } catch(e2) {
        console.warn('⚠️ No db.js found — using inline fallback');
        connectDB = async () => {
            const uri = process.env.MONGODB_URI || process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/free_redeemcode';
            try {
                await mongoose.connect(uri, { serverSelectionTimeoutMS: 5000 });
                console.log('✅ MongoDB connected (fallback)');
            } catch(err) {
                console.error('❌ MongoDB connection error:', err.message);
            }
        };
    }
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

const RenewalUser = safeLoadModel('RenewalUser', {
    name: { type: String, default: '', trim: true },
    email: { type: String, required: true, trim: true, lowercase: true },
    phone: { type: String, default: '', trim: true },
    googleId: { type: String, default: null },
    authMethod: { type: String, enum: ['email', 'google', 'otp'], default: 'otp' },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    currentPlan: { type: String, default: 'none' },
    planStartDate: { type: Date, default: null },
    planExpiryDate: { type: Date, default: null },
    lifetimeUnlimited: { type: Boolean, default: false },
    freeTrialUsed: { type: Boolean, default: false },
    freeTrialActivatedAt: { type: Date, default: null },
    linksCreatedThisCycle: { type: Number, default: 0 },
    visitorsThisCycle: { type: Number, default: 0 },
    profileCompleted: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    approvedAt: { type: Date, default: null }
});

const Pricing = safeLoadModel('Pricing', {
    plans: { type: Object, default: {} },
    paymentSettings: { type: Object, default: {} },
    whatsappNumber: { type: String, default: '916372923348' },
    supportEmail: { type: String, default: '' },
    autoPaymentEnabled: { type: Boolean, default: false }
});

const Session = safeLoadModel('Session', { userId: { type: String, default: 'admin' }, deviceKey: String, fingerprint: String, ip: String, userAgent: String, deviceName: String, deviceType: String, isActive: { type: Boolean, default: true }, lastActivity: { type: Date, default: Date.now }, createdAt: { type: Date, default: Date.now }, expiresAt: { type: Date, default: () => new Date(Date.now() + 7 * 24 * 3600 * 1000) } });
const AdminLog = safeLoadModel('AdminLog', { action: String, details: Object, timestamp: { type: Date, default: Date.now } });
const LoginAttempt = safeLoadModel('LoginAttempt', { ip: String, attempts: Number, lastAttempt: Date });
const TwoFactorAuth = safeLoadModel('TwoFactorAuth', { userId: String, secret: String, backupCodes: Array, isEnabled: Boolean, verifiedAt: Date });
const BlockedDevice = safeLoadModel('BlockedDevice', { deviceKey: String, fingerprint: String, ip: String, deviceName: String, deviceType: String, attempts: { type: Number, default: 1 }, reason: String, isPermanent: { type: Boolean, default: false }, lastAttempt: { type: Date, default: Date.now } });
const OTPVerification = safeLoadModel('OTPVerification', { phone: String, otp: String, expiresAt: Date });
const ShortLink = safeLoadModel('ShortLink', { code: String, originalUrl: String, title: String, creator: String, visits: { type: Number, default: 0 }, appOpen: Boolean, appScheme: String, createdAt: { type: Date, default: Date.now } });
const ShortLinkClick = safeLoadModel('ShortLinkClick', { shortLinkId: String, ip: String, userAgent: String, deviceName: String, deviceType: String, referer: String, timestamp: { type: Date, default: Date.now } });

const Otp = safeLoadModel('Otp', {
    email: { type: String, required: true, lowercase: true, trim: true },
    otp: { type: String, required: true },
    purpose: { type: String, enum: ['signup', 'signin'], default: 'signin' },
    attempts: { type: Number, default: 0 },
    verified: { type: Boolean, default: false },
    expiresAt: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now }
});

const VisitorActivitySchema = new mongoose.Schema({
    linkId: { type: String, required: true, index: true },
    visitorKey: { type: String, required: true, index: true },
    type: { type: String, enum: ['visit', 'claim'], required: true, index: true },
    source: { type: String, enum: ['video', 'popup', 'direct'], default: 'video' },
    uid: { type: String, default: null },
    lastSeen: { type: Date, default: Date.now, index: true }
}, { timestamps: true, strict: false });

VisitorActivitySchema.index({ linkId: 1, visitorKey: 1, type: 1, lastSeen: -1 });
VisitorActivitySchema.index({ type: 1, lastSeen: -1 });
const VisitorActivity = mongoose.models.VisitorActivity || mongoose.model('VisitorActivity', VisitorActivitySchema);

const DEFAULT_PASSCODE = process.env.ADMIN_PASSCODE ? process.env.ADMIN_PASSCODE.toString().trim() : '951753';

const DISPOSABLE_DOMAINS = [
    'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
    'yopmail.com', 'throwaway.email', 'sharklasers.com', 'guerrillamailblock.com',
    'temp-mail.org', 'fakeinbox.com', 'trashmail.com', 'getnada.com',
    'maildrop.cc', 'mohmal.com', 'tempr.email', 'dispostable.com',
    'emailondeck.com', 'mytemp.email', 'burnermail.io', 'mailsac.com'
];

const PLAN_ORDER = ['free-trial', 'basic', 'creator', 'pro', 'business', 'enterprise-vip'];

const DEFAULT_PLANS = {
    'free-trial': { name: 'Free Trial', icon: 'gift', durationDays: 3, linkLimit: 1, visitorLimit: 150, price: 0, enabled: true, badge: 'FREE', features: ['1 Active Link', '150 Total Visitors', '3 Days Validity', 'Basic Analytics'] },
    'basic': { name: 'Basic', icon: 'package', durationDays: 14, linkLimit: 5, visitorLimit: 5000, price: 199, enabled: true, badge: '', features: ['5 Active Links', '5,000 Total Visitors', 'Detailed Analytics', '14 Days Validity'] },
    'creator': { name: 'Creator', icon: 'star', durationDays: 14, linkLimit: 10, visitorLimit: 15000, price: 399, enabled: true, badge: '', features: ['10 Active Links', '15,000 Total Visitors', 'Detailed Analytics', '14 Days Validity'] },
    'pro': { name: 'Pro', icon: 'rocket', durationDays: 30, linkLimit: 25, visitorLimit: 50000, price: 799, enabled: true, badge: 'POPULAR', features: ['25 Active Links', '50,000 Total Visitors', 'Advanced Analytics', 'Custom Link Names', '30 Days Validity'] },
    'business': { name: 'Business', icon: 'briefcase', durationDays: 90, linkLimit: 100, visitorLimit: 200000, price: 1999, enabled: true, badge: 'SAVE 20%', features: ['100 Active Links', '2,00,000 Total Visitors', 'Priority Support', 'Custom Link Names', '90 Days Validity'] },
    'enterprise-vip': { name: 'Enterprise VIP', icon: 'crown', durationDays: 365, linkLimit: 'unlimited', visitorLimit: 'unlimited', price: 4999, enabled: true, badge: 'BEST VALUE', features: ['Unlimited Links', 'Unlimited Visitors', 'VIP Support', 'Custom Everything', '1 Year Validity'] }
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
    }
    return { $or: orConditions };
}

function isLinkExpired(link) {
    if (!link) return true;
    if (link.status === 'suspended' || link.status === 'disabled' || link.status === 'inactive') return true;
    if (link.expiryDate && !isNaN(new Date(link.expiryDate).getTime())) {
        const expTime = new Date(link.expiryDate).getTime();
        if (expTime > 1000000000000 && Date.now() > expTime) return true;
    }
    return false;
}

function canUserPurchasePlan(user, targetPlanKey) {
    if (!user) return { allowed: false, reason: 'NO_USER' };
    if (user.lifetimeUnlimited === true) return { allowed: false, reason: 'LIFETIME_UNLIMITED', message: 'You already have Lifetime Unlimited access.' };
    const currentPlan = user.currentPlan || 'none';
    if (currentPlan === 'none' || isPlanExpired(user)) return { allowed: true };
    if (currentPlan === 'lifetime-unlimited') return { allowed: false, reason: 'LIFETIME_UNLIMITED', message: 'You already have Lifetime Unlimited access.' };
    const currentIdx = PLAN_ORDER.indexOf(currentPlan);
    const targetIdx = PLAN_ORDER.indexOf(targetPlanKey);
    if (currentIdx === -1 || targetIdx === -1) return { allowed: true };
    if (targetIdx <= currentIdx) return { allowed: false, reason: 'PLAN_TOO_LOW', message: `You already have ${currentPlan} plan. You can only upgrade to a higher plan.` };
    return { allowed: true };
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
    } catch(e) { return { success: false, error: 'Verification failed' }; }
}

// ==================== PLAN HELPERS ====================
async function getPricingDoc() {
    let pricingDoc = await Pricing.findOne();
    if (!pricingDoc) {
        pricingDoc = await Pricing.create({
            plans: DEFAULT_PLANS,
            paymentSettings: { method: 'UPI', showUpi: true, details: { upiId: 'admin@upi' } },
            whatsappNumber: '916372923348',
            supportEmail: '',
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
    if (!user.planExpiryDate) return true;
    try { return new Date(user.planExpiryDate) < new Date(); } catch(e) { return true; }
}

function userHasActivePlan(user) {
    if (!user) return false;
    if (user.lifetimeUnlimited === true) return true;
    if (!user.planExpiryDate) return false;
    const currentPlan = (user.currentPlan || 'none').toString().trim();
    if (!currentPlan || currentPlan === 'none' || currentPlan === 'no-plan') return false;
    try { return new Date(user.planExpiryDate) >= new Date(); } catch(e) { return false; }
}

async function getUserLinkLimit(user) {
    try {
        if (!user) return { limit: 0, used: 0, unlimited: false };
        if (user.lifetimeUnlimited === true) return { limit: 'unlimited', used: 0, unlimited: true };
        const pricingDoc = await getPricingDoc();
        const currentPlan = user.currentPlan || 'free-trial';
        const planDetails = (pricingDoc.plans && pricingDoc.plans[currentPlan]) ? pricingDoc.plans[currentPlan] : DEFAULT_PLANS[currentPlan] || DEFAULT_PLANS['free-trial'];
        const linkLimit = planDetails.linkLimit;
        const userRegex = new RegExp('^' + (user.name || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
        const usedCount = await Link.countDocuments({ $or: [{ assignedUser: userRegex }, { userName: userRegex }, { creator: userRegex }, { name: userRegex }] });
        return { limit: isUnlimited(linkLimit) ? 'unlimited' : linkLimit, used: usedCount, unlimited: isUnlimited(linkLimit), planKey: currentPlan };
    } catch(e) { return { limit: 0, used: 0, unlimited: false, error: e.message }; }
}

async function canUserGetVisitor(user) {
    try {
        if (user.lifetimeUnlimited === true) return { allowed: true, totalVisitors: 0, limit: 'unlimited', lifetimeUnlimited: true };
        if (isPlanExpired(user)) return { allowed: false, totalVisitors: 0, limit: 0, reason: 'PLAN_EXPIRED' };
        const pricingDoc = await getPricingDoc();
        const planKey = user.currentPlan || 'free-trial';
        const plan = getPlanDetails(pricingDoc, planKey);
        const visitorLimit = plan.visitorLimit;
        if (isUnlimited(visitorLimit)) return { allowed: true, limit: 'unlimited' };
        const userRegex = new RegExp('^' + (user.name || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
        const userLinks = await Link.find({ $or: [{ assignedUser: userRegex }, { userName: userRegex }, { creator: userRegex }, { name: userRegex }] }).lean();
        const totalVisitors = userLinks.reduce((sum, l) => sum + (parseInt(l.visits) || 0), 0);
        if (totalVisitors >= visitorLimit) return { allowed: false, totalVisitors, limit: visitorLimit, reason: 'VISITOR_LIMIT_REACHED' };
        return { allowed: true, totalVisitors, limit: visitorLimit };
    } catch(e) { return { allowed: true }; }
}

// ==================== USER LOOKUP ====================
async function findRenewalUserByIdentifiers({ userId, userEmail, userName }) {
    let user = null;
    if (userId && mongoose.Types.ObjectId.isValid(userId)) { user = await RenewalUser.findById(userId); if (user) return user; }
    if (userEmail) { const cleanEmail = userEmail.toString().trim().toLowerCase(); if (cleanEmail) { user = await RenewalUser.findOne({ email: cleanEmail }); if (user) return user; } }
    if (userName) { const cleanName = userName.toString().trim(); if (cleanName && cleanName !== 'undefined') { user = await RenewalUser.findOne({ name: new RegExp('^' + cleanName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i') }); if (user) return user; } }
    return null;
}

async function autoFixUserFields(user) {
    if (!user) return null;
    const updates = {};
    let needsUpdate = false;
    if (!user.name || user.name.trim() === '' || user.name === 'undefined') { const emailPrefix = (user.email || '').split('@')[0] || 'User'; updates.name = emailPrefix.charAt(0).toUpperCase() + emailPrefix.slice(1); needsUpdate = true; }
    if (user.phone === undefined || user.phone === null) { updates.phone = ''; needsUpdate = true; }
    if (!user.status || user.status === 'undefined') { updates.status = 'pending'; needsUpdate = true; }
    if (user.currentPlan === undefined || user.currentPlan === null || user.currentPlan === '') { updates.currentPlan = 'none'; needsUpdate = true; }
    if (user.lifetimeUnlimited === undefined || user.lifetimeUnlimited === null) { updates.lifetimeUnlimited = false; needsUpdate = true; }
    if (user.freeTrialUsed === undefined || user.freeTrialUsed === null) { updates.freeTrialUsed = false; needsUpdate = true; }
    if (user.profileCompleted === undefined || user.profileCompleted === null) { updates.profileCompleted = !!(user.name && user.phone && user.phone.length >= 10); needsUpdate = true; }
    if (needsUpdate) { await RenewalUser.collection.updateOne({ _id: user._id }, { $set: updates }); return await RenewalUser.findById(user._id); }
    return user;
}

async function autoActivateFreeTrialIfNeeded(user) {
    if (!user) return user;
    if (user.lifetimeUnlimited === true) {
        if (user.currentPlan !== 'lifetime-unlimited') { await RenewalUser.collection.updateOne({ _id: user._id }, { $set: { currentPlan: 'lifetime-unlimited', status: 'approved' } }); user.currentPlan = 'lifetime-unlimited'; user.status = 'approved'; }
        return user;
    }
    const planExpiryDate = user.planExpiryDate ? new Date(user.planExpiryDate) : null;
    const now = new Date();
    const planNotExpired = planExpiryDate ? (planExpiryDate > now) : false;
    const userCurrentPlan = (user.currentPlan || 'none').toString().trim();
    const hasPlanKey = userCurrentPlan && userCurrentPlan !== 'none' && userCurrentPlan !== 'no-plan';
    if (hasPlanKey && planNotExpired) return user;
    if (user.freeTrialUsed === true) return user;
    if (user.status === 'approved' && !hasPlanKey) {
        const pricingDoc = await getPricingDoc();
        const ftPlan = getPlanDetails(pricingDoc, 'free-trial');
        const planStart = new Date();
        const planExpiry = new Date();
        planExpiry.setDate(planExpiry.getDate() + (ftPlan.durationDays || 3));
        await RenewalUser.collection.updateOne({ _id: user._id }, { $set: { currentPlan: 'free-trial', planStartDate: planStart, planExpiryDate: planExpiry, lifetimeUnlimited: false, freeTrialUsed: true, freeTrialActivatedAt: planStart, status: 'approved' } });
        return await RenewalUser.findById(user._id);
    }
    return user;
}

// ==================== Database Init ====================
async function initializeDatabase() {
    try {
        const activeEnvPass = process.env.ADMIN_PASSCODE ? process.env.ADMIN_PASSCODE.toString().trim() : DEFAULT_PASSCODE;
        let admin = await User.findOne();
        if (!admin) {
            const hashedPasscode = bcrypt.hashSync(activeEnvPass, 10);
            await User.create({ passcode: hashedPasscode, lastEnvPasscode: activeEnvPass, theme: 'dark', email: process.env.ADMIN_EMAIL || '', phone: process.env.ADMIN_PHONE || '', secretKey: 'admin@2024' });
        } else if (process.env.ADMIN_PASSCODE && admin.lastEnvPasscode !== activeEnvPass) {
            admin.passcode = bcrypt.hashSync(activeEnvPass, 10); admin.lastEnvPasscode = activeEnvPass; await admin.save();
        }
        const statsExists = await Stats.findOne();
        if (!statsExists) await Stats.create({});
        const popupExists = await PopupSettings.findOne();
        if (!popupExists) await PopupSettings.create({ image: null, title: '🎁 Claim Your Reward', buttonText: 'Claim Now', subtitle: 'Tap below to unlock your reward', uidChecking: true });
        await getPricingDoc();
        if (Session) await Session.deleteMany({ expiresAt: { $lt: new Date() } }).catch(() => {});
        try {
            const usersWithMissingPhone = await RenewalUser.collection.updateMany({ phone: { $exists: false } }, { $set: { phone: '' } });
            if (usersWithMissingPhone.modifiedCount > 0) console.log(`🔧 Migration: Fixed ${usersWithMissingPhone.modifiedCount} users with missing phone field`);
        } catch(e) {}
    } catch (error) { console.error('❌ Database initialization error:', error); }
}

async function startServer() {
    try {
        await connectDB();
        await initializeDatabase();
        app.listen(port, '0.0.0.0', () => { console.log(`🚀 Server running on port ${port}`); console.log(`📧 Email: ${process.env.SENDER_EMAIL ? '✅ Configured' : '❌ NOT CONFIGURED'}`); });
    } catch (err) { console.error('❌ Failed to start server:', err.message); process.exit(1); }
}
startServer();

// ==================== MIDDLEWARE ====================
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use((req, res, next) => { res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin'); res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups'); next(); });
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
                if (key.startsWith('$') || key.includes('..') || key === '__proto__' || key === 'constructor' || key === 'prototype') { delete obj[key]; continue; }
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
    const blocked = ['.env', '.log', '.json', '.md'];
    const p = req.path.toLowerCase();
    if (p === '/manifest.json') return next();
    for (let ext of blocked) { if (p.endsWith(ext)) return res.status(403).send('Forbidden'); }
    next();
});

const csrfSecret = process.env.CSRF_SECRET || 'change-this-csrf-secret-32-chars-minimum-xyz-123';
const { generateToken: generateCsrfToken } = doubleCsrf({
    getSecret: () => csrfSecret, cookieName: 'csrf-token',
    cookieOptions: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/' },
    size: 64, ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
    getTokenFromRequest: (req) => req.headers['x-csrf-token'] || req.body?._csrf
});

app.get('/api/csrf-token', (req, res) => { try { const token = generateCsrfToken(req, res); res.json({ csrfToken: token }); } catch(e) { res.status(500).json({ error: 'Failed to generate token' }); } });

// ========== RATE LIMITERS ==========
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: parseInt(process.env.RATE_LIMIT_MAX) || 500, standardHeaders: true, legacyHeaders: false, skip: (req) => (req.path === '/health' || req.path === '/ping' || req.path.endsWith('.css') || req.path.endsWith('.js') || req.path.endsWith('.png') || req.path.endsWith('.jpg') || req.path.endsWith('.ico')), message: { error: 'Too many requests. Please try again later.' } });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, skipSuccessfulRequests: true, message: { error: 'Too many login attempts. Please wait 15 minutes.' } });
const otpSendLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 3, keyGenerator: (req) => 'otp_' + (req.headers['x-forwarded-for']?.toString().split(',')[0] || req.ip || 'unknown'), message: { error: 'Too many OTP requests. Maximum 3 per hour. Please try again later.' }, standardHeaders: true, legacyHeaders: false });
const profileLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 25, message: { error: 'Too many profile submissions. Please wait.' } });
const createLinkLimiter = rateLimit({ windowMs: 60 * 1000, max: 20, keyGenerator: (req) => req.body?.userName || req.body?.userEmail || req.ip, message: { error: 'Too many link creations. Please wait a moment.' } });
const userApiLimiter = rateLimit({ windowMs: 60 * 1000, max: 100, keyGenerator: (req) => req.body?.userName || req.body?.userEmail || req.ip, message: { error: 'Too many requests. Please slow down.' } });
const claimLimiter = rateLimit({ windowMs: 60 * 1000, max: 30 });

app.use('/api', globalLimiter);

app.get('/health', (req, res) => { const dbState = mongoose.connection.readyState; const dbStatus = dbState === 1 ? 'connected' : dbState === 2 ? 'connecting' : dbState === 3 ? 'disconnecting' : 'disconnected'; res.status(dbState === 1 ? 200 : 503).json({ status: dbState === 1 ? 'healthy' : 'unhealthy', database: dbStatus, uptime: Math.floor(process.uptime()), environment: process.env.NODE_ENV || 'development', emailConfigured: !!process.env.SENDER_EMAIL, timestamp: new Date().toISOString() }); });
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
        Session.findOneAndUpdate({ $or: [{ deviceKey }, { fingerprint }, { ip }] }, { $set: { lastActivity: new Date(), isActive: true, ip, deviceName, deviceType }, $setOnInsert: { userId: 'admin', deviceKey, fingerprint, createdAt: new Date(), expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000) } }, { upsert: true }).catch(() => {});
    }
    next();
}

// ==================== ROUTES ====================
app.get(['/admin/unblock-all', '/api/admin/unblock-all'], async (req, res) => { res.status(403).send(`<!DOCTYPE html><html><head><title>Forbidden</title><style>body{background:#090a10;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center;padding:20px;margin:0;}.card{background:#131722;padding:40px;border-radius:20px;border:1px solid rgba(239,68,68,0.4);max-width:450px;}h1{color:#ef4444;font-size:22px;margin-bottom:10px;}p{color:#94a3b8;font-size:14px;line-height:1.6;}</style></head><body><div class="card"><h1>⛔ ACCESS DENIED</h1><p>Only an authorized administrator can unblock devices.</p></div></body></html>`); });

app.get('/api/pricing', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
        const pricingDoc = await getPricingDoc();
        const publicPlans = {};
        for (const [key, plan] of Object.entries(pricingDoc.plans || {})) { if (plan && plan.enabled !== false) publicPlans[key] = plan; }
        res.json({ plans: publicPlans, paymentSettings: { method: pricingDoc.paymentSettings?.method || 'UPI', showUpi: pricingDoc.paymentSettings?.showUpi !== false, details: pricingDoc.paymentSettings?.details || { upiId: 'admin@upi' } }, whatsappNumber: pricingDoc.whatsappNumber || '916372923348', supportEmail: pricingDoc.supportEmail || '', autoPaymentEnabled: false });
    } catch (error) { res.status(500).json({ error: 'Failed' }); }
});

// ==================== AUTH ROUTES ====================
app.post('/api/auth/send-otp', otpSendLimiter, async (req, res) => {
    try {
        const { email, purpose, name, phone } = req.body;
        if (!email) return res.status(400).json({ error: 'Email is required' });
        const cleanEmail = email.toString().trim().toLowerCase();
        if (!isValidEmailFormat(cleanEmail)) return res.status(400).json({ error: 'Invalid email format' });
        if (isDisposableEmail(cleanEmail)) return res.status(400).json({ error: 'Disposable / temporary emails are not allowed. Please use a valid email.' });
        if (!process.env.SENDER_EMAIL || !process.env.SENDER_APP_PASSWORD) return res.status(500).json({ error: 'Email service not configured. Contact admin.' });
        const mode = (purpose || 'signin').toString().toLowerCase();

        if (mode === 'signup') {
            if (!name || name.trim().length < 2) return res.status(400).json({ error: 'Please enter your full name' });
            if (!phone || !isValidMobile(phone)) return res.status(400).json({ error: 'Please enter a valid 10-digit mobile number' });
            const cleanPhone = phone.trim();
            const existingUser = await RenewalUser.findOne({ email: cleanEmail });
            if (existingUser) return res.status(400).json({ error: 'This email is already registered. Please Sign In instead.', alreadyRegistered: true });
            const phoneExists = await RenewalUser.findOne({ phone: cleanPhone });
            if (phoneExists) return res.status(400).json({ error: 'This phone number is already registered.' });
        }

        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        const recentOtpCount = await Otp.countDocuments({ email: cleanEmail, createdAt: { $gte: oneHourAgo } });
        if (recentOtpCount >= 3) return res.status(429).json({ error: 'Too many OTP requests. Please wait 1 hour.' });

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 60 * 1000);

        await Otp.updateMany({ email: cleanEmail, verified: false }, { $set: { verified: true } });
        await Otp.create({ email: cleanEmail, otp: otpCode, purpose: mode === 'signup' ? 'signup' : 'signin', expiresAt });

        const result = await emailHelper.sendOtpEmail(cleanEmail, otpCode, mode, 60);
        if (!result.success) return res.status(500).json({ error: 'Failed to send OTP email. Please try again.' });
        res.json({ success: true, message: 'OTP sent to your email', spamWarning: true });
    } catch (err) { res.status(500).json({ error: 'Failed to send OTP: ' + err.message }); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp, purpose, name, phone } = req.body;
        if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required' });
        const cleanEmail = email.toString().trim().toLowerCase();
        const cleanOtp = otp.toString().trim();
        if (!/^\d{6}$/.test(cleanOtp)) return res.status(400).json({ error: 'OTP must be 6 digits' });

        const otpRecord = await Otp.findOne({ email: cleanEmail, verified: false, expiresAt: { $gt: new Date() } }).sort({ createdAt: -1 });
        if (!otpRecord) return res.status(400).json({ error: 'OTP expired or not found. Please request a new one.' });
        if (otpRecord.attempts >= 5) { await Otp.updateOne({ _id: otpRecord._id }, { $set: { verified: true } }); return res.status(400).json({ error: 'Too many wrong attempts. Please request a new OTP.' }); }
        if (otpRecord.otp !== cleanOtp) { await Otp.updateOne({ _id: otpRecord._id }, { $inc: { attempts: 1 } }); return res.status(400).json({ error: `Invalid OTP. ${4 - otpRecord.attempts} attempts remaining.` }); }
        await Otp.updateOne({ _id: otpRecord._id }, { $set: { verified: true } });

        const cleanName = name.trim();
        const cleanPhone = phone.trim();
        const existing = await RenewalUser.findOne({ email: cleanEmail });
        if (existing) return res.status(400).json({ error: 'Email already registered. Please Sign In.', alreadyRegistered: true });

        const user = await RenewalUser.create({ name: cleanName, email: cleanEmail, phone: cleanPhone, googleId: null, authMethod: 'otp', status: 'pending', currentPlan: 'none', lifetimeUnlimited: false, freeTrialUsed: false, profileCompleted: true, createdAt: new Date() });
        emailHelper.sendWelcomeEmail(cleanEmail, cleanName).catch(() => {});
        res.json({ success: true, needsApproval: true, hoursRemaining: 24, user: { id: user._id, email: user.email, name: user.name, phone: user.phone, status: 'pending' } });
    } catch (err) { res.status(500).json({ error: 'Verification failed: ' + err.message }); }
});

app.post('/api/auth/direct-signin', async (req, res) => {
    try {
        const { email, phone } = req.body;
        if (!email || !phone) return res.status(400).json({ error: 'Email and phone are required' });
        const cleanEmail = email.toString().trim().toLowerCase();
        const cleanPhone = phone.toString().trim();
        let user = await RenewalUser.findOne({ email: cleanEmail });
        if (!user) return res.status(404).json({ error: 'No account found with this email. Please Sign Up first.' });
        user = await autoFixUserFields(user);
        if (user.status === 'rejected') return res.status(403).json({ error: 'Your account has been rejected. Contact support.' });
        if (user.phone !== cleanPhone) return res.status(401).json({ error: 'Phone number does not match our records.' });
        if (user.status === 'pending') {
            const createdAt = user.createdAt ? new Date(user.createdAt).getTime() : Date.now();
            const hoursElapsed = (Date.now() - createdAt) / (1000 * 60 * 60);
            return res.json({ success: true, needsApproval: true, pendingHours: Math.floor(hoursElapsed), hoursRemaining: Math.max(0, 24 - Math.floor(hoursElapsed)), user: { id: user._id, email: user.email, name: user.name, phone: user.phone } });
        }
        user = await autoActivateFreeTrialIfNeeded(user);
        res.json({ success: true, needsApproval: false, user: { id: user._id, name: user.name, email: user.email, phone: user.phone, authMethod: 'otp', currentPlan: user.currentPlan, lifetimeUnlimited: user.lifetimeUnlimited === true, status: user.status } });
    } catch (err) { res.status(500).json({ error: 'Sign in failed: ' + err.message }); }
});

// ==================== LINK API ====================
app.get('/api/link/:id', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
        let rawId = extractCleanId(req.params.id);
        let link = await Link.collection.findOne(getLinkQuery(rawId));
        if (!link && (rawId === 'default' || !rawId)) { const allActive = await Link.find({ status: 'active' }).sort({ created: -1 }).limit(1).lean(); link = allActive[0]; }
        if (!link) return res.status(404).json({ error: 'not_found', message: 'Link not found', expired: true });
        if (link.status === 'suspended' || link.status === 'disabled' || link.status === 'inactive') return res.status(403).json({ error: link.status, message: `Link ${link.status}`, status: link.status, expired: true });
        if (link.expiryDate && !isNaN(new Date(link.expiryDate).getTime()) && Date.now() > new Date(link.expiryDate).getTime()) return res.status(403).json({ error: 'expired', message: 'Link expired', status: 'expired', expired: true });
        const ownerName = link.assignedUser || link.userName || link.name || link.creator;
        if (ownerName) {
            const ownerUser = await RenewalUser.findOne({ name: new RegExp('^' + ownerName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i') }).lean();
            if (!ownerUser) { await Link.collection.deleteOne({ _id: link._id }).catch(() => {}); return res.status(403).json({ error: 'owner_deleted', message: 'Owner removed', status: 'expired', expired: true }); }
            if (isPlanExpired(ownerUser)) return res.status(403).json({ error: 'plan_expired', message: 'Plan expired', status: 'expired', expired: true });
        }
        const { ip, deviceKey } = getDeviceId(req);
        const visitorKey = deviceKey || ip;
        const today = getISTDate();
        const recentUniqueVisit = await VisitorActivity.findOne({ linkId: { $in: [link.id, String(link._id), rawId] }, visitorKey, type: 'visit', lastSeen: { $gte: new Date(Date.now() - UNIQUE_WINDOW_MS) } }).maxTimeMS(1500).catch(() => null);
        if (!recentUniqueVisit) {
            await Link.collection.updateOne({ _id: link._id }, { $inc: { visits: 1, [`dailyVisits.${today}`]: 1 } }).catch(() => {});
            await Stats.collection.updateOne({}, { $inc: { totalVisitors: 1, [`dailyVisitors.${today}`]: 1 } }, { upsert: true }).catch(() => {});
        }
        await VisitorActivity.findOneAndUpdate({ linkId: link.id, visitorKey, type: 'visit' }, { $set: { lastSeen: new Date() } }, { upsert: true }).catch(() => {});
        const popup = link.popupSettings || {};
        const bannerImage = popup.image || link.image || null;
        res.json({ id: link.id, name: link.linkName || link.title || 'Untitled', video: link.video, claim: link.claim, buttonText: link.buttonText, headline: link.headline, status: link.status, expiryDate: link.expiryDate, expired: false, uidChecking: !isUidCheckDisabled(link.uidChecking), image: bannerImage, popupSettings: { image: bannerImage, title: popup.title || '🎁 Claim Your Reward', buttonText: popup.buttonText || 'Claim Now', subtitle: popup.subtitle || 'Tap below' } });
    } catch (error) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/submit-uid/:linkId', async (req, res) => {
    try {
        const { uid } = req.body;
        const cleanUid = (uid || '').toString().trim();
        if (!cleanUid || cleanUid.length < 5) return res.status(400).json({ error: 'Invalid UID' });
        const link = await Link.findOne(getLinkQuery(req.params.linkId));
        if (!link) return res.status(404).json({ error: 'Link not found' });
        const { ip, deviceKey } = getDeviceId(req);
        await VisitorActivity.findOneAndUpdate({ linkId: link.id, visitorKey: deviceKey || ip, type: 'visit' }, { $set: { lastSeen: new Date(), uid: cleanUid } }, { upsert: true }).catch(() => {});
        res.json({ success: true, message: 'UID submitted', uid: cleanUid });
    } catch (error) { res.status(500).json({ error: 'Failed' }); }
});

async function executeClaimTracking(rawLinkId, req) {
    const cleanId = extractCleanId(rawLinkId);
    if (!cleanId) return { success: false, error: 'Link ID missing' };
    const sourceParam = (req.query.source || req.body?.source || '').toString().toLowerCase().trim();
    if (sourceParam !== 'video') return { success: true, ignored: true };
    const link = await Link.findOne(getLinkQuery(cleanId));
    if (!link) return { success: false, error: 'Link not found' };
    const { ip, deviceKey } = getDeviceId(req);
    const visitorKey = deviceKey || ip;
    const today = getISTDate();
    const recentUniqueClaim = await VisitorActivity.findOne({ linkId: { $in: [link.id, String(link._id), cleanId] }, visitorKey, type: 'claim', source: 'video', lastSeen: { $gte: new Date(Date.now() - UNIQUE_WINDOW_MS) } }).maxTimeMS(1500).catch(() => null);
    if (!recentUniqueClaim) {
        await Link.collection.updateOne({ _id: link._id }, { $inc: { claims: 1, [`dailyClaims.${today}`]: 1 } }).catch(() => {});
        await Stats.collection.updateOne({}, { $inc: { totalClaims: 1, [`dailyClaims.${today}`]: 1 } }, { upsert: true }).catch(() => {});
    }
    await VisitorActivity.findOneAndUpdate({ linkId: link.id, visitorKey, type: 'claim' }, { $set: { lastSeen: new Date(), source: 'video' } }, { upsert: true }).catch(() => {});
    return { success: true, linkId: link.id, counted: !recentUniqueClaim };
}

const handleClaimTrackingRequest = async (req, res) => {
    try {
        let rawId = req.params.linkId || req.body?.linkId || req.body?.link;
        const result = await executeClaimTracking(rawId, req);
        if (result.success) return res.json({ success: true, linkId: result.linkId, ignored: !!result.ignored });
        else return res.status(404).json({ error: result.error });
    } catch(err) { return res.status(500).json({ error: 'Failed' }); }
};

app.post('/api/track-claim/:linkId', claimLimiter, handleClaimTrackingRequest);
app.post('/api/track-claim', claimLimiter, handleClaimTrackingRequest);
app.all('/api/claim/:linkId', claimLimiter, handleClaimTrackingRequest);

app.get('/api/renewal/history/:linkId', async (req, res) => { try { const history = await RenewalRequest.find({ linkId: req.params.linkId }).sort({ createdAt: -1 }).limit(7).lean(); res.json({ history, count: history.length }); } catch (error) { res.status(500).json({ error: 'Failed' }); } });
app.get('/api/settings', async (req, res) => { try { const admin = await User.findOne().lean(); const popupSettings = await PopupSettings.findOne().lean(); const pricingDoc = await getPricingDoc(); res.json({ theme: admin?.theme || 'dark', background: popupSettings?.image || null, whatsappNumber: pricingDoc?.whatsappNumber || '916372923348' }); } catch (error) { res.status(500).json({ error: 'Failed' }); } });

app.post('/api/user/verify-session', userApiLimiter, async (req, res) => {
    try {
        const { userName, userId, userEmail } = req.body;
        const user = await findRenewalUserByIdentifiers({ userId, userEmail, userName });
        if (!user) return res.status(404).json({ success: false, deleted: true });
        if (user.status === 'rejected') return res.status(403).json({ success: false, deleted: true });
        if (user.status === 'pending') { const hoursElapsed = (Date.now() - new Date(user.createdAt).getTime()) / (1000 * 60 * 60); return res.json({ success: true, needsApproval: true, hoursRemaining: Math.max(0, 24 - Math.floor(hoursElapsed)) }); }
        res.json({ success: true, user: { id: user._id, name: user.name, status: user.status, currentPlan: user.currentPlan, lifetimeUnlimited: user.lifetimeUnlimited === true } });
    } catch(e) { res.status(500).json({ error: 'Verification failed' }); }
});

app.post('/api/user/select-free-plan', userApiLimiter, async (req, res) => {
    try {
        const { userName, userEmail, userId } = req.body;
        const user = await findRenewalUserByIdentifiers({ userId, userEmail, userName });
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.status === 'pending') return res.status(403).json({ error: 'Account pending approval.' });
        if (user.lifetimeUnlimited === true) return res.status(403).json({ error: 'Lifetime unlimited active.' });
        if (user.freeTrialUsed === true) return res.status(403).json({ error: 'Free trial already used.' });
        const pricingDoc = await getPricingDoc();
        const ftPlan = getPlanDetails(pricingDoc, 'free-trial');
        const planExpiry = new Date(); planExpiry.setDate(planExpiry.getDate() + (ftPlan.durationDays || 3));
        await RenewalUser.collection.updateOne({ _id: user._id }, { $set: { currentPlan: 'free-trial', planStartDate: new Date(), planExpiryDate: planExpiry, lifetimeUnlimited: false, freeTrialUsed: true, status: 'approved', approvedAt: user.approvedAt || new Date() } });
        res.json({ success: true, message: 'Free trial activated!', user: { currentPlan: 'free-trial', planExpiryDate: planExpiry } });
    } catch (e) { res.status(500).json({ error: 'Failed: ' + e.message }); }
});

app.post('/api/user/create-link', createLinkLimiter, async (req, res) => {
    try {
        const { userName, userEmail, userId, linkName, video, claim, buttonText, headline, uidChecking, popupTitle, popupSubtitle, popupButtonText, popupImage } = req.body;
        let user = await findRenewalUserByIdentifiers({ userId, userEmail, userName });
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.status === 'pending') return res.status(403).json({ error: 'Account pending approval.', reason: 'PENDING_APPROVAL' });
        user = await autoFixUserFields(user); user = await autoActivateFreeTrialIfNeeded(user);
        const isLifetimeUnlimited = user.lifetimeUnlimited === true;
        const hasPlan = isLifetimeUnlimited || (user.currentPlan !== 'none' && new Date(user.planExpiryDate) > new Date());
        if (!hasPlan) return res.status(403).json({ error: 'No active plan', reason: 'NO_PLAN' });
        const pricingDoc = await getPricingDoc();
        const plan = getPlanDetails(pricingDoc, user.currentPlan);
        const linkLimit = isLifetimeUnlimited ? 'unlimited' : plan.linkLimit;
        const userRegex = new RegExp('^' + (user.name || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
        const count = await Link.countDocuments({ $or: [{ assignedUser: userRegex }, { userName: userRegex }, { creator: userRegex }] });
        if (!isLifetimeUnlimited && !isUnlimited(linkLimit) && count >= linkLimit) return res.status(403).json({ error: `Limit reached (${count}/${linkLimit})`, reason: 'LINK_LIMIT_REACHED' });
        const linkId = 'link_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex');
        const linkExpiry = isLifetimeUnlimited ? null : new Date(user.planExpiryDate);
        const cleanImage = popupImage && popupImage.trim().length > 4 ? popupImage.trim() : null;
        await Link.collection.insertOne({ id: linkId, name: user.name, userName: user.name, assignedUser: user.name, creator: user.name, linkName: linkName || 'My Link', title: linkName || 'My Link', video: video || 'https://youtu.be/dQw4w9WgXcQ', claim: claim || '#', buttonText: buttonText || 'Claim Now', headline: headline || 'Watch Video', expiryDate: linkExpiry, uidChecking: !isUidCheckDisabled(uidChecking), status: 'active', claims: 0, visits: 0, dailyClaims: {}, dailyVisits: {}, image: cleanImage, popupImage: cleanImage, popupSettings: { title: popupTitle, subtitle: popupSubtitle, buttonText: popupButtonText, image: cleanImage }, created: new Date() });
        if (user.email) { const fullUrl = `${process.env.APP_URL || 'http://localhost:3001'}/uid?link=${linkId}`; emailHelper.sendLinkCreatedEmail(user.email, user.name, linkName, fullUrl).catch(() => {}); }
        res.json({ success: true, message: 'Link created!', link: { id: linkId, linkName } });
    } catch (e) { res.status(500).json({ error: 'Failed: ' + e.message }); }
});

app.post('/api/user/link-details', userApiLimiter, async (req, res) => {
    try {
        const { userName, userEmail, userId, linkInput, filter, startDate, endDate } = req.body;
        let user = await findRenewalUserByIdentifiers({ userId, userEmail, userName });
        if (!user) return res.status(404).json({ success: false, deleted: true });
        if (user.status === 'pending') return res.status(403).json({ success: false, pendingApproval: true });
        user = await autoFixUserFields(user); user = await autoActivateFreeTrialIfNeeded(user); user = await RenewalUser.findById(user._id).lean();
        const userRegex = new RegExp('^' + user.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
        const allUserLinks = await Link.find({ $or: [{ assignedUser: userRegex }, { userName: userRegex }] }).sort({ created: -1 }).lean();
        const link = allUserLinks.find(l => l.id === linkInput) || allUserLinks[0];
        const pricingDoc = await getPricingDoc();
        const isLifetimeUnlimited = user.lifetimeUnlimited === true;
        const hasPlan = isLifetimeUnlimited || (user.currentPlan !== 'none' && new Date(user.planExpiryDate) > new Date());
        const plan = getPlanDetails(pricingDoc, hasPlan ? user.currentPlan : 'free-trial');
        let planDaysLeft = 0;
        if (user.planExpiryDate && hasPlan && !isLifetimeUnlimited) planDaysLeft = Math.max(0, Math.ceil((new Date(user.planExpiryDate) - new Date()) / (1000 * 60 * 60 * 24)));
        const planUsage = { planKey: isLifetimeUnlimited ? 'lifetime-unlimited' : (hasPlan ? user.currentPlan : 'no-plan'), planName: isLifetimeUnlimited ? 'Lifetime Unlimited' : plan.name, linkLimit: isLifetimeUnlimited ? 'unlimited' : plan.linkLimit, linksUsed: allUserLinks.length, linksRemaining: isLifetimeUnlimited ? 'unlimited' : Math.max(0, plan.linkLimit - allUserLinks.length), planExpiryDate: user.planExpiryDate, planStartDate: user.planStartDate, lifetimeUnlimited: isLifetimeUnlimited, planDaysLeft: isLifetimeUnlimited ? 'lifetime' : planDaysLeft, freeTrialUsed: user.freeTrialUsed === true, features: plan.features, price: plan.price };
        if (!link) return res.status(404).json({ success: false, hasAnyLink: false, planUsage, plans: pricingDoc.plans });
        res.json({ success: true, hasAnyLink: true, link: { id: link.id, name: link.linkName || link.title, created: link.created, expiryDate: link.expiryDate, daysLeft: planDaysLeft, totalVisits: link.visits, totalClaims: link.claims, isExpired: link.expiryDate && new Date(link.expiryDate) < new Date() }, userLinks: allUserLinks.map(l => ({ id: l.id, name: l.linkName, title: l.title, linkName: l.linkName })), planUsage, plans: pricingDoc.plans, paymentSettings: { details: pricingDoc.paymentSettings?.details, showUpi: pricingDoc.paymentSettings?.showUpi } });
    } catch (e) { res.status(500).json({ error: 'Failed: ' + e.message }); }
});

app.delete('/api/user/delete-link/:linkId', userApiLimiter, async (req, res) => {
    try {
        const { userName, userEmail, userId } = req.body;
        const user = await findRenewalUserByIdentifiers({ userId, userEmail, userName });
        if (!user) return res.status(404).json({ error: 'User not found' });
        const link = await Link.findOne(getLinkQuery(req.params.linkId)).lean();
        if (!link || (link.assignedUser || '').toLowerCase() !== user.name.toLowerCase()) return res.status(403).json({ error: 'Not your link' });
        await RenewalRequest.deleteMany({ linkId: link.id }); await VisitorActivity.deleteMany({ linkId: link.id });
        await Link.deleteOne({ _id: link._id });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/user/renew-payment', userApiLimiter, async (req, res) => {
    try {
        const { linkId, linkName, plan, days, amount, refNo, userName, userEmail, userId } = req.body;
        if (!plan) return res.status(400).json({ error: 'Plan required' });
        const user = await findRenewalUserByIdentifiers({ userId, userEmail, userName });
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.status === 'pending') return res.status(403).json({ error: 'Account pending approval.' });
        if (user.currentPlan && user.currentPlan !== 'none' && !isPlanExpired(user)) { const purchaseCheck = canUserPurchasePlan(user, plan); if (!purchaseCheck.allowed) return res.status(403).json({ error: purchaseCheck.message }); }
        const finalLinkId = linkId || 'pending_' + user._id;
        const finalLinkName = linkName || `${user.name} (New User)`;
        await RenewalRequest.create({ id: 'req_' + Date.now(), linkId: finalLinkId, linkName: finalLinkName, plan, days: parseInt(days) || 30, amount: parseInt(amount) || 0, transactionId: refNo || 'Manual', status: 'pending' });
        res.json({ success: true, message: 'Renewal request submitted.' });
    } catch (e) { res.status(500).json({ error: 'Failed: ' + e.message }); }
});

app.get('/api/user/short-links', userApiLimiter, async (req, res) => { try { const { userName, userEmail, userId } = req.query; const user = await findRenewalUserByIdentifiers({ userId, userEmail, userName }); if (!user) return res.json({ success: true, links: [] }); const links = await ShortLink.find({ creator: user.name }).sort({ createdAt: -1 }).lean(); res.json({ success: true, links }); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.post('/api/user/short-links', userApiLimiter, async (req, res) => { try { const { originalUrl, title, userName, userEmail, userId, appScheme } = req.body; if (!originalUrl) return res.status(400).json({ error: 'URL required' }); const user = await findRenewalUserByIdentifiers({ userId, userEmail, userName }); if (!user) return res.status(404).json({ error: 'User not found' }); const link = new ShortLink({ code: Math.random().toString(36).substring(2, 8), originalUrl, title: title || 'Untitled', creator: user.name, appOpen: !!appScheme, appScheme: appScheme || '' }); await link.save(); res.json({ success: true, link, shortUrl: `${req.protocol}://${req.get('host')}/s/${link.code}` }); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.delete('/api/user/short-links/:id', userApiLimiter, async (req, res) => { try { await ShortLink.findByIdAndDelete(req.params.id); await ShortLinkClick.deleteMany({ shortLinkId: req.params.id }).catch(() => {}); res.json({ success: true }); } catch(e) { res.status(500).json({ error: 'Failed' }); } });

app.get('/api/admin/all-users', authMiddleware, async (req, res) => {
    try {
        const users = await RenewalUser.find().sort({ createdAt: -1 }).lean();
        const links = await Link.find().lean();
        const pricingDoc = await getPricingDoc();
        const usersWithStats = users.map(u => {
            const cleanName = (u.name || '').toLowerCase().trim();
            const userLinks = links.filter(l => { const ln = (l.name || '').toLowerCase().trim(); const au = (l.assignedUser || '').toLowerCase().trim(); const un = (l.userName || '').toLowerCase().trim(); const cr = (l.creator || '').toLowerCase().trim(); return ln === cleanName || au === cleanName || un === cleanName || cr === cleanName; });
            const totalVisits = userLinks.reduce((sum, l) => sum + (parseInt(l.visits) || 0), 0);
            const totalClaims = userLinks.reduce((sum, l) => sum + (parseInt(l.claims) || 0), 0);
            const waData = generateWhatsAppApprovalData(u, req);
            const plan = getPlanDetails(pricingDoc, u.currentPlan || 'free-trial');
            const isLifetimeUnlimited = u.lifetimeUnlimited === true;
            const linkLimit = isLifetimeUnlimited ? 'unlimited' : plan.linkLimit;
            const linksRemaining = (isLifetimeUnlimited || isUnlimited(linkLimit)) ? 'unlimited' : Math.max(0, linkLimit - userLinks.length);
            return { ...u, totalLinks: userLinks.length, totalVisits, totalClaims, lifetimeUnlimited: isLifetimeUnlimited, currentPlanName: isLifetimeUnlimited ? 'Lifetime Unlimited' : plan.name, planLimit: linkLimit, visitorLimit: isLifetimeUnlimited ? 'unlimited' : plan.visitorLimit, linksRemaining, whatsappMessage: waData.message, whatsappUrl: waData.whatsappUrl, portalLoginUrl: waData.loginUrl };
        });
        res.json({ success: true, users: usersWithStats, totalUsers: users.length });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/users/:id/whatsapp-approval', authMiddleware, async (req, res) => { try { const userId = req.params.id; const userQuery = mongoose.Types.ObjectId.isValid(userId) ? { _id: userId } : { id: userId }; const user = await RenewalUser.findOne(userQuery).lean(); if (!user) return res.status(404).json({ error: 'User not found' }); const waData = generateWhatsAppApprovalData(user, req); res.json({ success: true, user, ...waData }); } catch(e) { res.status(500).json({ error: 'Failed' }); } });

app.delete('/api/admin/users/:id', authMiddleware, async (req, res) => {
    try {
        const userId = req.params.id;
        const userQuery = mongoose.Types.ObjectId.isValid(userId) ? { _id: userId } : { id: userId };
        const user = await RenewalUser.findOne(userQuery).lean();
        if (!user) return res.status(404).json({ error: 'User not found' });
        const userName = user.name || '';
        let linksDeleted = 0, renewalReqsDeleted = 0, shortLinksDeleted = 0, visitorActivityDeleted = 0;
        if (userName) {
            const userRegex = new RegExp('^' + userName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
            const userLinks = await Link.find({ $or: [{ assignedUser: userRegex }, { userName: userRegex }, { creator: userRegex }, { name: userRegex }] }).lean();
            const linkIds = userLinks.map(l => l.id).filter(Boolean);
            if (linkIds.length > 0) { const renewalRes = await RenewalRequest.deleteMany({ $or: [{ linkId: { $in: linkIds } }, { linkName: userRegex }] }); renewalReqsDeleted = renewalRes.deletedCount || 0; const visitorRes = await VisitorActivity.deleteMany({ linkId: { $in: linkIds } }); visitorActivityDeleted = visitorRes.deletedCount || 0; }
            const shortRes = await ShortLink.deleteMany({ creator: userRegex }); shortLinksDeleted = shortRes.deletedCount || 0;
            const linkRes = await Link.deleteMany({ $or: [{ assignedUser: userRegex }, { userName: userRegex }, { creator: userRegex }, { name: userRegex }] }); linksDeleted = linkRes.deletedCount || 0;
        }
        await RenewalUser.deleteOne({ _id: user._id });
        res.json({ success: true, message: `User "${userName}" deleted.`, stats: { linksDeleted, renewalReqsDeleted, visitorActivityDeleted, shortLinksDeleted } });
    } catch (e) { res.status(500).json({ error: 'Failed: ' + e.message }); }
});

app.post('/api/admin/users/:id/lifetime-unlimited', authMiddleware, async (req, res) => {
    try {
        const { enable } = req.body;
        const userId = req.params.id;
        const userQuery = mongoose.Types.ObjectId.isValid(userId) ? { _id: new mongoose.Types.ObjectId(userId) } : { id: userId };
        const user = await RenewalUser.findOne(userQuery).lean();
        if (!user) return res.status(404).json({ error: 'User not found' });
        const $set = {};
        if (enable === true) { $set.lifetimeUnlimited = true; $set.currentPlan = 'lifetime-unlimited'; $set.status = 'approved'; $set.planStartDate = user.planStartDate || new Date(); $set.planExpiryDate = null; $set.profileCompleted = true; if (!user.approvedAt) $set.approvedAt = new Date(); if (user.phone === undefined || user.phone === null) $set.phone = ''; if (!user.name) { const emailPrefix = (user.email || '').split('@')[0] || 'User'; $set.name = emailPrefix.charAt(0).toUpperCase() + emailPrefix.slice(1); } }
        else { $set.lifetimeUnlimited = false; if (user.currentPlan === 'lifetime-unlimited') { $set.currentPlan = 'none'; $set.planExpiryDate = null; $set.planStartDate = null; } }
        await RenewalUser.collection.updateOne({ _id: user._id }, { $set: $set });
        if (enable === true) { const userRegex = new RegExp('^' + (user.name || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i'); await Link.collection.updateMany({ $or: [{ assignedUser: userRegex }, { userName: userRegex }, { creator: userRegex }, { name: userRegex }] }, { $set: { expiryDate: null, status: 'active' } }); }
        res.json({ success: true, message: enable ? 'User set to Lifetime Unlimited!' : 'Lifetime removed' });
    } catch (e) { res.status(500).json({ error: 'Failed: ' + e.message }); }
});

app.get('/api/admin/renewal-users', authMiddleware, async (req, res) => { try { const users = await RenewalUser.find().sort({ createdAt: -1 }).lean(); const usersWithWa = users.map(u => ({ ...u, ...generateWhatsAppApprovalData(u, req) })); res.json({ success: true, users: usersWithWa }); } catch (e) { res.status(500).json({ error: 'Failed' }); } });

const handleUserApprovalAction = async (req, res) => {
    try {
        const { action } = req.body;
        const targetAction = (action || 'approved').toString().trim().toLowerCase();
        const userId = req.params.id;
        const userQuery = mongoose.Types.ObjectId.isValid(userId) ? { _id: userId } : { id: userId };
        const user = await RenewalUser.findOne(userQuery);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const $set = { status: targetAction };
        if (targetAction === 'approved') {
            $set.approvedAt = user.approvedAt || new Date(); $set.profileCompleted = true;
            if (user.phone === undefined || user.phone === null) $set.phone = '';
            if (!user.name) { const emailPrefix = (user.email || '').split('@')[0] || 'User'; $set.name = emailPrefix.charAt(0).toUpperCase() + emailPrefix.slice(1); }
            const hasNoPlan = !user.currentPlan || user.currentPlan === 'none' || user.currentPlan === 'no-plan';
            const planIsExpired = user.planExpiryDate && new Date(user.planExpiryDate) < new Date();
            if (!user.lifetimeUnlimited && (hasNoPlan || planIsExpired) && !user.freeTrialUsed) {
                const pricingDoc = await getPricingDoc(); const ftPlan = getPlanDetails(pricingDoc, 'free-trial');
                const planStart = new Date(); const planExpiry = new Date(); planExpiry.setDate(planExpiry.getDate() + (ftPlan.durationDays || 3));
                $set.currentPlan = 'free-trial'; $set.planStartDate = planStart; $set.planExpiryDate = planExpiry; $set.freeTrialUsed = true; $set.freeTrialActivatedAt = planStart;
            }
        }
        await RenewalUser.collection.updateOne({ _id: user._id }, { $set: $set });
        if (targetAction === 'rejected') { const userRegex = new RegExp('^' + (user.name || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i'); await Link.updateMany({ $or: [{ assignedUser: userRegex }, { userName: userRegex }, { creator: userRegex }, { name: userRegex }] }, { $set: { status: 'suspended' } }); }
        const updatedUser = await RenewalUser.findOne({ _id: user._id }).lean();
        const waData = generateWhatsAppApprovalData(updatedUser, req);
        if (updatedUser.email) { if (targetAction === 'approved') emailHelper.sendApprovalEmail(updatedUser.email, updatedUser.name).catch(() => {}); else if (targetAction === 'rejected') emailHelper.sendRejectionEmail(updatedUser.email, updatedUser.name).catch(() => {}); }
        res.json({ success: true, message: `User ${targetAction}!`, status: targetAction, user: updatedUser, whatsappUrl: waData.whatsappUrl });
    } catch (e) { res.status(500).json({ error: 'Failed: ' + e.message }); }
};

app.post('/api/admin/renewal-users/:id/action', authMiddleware, handleUserApprovalAction);
app.post('/api/admin/users/:id/action', authMiddleware, handleUserApprovalAction);

app.get('/api/admin/renewal-settings', authMiddleware, async (req, res) => { try { const pricingDoc = await getPricingDoc(); const requests = await RenewalRequest.find({ status: 'pending' }).sort({ createdAt: -1 }).lean(); res.json({ success: true, pricing: pricingDoc.toObject(), plans: pricingDoc.plans, paymentSettings: { ...pricingDoc.paymentSettings, whatsappNumber: pricingDoc.whatsappNumber, supportEmail: pricingDoc.supportEmail }, supportEmail: pricingDoc.supportEmail || '', requests }); } catch (e) { res.status(500).json({ error: 'Failed' }); } });
app.post('/api/admin/renewal-settings', authMiddleware, async (req, res) => { try { const { plans, paymentSettings, upiId, whatsappNumber, supportEmail, showUpi } = req.body; let pricingDoc = await Pricing.findOne(); if (!pricingDoc) pricingDoc = new Pricing(); if (plans && typeof plans === 'object') { const currentPlans = pricingDoc.plans || {}; for (const [key, incomingPlan] of Object.entries(plans)) { if (incomingPlan && typeof incomingPlan === 'object') currentPlans[key] = { ...(currentPlans[key] || DEFAULT_PLANS[key] || {}), ...incomingPlan }; } pricingDoc.plans = currentPlans; pricingDoc.markModified('plans'); } if (paymentSettings && typeof paymentSettings === 'object') { if (!pricingDoc.paymentSettings) pricingDoc.paymentSettings = {}; Object.assign(pricingDoc.paymentSettings, paymentSettings); pricingDoc.markModified('paymentSettings'); } if (showUpi !== undefined) { if (!pricingDoc.paymentSettings) pricingDoc.paymentSettings = {}; pricingDoc.paymentSettings.showUpi = showUpi !== false; pricingDoc.markModified('paymentSettings'); } if (upiId !== undefined) { if (!pricingDoc.paymentSettings) pricingDoc.paymentSettings = {}; if (!pricingDoc.paymentSettings.details) pricingDoc.paymentSettings.details = {}; pricingDoc.paymentSettings.details.upiId = upiId.toString().trim(); pricingDoc.markModified('paymentSettings'); } if (whatsappNumber) pricingDoc.whatsappNumber = whatsappNumber.toString().trim(); if (supportEmail !== undefined) pricingDoc.supportEmail = (supportEmail || '').toString().trim(); pricingDoc.autoPaymentEnabled = false; await pricingDoc.save(); res.json({ success: true, message: 'Settings saved' }); } catch (e) { res.status(500).json({ error: 'Failed: ' + e.message }); } });

app.post('/api/admin/renewal-requests/:id/approve', authMiddleware, async (req, res) => {
    try {
        const reqDoc = await RenewalRequest.findOne({ id: req.params.id });
        if (!reqDoc) return res.status(404).json({ error: 'Request not found' });
        let ownerName = null;
        if (reqDoc.linkId && !reqDoc.linkId.startsWith('pending_')) { const link = await Link.findOne(getLinkQuery(reqDoc.linkId)); if (link) { const curExpiry = link.expiryDate && new Date(link.expiryDate) > new Date() ? new Date(link.expiryDate) : new Date(); curExpiry.setDate(curExpiry.getDate() + (reqDoc.days || 30)); link.expiryDate = curExpiry; link.status = 'active'; await link.save(); ownerName = link.assignedUser || link.userName || link.name || link.creator; } }
        if (!ownerName && reqDoc.linkName) { const cleanName = reqDoc.linkName.replace(/\s*\(New User.*\)$/, '').replace(/\s*\(Pending\)$/, '').trim(); if (cleanName) ownerName = cleanName; }
        if (ownerName && reqDoc.plan) {
            const ownerUser = await RenewalUser.findOne({ name: new RegExp('^' + ownerName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i') });
            if (ownerUser) {
                const pricingDoc = await getPricingDoc();
                if (pricingDoc.plans && pricingDoc.plans[reqDoc.plan]) {
                    const planDetails = pricingDoc.plans[reqDoc.plan]; const planStart = new Date(); const planExpiry = new Date(); planExpiry.setDate(planExpiry.getDate() + (planDetails.durationDays || reqDoc.days || 30));
                    await RenewalUser.collection.updateOne({ _id: ownerUser._id }, { $set: { currentPlan: reqDoc.plan, planStartDate: planStart, planExpiryDate: planExpiry, lifetimeUnlimited: false, profileCompleted: true, status: 'approved', approvedAt: ownerUser.approvedAt || new Date() } });
                    const userRegex = new RegExp('^' + ownerUser.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
                    await Link.updateMany({ $or: [{ assignedUser: userRegex }, { userName: userRegex }, { creator: userRegex }, { name: userRegex }] }, { $set: { expiryDate: planExpiry, status: 'active' } });
                    if (ownerUser.email) emailHelper.sendPaymentEmail(ownerUser.email, ownerUser.name, 'approved', planDetails.name, reqDoc.amount).catch(() => {});
                }
            }
        }
        reqDoc.status = 'approved'; reqDoc.approvedAt = new Date(); await reqDoc.save();
        res.json({ success: true, message: 'Renewal approved!' });
    } catch (e) { res.status(500).json({ error: 'Failed: ' + e.message }); }
});

app.post('/api/renewal/reject/:requestId', authMiddleware, async (req, res) => { try { const request = await RenewalRequest.findOne({ id: req.params.requestId }); if (!request) return res.status(404).json({ error: 'Request not found' }); request.status = 'rejected'; await request.save(); res.json({ success: true, message: 'Renewal rejected' }); } catch (error) { res.status(500).json({ error: 'Failed' }); } });

app.get('/api/admin/block-status', async (req, res) => { try { const blocked = await isDeviceBlocked(req); if (blocked) return res.json({ blocked: true, isPermanent: true, reason: blocked.reason || 'Permanent ban' }); res.json({ blocked: false }); } catch (e) { res.json({ blocked: false }); } });

app.post('/api/admin/login', authLimiter, async (req, res) => {
    try {
        const { passcode } = req.body;
        const cleanPass = (passcode || '').toString().trim();
        if (!cleanPass) return res.status(400).json({ error: 'Passcode required' });
        const existingBlock = await isDeviceBlocked(req);
        if (existingBlock) return res.status(403).json({ error: 'permanently_blocked', message: '⛔ Device permanently blocked.' });
        let admin = await User.findOne();
        const activeEnvPass = process.env.ADMIN_PASSCODE ? process.env.ADMIN_PASSCODE.toString().trim() : DEFAULT_PASSCODE;
        if (!admin || !admin.passcode) { const hashed = bcrypt.hashSync(activeEnvPass, 10); admin = await User.create({ passcode: hashed, lastEnvPasscode: activeEnvPass, theme: 'dark', email: process.env.ADMIN_EMAIL || '', phone: process.env.ADMIN_PHONE || '', secretKey: 'admin@2024' }); }
        else if (process.env.ADMIN_PASSCODE && admin.lastEnvPasscode !== activeEnvPass) { admin.passcode = bcrypt.hashSync(activeEnvPass, 10); admin.lastEnvPasscode = activeEnvPass; await admin.save(); }
        const isValid = verifyPasscode(cleanPass, admin.passcode);
        if (isValid) {
            const { deviceKey, fingerprint, ip } = getDeviceId(req); const { deviceName, deviceType } = getDeviceDetails(req);
            await BlockedDevice.deleteMany({ $or: [{ deviceKey }, { ip }, { fingerprint }], isPermanent: false }).catch(() => {});
            if (Session) await Session.create({ userId: 'admin', deviceKey, fingerprint, ip, userAgent: (req.headers && req.headers['user-agent']) ? req.headers['user-agent'].toString() : 'Unknown', deviceName, deviceType, isActive: true, lastActivity: new Date(), createdAt: new Date(), expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000) }).catch(() => {});
            const jwtToken = generateToken('admin');
            res.cookie('adminToken', jwtToken, { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 24 * 3600 * 1000 });
            return res.json({ success: true, token: jwtToken });
        }
        const { deviceKey, fingerprint, ip } = getDeviceId(req); const { deviceName, deviceType } = getDeviceDetails(req);
        let record = await BlockedDevice.findOne({ $or: [{ deviceKey }, { ip }, { fingerprint }] });
        if (!record) { record = new BlockedDevice({ deviceKey, fingerprint, ip, deviceName, deviceType, attempts: 1, reason: 'Failed login attempt (1/3)', isPermanent: false, lastAttempt: new Date() }); }
        else { record.attempts = (record.attempts || 0) + 1; record.lastAttempt = new Date(); record.ip = ip; record.deviceName = deviceName; record.deviceType = deviceType; }
        if (record.attempts >= 3 && ip !== '127.0.0.1' && ip !== '::1' && !ip.includes('localhost')) { record.isPermanent = true; record.reason = 'Permanent ban: 3 failed attempts'; await record.save(); return res.status(403).json({ error: 'permanently_blocked', message: '⛔ Device permanently blocked.' }); }
        else { record.reason = `Failed passcode attempt (${record.attempts}/3)`; await record.save(); return res.status(401).json({ error: `Incorrect Passcode! Attempt ${record.attempts} of 3.` }); }
    } catch (error) { res.status(500).json({ error: 'Server authentication error' }); }
});

app.post('/api/admin/logout', async (req, res) => { try { const { deviceKey, fingerprint, ip } = getDeviceId(req); if (Session) await Session.updateMany({ $or: [{ deviceKey }, { ip }, { fingerprint }] }, { $set: { isActive: false, lastActivity: new Date() } }).catch(() => {}); } catch(e) {} res.clearCookie('adminToken', { path: '/' }); res.json({ success: true }); });
app.post('/api/admin/passcode', authMiddleware, async (req, res) => { try { const { oldPasscode, newPasscode } = req.body; const cleanOld = (oldPasscode || '').toString().trim(); const cleanNew = (newPasscode || '').toString().trim(); if (!cleanNew || cleanNew.length !== 6) return res.status(400).json({ error: 'New passcode must be 6 digits' }); const admin = await User.findOne(); if (!admin) return res.status(404).json({ error: 'Admin not found' }); if (!verifyPasscode(cleanOld, admin.passcode)) return res.status(401).json({ error: 'Current passcode incorrect' }); admin.passcode = bcrypt.hashSync(cleanNew, 10); admin.lastEnvPasscode = cleanNew; await admin.save(); res.json({ success: true, message: 'Passcode changed!' }); } catch (error) { res.status(500).json({ error: 'Failed' }); } });
app.post('/api/admin/theme', authMiddleware, async (req, res) => { try { const admin = await User.findOne(); if (admin) { admin.theme = req.body.theme; await admin.save(); } res.json({ success: true }); } catch (error) { res.status(500).json({ error: 'Failed' }); } });
app.post('/api/admin/background', authMiddleware, async (req, res) => { try { let popup = await PopupSettings.findOne(); if (!popup) popup = new PopupSettings(); if (req.body.background !== undefined) popup.image = req.body.background || null; if (req.body.uidChecking !== undefined) popup.uidChecking = !isUidCheckDisabled(req.body.uidChecking); await popup.save(); res.json({ success: true }); } catch (error) { res.status(500).json({ error: 'Failed' }); } });
app.post('/api/admin/update-contact', authMiddleware, async (req, res) => { try { const admin = await User.findOne(); if (admin) { if (req.body.email) admin.email = req.body.email; if (req.body.phone) admin.phone = req.body.phone; await admin.save(); } if (req.body.supportEmail !== undefined) { const pricingDoc = await getPricingDoc(); pricingDoc.supportEmail = (req.body.supportEmail || '').toString().trim(); await pricingDoc.save(); } res.json({ success: true }); } catch(e) { res.status(500).json({ error: 'Failed' }); } });

app.get(['/api/links', '/api/admin/links'], authMiddleware, async (req, res) => { try { const links = await Link.find().sort({ created: -1 }).lean(); const formatted = links.map(l => { const popup = l.popupSettings || {}; const img = popup.image || l.image || null; const isUidOn = !isUidCheckDisabled(l.uidChecking); const userName = l.name || l.userName || l.assignedUser || 'User'; const linkName = l.linkName || l.title || 'Link'; return { ...l, name: userName, userName: userName, assignedUser: userName, linkName: linkName, title: linkName, claims: l.claims || 0, visits: l.visits || 0, uidChecking: isUidOn, image: img, popupImage: img, popupSettings: { ...popup, image: img } }; }); res.json(formatted); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.get(['/api/links/:id', '/api/link/:id'], authMiddleware, async (req, res) => { try { const rawId = extractCleanId(req.params.id); const l = await Link.findOne(getLinkQuery(rawId)).lean(); if (!l) return res.status(404).json({ error: 'Link not found' }); const popup = l.popupSettings || {}; const img = popup.image || l.image || null; const isUidOn = !isUidCheckDisabled(l.uidChecking); const userName = l.name || l.userName || l.assignedUser || 'User'; const linkName = l.linkName || l.title || 'Link'; res.json({ ...l, name: userName, userName: userName, linkName: linkName, title: linkName, claims: l.claims || 0, visits: l.visits || 0, uidChecking: isUidOn, image: img, popupImage: img, popupSettings: { ...popup, image: img } }); } catch (e) { res.status(500).json({ error: 'Failed' }); } });

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
        const finalPopup = { title: req.body.popupSettings?.title || req.body.popupTitle || '🎁 Claim Your Reward', subtitle: req.body.popupSettings?.subtitle || req.body.popupSubtitle || 'Tap below to unlock your reward', buttonText: req.body.popupSettings?.buttonText || req.body.popupButtonText || cleanButtonText, image: finalBanner };
        let assignedUser = null;
        if (cleanUserName && cleanUserName.toLowerCase() !== 'user') { assignedUser = await RenewalUser.findOne({ name: new RegExp('^' + cleanUserName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i') }); }
        if (assignedUser) { const userLimitInfo = await getUserLinkLimit(assignedUser); if (userLimitInfo.limit !== 'unlimited' && userLimitInfo.used >= userLimitInfo.limit) return res.status(403).json({ error: `Cannot create link for "${cleanUserName}". Limit reached.`, reason: 'LINK_LIMIT_REACHED' }); }
        const finalExpiry = cleanExpiry || (assignedUser?.planExpiryDate ? new Date(assignedUser.planExpiryDate) : null);
        const linkId = 'link_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex');
        const linkDoc = { id: linkId, name: cleanUserName, userName: cleanUserName, assignedUser: cleanUserName, creator: cleanUserName, linkName: cleanLinkName, title: cleanLinkName, video: cleanVideo, claim: cleanClaim, buttonText: cleanButtonText, headline: cleanHeadline, expiryDate: finalExpiry, uidChecking: cleanUidChecking, status: 'active', claims: 0, visits: 0, dailyClaims: {}, dailyVisits: {}, image: finalBanner, popupImage: finalBanner, popupImageUrl: finalBanner, banner: finalBanner, popupSettings: finalPopup, created: new Date() };
        await Link.collection.insertOne(linkDoc);
        res.json({ ...linkDoc, name: cleanUserName, userName: cleanUserName, linkName: cleanLinkName, title: cleanLinkName, uidChecking: cleanUidChecking, claims: 0, visits: 0, image: finalBanner, popupSettings: finalPopup });
    } catch (e) { res.status(500).json({ error: 'Failed to create link' }); }
});

async function handleLinkUpdate(req, res) {
    try {
        let rawId = req.params.id;
        if (!rawId || ['undefined', 'null', 'update', 'edit', 'save'].includes(rawId)) rawId = req.body.id || req.body.linkId || req.body._id;
        const cleanId = extractCleanId(rawId);
        const query = getLinkQuery(cleanId);
        const existingLink = await Link.findOne(query).lean();
        if (!existingLink) return res.status(404).json({ error: 'Link not found' });
        if (req.path.includes('toggle') || req.body.action === 'toggle' || req.body.toggle === true) { const newVal = !(!isUidCheckDisabled(existingLink.uidChecking)); await Link.collection.updateOne({ _id: existingLink._id }, { $set: { uidChecking: newVal } }); return res.json({ success: true, uidChecking: newVal }); }
        const $set = {};
        if (req.body.name && req.body.name.toString().trim()) { const uName = req.body.name.toString().trim(); $set.name = uName; $set.userName = uName; $set.assignedUser = uName; $set.creator = uName; }
        const incomingLinkName = req.body.linkName ?? req.body.title ?? req.body.linkTitle ?? req.body.campaignName;
        if (incomingLinkName !== undefined && incomingLinkName !== null && incomingLinkName.toString().trim() !== '') { $set.linkName = incomingLinkName.toString().trim(); $set.title = incomingLinkName.toString().trim(); }
        const incomingVideo = req.body.video ?? req.body.videoUrl ?? req.body.url; if (incomingVideo !== undefined) $set.video = (incomingVideo || '').toString().trim();
        const incomingClaim = req.body.claim ?? req.body.claimUrl ?? req.body.claimLink; if (incomingClaim !== undefined) $set.claim = (incomingClaim || '').toString().trim();
        const incomingBtn = req.body.buttonText ?? req.body.btnText; if (incomingBtn !== undefined) $set.buttonText = (incomingBtn || '').toString().trim();
        const incomingHeadline = req.body.headline ?? req.body.heading; if (incomingHeadline !== undefined) $set.headline = (incomingHeadline || '').toString().trim();
        if (req.body.status !== undefined) $set.status = req.body.status;
        let incomingUidVal = req.body.uidChecking ?? req.body.uidCheck ?? req.body.checkUid ?? req.body.enableUid; if (incomingUidVal !== undefined) $set.uidChecking = !isUidCheckDisabled(incomingUidVal);
        const makeLifetimeFlag = req.body.makeLifetime === true || req.body.lifetimeActive === true;
        const hasExpiryField = ('expiryDate' in req.body) || ('expiry' in req.body) || ('expDate' in req.body);
        if (makeLifetimeFlag) $set.expiryDate = null; else if (hasExpiryField) { const incomingExpiry = req.body.expiryDate ?? req.body.expiry ?? req.body.expDate; if (incomingExpiry === null || incomingExpiry === '' || incomingExpiry === 'null' || incomingExpiry === undefined) $set.expiryDate = null; else if (!isNaN(new Date(incomingExpiry).getTime())) $set.expiryDate = new Date(incomingExpiry); else $set.expiryDate = null; }
        const currentPopup = existingLink.popupSettings || {};
        const newPopup = { title: req.body.popupSettings?.title || req.body.popupTitle || currentPopup.title || '🎁 Claim Your Reward', subtitle: req.body.popupSettings?.subtitle || req.body.popupSubtitle || currentPopup.subtitle || 'Tap below to unlock your reward', buttonText: req.body.popupSettings?.buttonText || req.body.popupButtonText || currentPopup.buttonText || 'Claim Now', image: currentPopup.image || null };
        let incomingImage = req.body.popupImage ?? req.body.image ?? req.body.banner ?? req.body.popupSettings?.image; if (incomingImage !== undefined) { const cleanImg = (incomingImage || '').toString().trim(); const finalImg = cleanImg.length > 4 ? cleanImg : null; newPopup.image = finalImg; $set.image = finalImg; $set.popupImage = finalImg; $set.popupImageUrl = finalImg; $set.banner = finalImg; }
        $set.popupSettings = newPopup;
        const updateResult = await Link.collection.updateOne({ _id: existingLink._id }, { $set: $set });
        if (updateResult.matchedCount === 0) return res.status(404).json({ error: 'Link not found during update' });
        if ($set.linkName) await RenewalRequest.updateMany({ linkId: existingLink.id }, { $set: { linkName: $set.linkName } }).catch(() => {});
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Failed: ' + e.message }); }
}

app.put(['/api/links/:id', '/api/link/:id', '/api/links/update/:id', '/api/links/update'], authMiddleware, handleLinkUpdate);
app.post(['/api/links/:id', '/api/link/:id', '/api/links/update/:id', '/api/links/update', '/api/link/update'], authMiddleware, handleLinkUpdate);
app.patch(['/api/links/:id', '/api/link/:id'], authMiddleware, handleLinkUpdate);
app.all('/api/links/:id/uid-checking', authMiddleware, handleLinkUpdate);
app.all('/api/links/:id/toggle-uid', authMiddleware, handleLinkUpdate);
app.delete(['/api/links/:id', '/api/link/:id'], authMiddleware, async (req, res) => { try { const query = getLinkQuery(extractCleanId(req.params.id)); const link = await Link.findOne(query).lean(); if (!link) return res.status(404).json({ error: 'Link not found' }); await RenewalRequest.deleteMany({ linkId: link.id }).catch(() => {}); await VisitorActivity.deleteMany({ linkId: link.id }).catch(() => {}); await Link.deleteMany(query); res.json({ success: true, message: 'Link deleted' }); } catch (error) { res.status(500).json({ error: 'Failed' }); } });

// ==================== FILE SERVING ====================
function sendAppFile(res, ...fileNames) { const searchDirs = [path.join(__dirname, 'admin'), path.join(__dirname, 'public'), __dirname, path.join(__dirname, '..'), path.join(__dirname, '..', 'admin'), path.join(__dirname, '..', 'public')]; for (const name of fileNames) { for (const dir of searchDirs) { const p = path.join(dir, name); if (fs.existsSync(p)) return res.sendFile(p); } } res.status(404).send(`File not found`); }
function injectScriptIntoHTML(content, script) { if (/<head[^>]*>/i.test(content)) return content.replace(/<head[^>]*>/i, (m) => m + '\n' + script); else if (/<body[^>]*>/i.test(content)) return content.replace(/<body[^>]*>/i, (m) => m + '\n' + script); return script + content; }
function sendUidCheckerFile(res, targetLinkId) { const searchDirs = [path.join(__dirname, 'admin'), path.join(__dirname, 'public'), __dirname, path.join(__dirname, '..'), path.join(__dirname, '..', 'admin'), path.join(__dirname, '..', 'public')]; const fileNames = ['uid-checker.html', 'uid.html']; for (const name of fileNames) { for (const dir of searchDirs) { const p = path.join(dir, name); if (fs.existsSync(p)) { try { let content = fs.readFileSync(p, 'utf8'); const guardScript = `<script>(function() {try {var p = new URLSearchParams(window.location.search);var lid = p.get('link') || p.get('id') || p.get('l') || ${JSON.stringify(targetLinkId || '')};if (!lid) { var parts = window.location.pathname.split('/'); var last = parts[parts.length - 1]; if (last && last !== 'uid' && last !== 'uid.html' && last !== 'uid-checker.html') lid = last; }if (lid) { fetch('/api/link/' + encodeURIComponent(lid)).then(function(r) { if (r.status === 403 || r.status === 404) { window.location.replace('/expired.html'); return; }return r.json(); }).then(function(d) { if (!d) return;if (d.expired === true) { window.location.replace('/expired.html'); return; }if (d.uidChecking === false || d.uidChecking === 'false' || d.uidChecking === 'off' || d.uidChecking === 0) { window.location.replace('/v/' + encodeURIComponent(d.id || lid)); }}).catch(function(){}); }} catch(e) {}})();</script>`; content = injectScriptIntoHTML(content, guardScript); res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate'); return res.send(content); } catch(e) { return res.sendFile(p); } } } } res.status(404).send('File not found: uid-checker.html'); }
function sendVideoLockFile(res, targetLinkId) { const searchDirs = [path.join(__dirname, 'admin'), path.join(__dirname, 'public'), __dirname, path.join(__dirname, '..'), path.join(__dirname, '..', 'admin'), path.join(__dirname, '..', 'public')]; const fileNames = ['video-lock.html']; for (const name of fileNames) { for (const dir of searchDirs) { const p = path.join(dir, name); if (fs.existsSync(p)) { try { let content = fs.readFileSync(p, 'utf8'); const preVerifyScript = `<script>window.__LINK_ID__ = ${JSON.stringify(targetLinkId || '')};try { sessionStorage.setItem('player_uid', 'verified'); sessionStorage.setItem('uid_verified', 'true'); localStorage.setItem('player_uid', 'verified'); localStorage.setItem('uid_verified', 'true'); } catch(e) {}</script><script>(function() {try {var lid = ${JSON.stringify(targetLinkId || '')};if (!lid) { var parts = window.location.pathname.split('/'); var last = parts[parts.length - 1]; if (last && last !== 'v') lid = last; }if (lid) {fetch('/api/link/' + encodeURIComponent(lid)).then(function(r) { if (r.status === 403 || r.status === 404) { window.location.replace('/expired.html'); } }).catch(function(){});}} catch(e) {}})();</script>`; content = injectScriptIntoHTML(content, preVerifyScript); res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate'); return res.send(content); } catch(e) { return res.sendFile(p); } } } } res.status(404).send('File not found: video-lock.html'); }

app.get('/admin/login.html', async (req, res) => { const blocked = await isDeviceBlocked(req); if (blocked) return res.send(`<!DOCTYPE html><html><head><title>Access Blocked</title><style>body{background:#090a10;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;text-align:center;}.card{background:#131722;padding:40px;border-radius:20px;border:1px solid rgba(239,68,68,0.4);max-width:450px;}h1{color:#ef4444;}</style></head><body><div class="card"><h1>⛔ DEVICE PERMANENTLY BLOCKED</h1><p>Your device has been permanently blocked due to repeated failed login attempts.</p></div></body></html>`); sendAppFile(res, 'login.html', 'admin/login.html'); });
app.get('/expired.html', (req, res) => { res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.send(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Link Expired</title><link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;800;900&display=swap" rel="stylesheet"><style>* { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; } body { background: #080c16; color: #f8fafc; min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; } .expired-card { background: rgba(17, 23, 38, 0.85); border-radius: 26px; padding: 42px 30px; max-width: 440px; width: 100%; text-align: center; border: 1px solid rgba(239, 68, 68, 0.35); box-shadow: 0 30px 80px rgba(0, 0, 0, 0.75); } .expired-icon { width: 90px; height: 90px; margin: 0 auto 18px; border-radius: 50%; background: rgba(239, 68, 68, 0.15); border: 2px solid rgba(239, 68, 68, 0.5); display: flex; align-items: center; justify-content: center; font-size: 44px; } .expired-title { font-size: 28px; font-weight: 900; color: #ef4444; margin-bottom: 12px; } .expired-subtitle { font-size: 14.5px; color: #cbd5e1; line-height: 1.6; margin-bottom: 24px; } .info-box { background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 14px; padding: 16px; text-align: left; } .info-row { display: flex; align-items: center; justify-content: space-between; font-size: 13px; color: #cbd5e1; margin-bottom: 8px; } .info-row:last-child { margin-bottom: 0; } .info-row strong { color: #fff; font-weight: 700; }</style></head><body><div class="expired-card"><div class="expired-icon">⏰</div><div class="expired-title">Link Expired</div><div class="expired-subtitle">This link is no longer active. Its validity period has ended, or the owner's plan has expired.</div><div class="info-box"><div class="info-row"><span>📌 Status</span><strong style="color:#f87171;">Expired</strong></div><div class="info-row"><span>🔒 Access</span><strong>Blocked</strong></div><div class="info-row"><span>💬 Support</span><strong>Contact Owner</strong></div></div></div></body></html>`); });
app.get('/', async (req, res) => { let rawParam = (req.query.link || req.query.id || req.query.l || '').toString().trim(); if (rawParam) { let cleanId = extractCleanId(rawParam); if (cleanId) { const link = await Link.findOne(getLinkQuery(cleanId)).lean(); if (link && isLinkExpired(link)) return res.redirect('/expired.html'); if (link && isUidCheckDisabled(link.uidChecking)) return res.redirect('/v/' + encodeURIComponent(link.id || cleanId)); else if (link) return res.redirect('/uid?link=' + encodeURIComponent(link.id || cleanId)); } } res.redirect('/admin/secret-gateway'); });
app.get('/admin/secret-gateway', (req, res) => sendAppFile(res, 'secret-gateway.html', 'admin/secret-gateway.html'));
app.get(['/admin/index.html', '/admin'], (req, res) => { const token = req.cookies?.adminToken; if (!token || !verifyToken(token)) return res.redirect('/admin/login.html'); sendAppFile(res, 'admin/index.html', 'index.html'); });
app.get(['/uid', '/uid.html', '/uid-checker.html', '/uid/:id'], async (req, res) => { let cleanId = ''; try { let rawParam = (req.query.link || req.query.id || req.query.l || req.query.linkId || req.params.id || '').toString().trim(); cleanId = extractCleanId(rawParam); let link = cleanId ? await Link.findOne(getLinkQuery(cleanId)).lean() : null; if (!link) link = await Link.findOne({ status: 'active' }).sort({ created: -1 }).lean(); if (link && isLinkExpired(link)) return res.redirect('/expired.html'); const globalPopup = await PopupSettings.findOne().lean().catch(() => null); const isGlobalOff = globalPopup && isUidCheckDisabled(globalPopup.uidChecking); const isLinkOff = link && isUidCheckDisabled(link.uidChecking); if (isLinkOff || isGlobalOff) { const targetId = (link && link.id) ? link.id : (cleanId || 'default'); return res.redirect('/v/' + encodeURIComponent(targetId)); } } catch(err) {} sendUidCheckerFile(res, cleanId); });
app.get('/v/:id', async (req, res) => { const cleanId = extractCleanId(req.params.id); try { const link = await Link.findOne(getLinkQuery(cleanId)).lean(); if (!link) return res.redirect('/expired.html'); if (isLinkExpired(link)) return res.redirect('/expired.html'); const ownerName = link.assignedUser || link.userName || link.name || link.creator; if (ownerName) { const ownerUser = await RenewalUser.findOne({ name: new RegExp('^' + ownerName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i') }).lean(); if (!ownerUser) { await Link.collection.deleteOne({ _id: link._id }).catch(() => {}); return res.redirect('/expired.html'); } if (isPlanExpired(ownerUser)) return res.redirect('/expired.html'); } } catch(err) {} sendVideoLockFile(res, cleanId); });
app.get(['/user-dashboard', '/user-dashboard/:id?'], (req, res) => sendAppFile(res, 'user-dashboard.html'));
app.get('/manifest.json', (req, res) => sendAppFile(res, 'manifest.json'));
app.get('/sw.js', (req, res) => sendAppFile(res, 'sw.js'));

process.on('uncaughtException', (err) => { console.error('❌ Uncaught Exception:', err.message); });
process.on('unhandledRejection', (reason) => { console.error('❌ Unhandled Rejection:', reason); });

setInterval(async () => { try { if (Session) await Session.deleteMany({ expiresAt: { $lt: new Date() } }); await OTPVerification.deleteMany({ expiresAt: { $lt: new Date() } }); await Otp.deleteMany({ expiresAt: { $lt: new Date() } }); } catch (error) { console.error('Cleanup error:', error); } }, 60 * 60 * 1000);
