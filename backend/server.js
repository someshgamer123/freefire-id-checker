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

// Connect to MongoDB
connectDB();

// ==================== Initialize Default Data ====================
async function initializeDatabase() {
    try {
        const adminExists = await User.findOne();
        if (!adminExists) {
            const hashedPasscode = bcrypt.hashSync('951753', 10);
            await User.create({
                passcode: hashedPasscode,
                theme: 'light'
            });
            console.log('✅ Admin user created with passcode: 951753');
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
                    details: {
                        upiId: 'admin@upi',
                        qrCode: null,
                        text: ''
                    }
                },
                whatsappNumber: '919876543210'
            });
            console.log('✅ Pricing initialized');
        }
    } catch (error) {
        console.error('❌ Database initialization error:', error);
    }
}

initializeDatabase();

app.set('trust proxy', 1);

// ==================== Security Headers ====================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            styleSrcAttr: ["'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "blob:", "*"],
            connectSrc: ["'self'"],
            frameSrc: ["'self'", "https://www.youtube.com", "https://*.image2url.com", "https://*.terabox.com", "*"],
            mediaSrc: ["'self'", "https://*.image2url.com", "https://*.terabox.com", "*"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    }
}));

app.use(cors({
    origin: ['http://localhost:3000', 'https://freefire-id-checker.onrender.com', 'https://*.onrender.com'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

// ==================== Rate Limiting ====================
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests, please try again later.'
});
app.use('/api', globalLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many login attempts, please try again after 15 minutes'
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.use(express.static('.'));

// ==================== JWT & Auth ====================
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRY = '7d';

function generateToken(userId) {
    return jwt.sign({ id: userId, role: 'admin' }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
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
    return fingerprint;
}

// ==================== Auth Middleware ====================
async function authMiddleware(req, res, next) {
    const token = req.cookies?.adminToken;
    const csrfToken = req.headers['x-csrf-token'];
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    req.user = decoded;
    next();
}

// ==================== WHATSAPP NUMBER API ====================
let whatsappNumber = '919876543210';

app.get('/api/whatsapp-number', async (req, res) => {
    try {
        const pricing = await Pricing.findOne();
        const number = pricing?.whatsappNumber || whatsappNumber || '919876543210';
        res.json({ number: number });
    } catch (error) {
        res.json({ number: whatsappNumber || '919876543210' });
    }
});

app.post('/api/admin/whatsapp', authMiddleware, async (req, res) => {
    try {
        const { number } = req.body;
        if (!number) {
            return res.status(400).json({ error: 'WhatsApp number required' });
        }
        let pricing = await Pricing.findOne();
        if (!pricing) {
            pricing = new Pricing();
        }
        pricing.whatsappNumber = number;
        whatsappNumber = number;
        await pricing.save();
        res.json({ success: true, number: number });
    } catch (error) {
        console.error('❌ WhatsApp number save error:', error);
        res.status(500).json({ error: 'Failed to save WhatsApp number' });
    }
});

// ==================== DASHBOARD MAP API ====================
app.get('/api/dashboard-map/:dashboardId', async (req, res) => {
    try {
        const { dashboardId } = req.params;
        console.log('🔍 Dashboard map request for:', dashboardId);
        
        // Check if dashboardId itself is a link ID
        const existingLink = await Link.findOne({ id: dashboardId });
        if (existingLink) {
            console.log('✅ Found link by direct ID:', existingLink.id);
            return res.json({ linkId: existingLink.id });
        }
        
        // Find link where dashboardId matches
        const link = await Link.findOne({ dashboardId: dashboardId });
        if (link) {
            console.log('✅ Found link with dashboardId:', link.id);
            return res.json({ linkId: link.id });
        }
        
        // Partial match - search all links
        const allLinks = await Link.find({});
        const matched = allLinks.find(l => 
            l.id.includes(dashboardId) || 
            (l.dashboardId && l.dashboardId.includes(dashboardId)) ||
            dashboardId.includes(l.id)
        );
        
        if (matched) {
            console.log('✅ Found link by partial match:', matched.id);
            return res.json({ linkId: matched.id });
        }
        
        console.log('❌ No link found for dashboardId:', dashboardId);
        res.status(404).json({ error: 'No link found' });
    } catch (error) {
        console.error('❌ Dashboard map error:', error);
        res.status(500).json({ error: 'Failed to map dashboard' });
    }
});

// ==================== SEARCH LINKS API ====================
app.get('/api/search-links', authMiddleware, async (req, res) => {
    try {
        const { query } = req.query;
        
        if (!query || query.length < 1) {
            return res.json({ links: [] });
        }
        
        const searchRegex = new RegExp(query, 'i');
        
        const links = await Link.find({
            $or: [
                { name: searchRegex },
                { id: searchRegex },
                { dashboardId: searchRegex }
            ]
        }).limit(20).sort({ created: -1 });
        
        res.json({
            links: links,
            count: links.length,
            query: query
        });
    } catch (error) {
        console.error('❌ Search links error:', error);
        res.status(500).json({ error: 'Failed to search links' });
    }
});

// ==================== GENERATE DASHBOARD LINK API ====================
app.post('/api/generate-dashboard-link', authMiddleware, async (req, res) => {
    try {
        const { linkId } = req.body;
        
        if (!linkId) {
            return res.status(400).json({ error: 'Link ID required' });
        }
        
        const link = await Link.findOne({ id: linkId });
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }
        
        const dashboardId = 'dashboard_' + Date.now() + '_' + crypto.randomBytes(8).toString('hex');
        
        link.dashboardId = dashboardId;
        await link.save();
        
        const dashboardUrl = '/user-dashboard/' + dashboardId;
        const fullUrl = req.protocol + '://' + req.get('host') + dashboardUrl;
        
        res.json({
            success: true,
            dashboardId: dashboardId,
            dashboardUrl: dashboardUrl,
            fullUrl: fullUrl,
            linkName: link.name,
            linkId: link.id
        });
    } catch (error) {
        console.error('❌ Generate dashboard link error:', error);
        res.status(500).json({ error: 'Failed to generate dashboard link' });
    }
});

// ==================== ADMIN ROUTES ====================
app.post('/api/admin/login', authLimiter, async (req, res) => {
    try {
        const { passcode } = req.body;
        if (!passcode) {
            return res.status(400).json({ error: 'Passcode required' });
        }
        if (!/^\d+$/.test(passcode) || passcode.length !== 6) {
            return res.status(400).json({ error: 'Invalid passcode format (6 digits required)' });
        }
        
        const admin = await User.findOne();
        if (!admin) {
            return res.status(500).json({ error: 'Admin not found' });
        }
        
        const isValid = bcrypt.compareSync(passcode, admin.passcode);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid passcode' });
        }
        
        const token = generateToken('admin');
        const csrfToken = generateCSRFToken();
        
        res.cookie('adminToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production' || true,
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/'
        });
        
        res.json({
            success: true,
            csrfToken: csrfToken
        });
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/admin/logout', authMiddleware, async (req, res) => {
    try {
        res.clearCookie('adminToken');
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Logout failed' });
    }
});

app.post('/api/admin/passcode', authMiddleware, async (req, res) => {
    try {
        const { oldPasscode, newPasscode } = req.body;
        if (!oldPasscode || !newPasscode) {
            return res.status(400).json({ error: 'Both passcodes required' });
        }
        if (!/^\d+$/.test(newPasscode) || newPasscode.length !== 6) {
            return res.status(400).json({ error: 'New passcode must be 6 digits' });
        }
        
        const admin = await User.findOne();
        if (!admin) {
            return res.status(500).json({ error: 'Admin not found' });
        }
        
        const isValid = bcrypt.compareSync(oldPasscode, admin.passcode);
        if (!isValid) {
            return res.status(401).json({ error: 'Current passcode is incorrect' });
        }
        
        admin.passcode = bcrypt.hashSync(newPasscode, 10);
        await admin.save();
        
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
        if (!['light', 'dark'].includes(theme)) {
            return res.status(400).json({ error: 'Invalid theme' });
        }
        
        const admin = await User.findOne();
        if (admin) {
            admin.theme = theme;
            await admin.save();
        }
        
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
        if (popupSettings) {
            popupSettings.image = background || null;
            await popupSettings.save();
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Background update error:', error);
        res.status(500).json({ error: 'Failed to update background' });
    }
});

app.post('/api/admin/popup', authMiddleware, async (req, res) => {
    try {
        const { image, title, buttonText, subtitle, linkId } = req.body;
        
        if (linkId) {
            const link = await Link.findOne({ id: linkId });
            if (!link) {
                return res.status(404).json({ error: 'Link not found' });
            }
            if (image !== undefined) link.popupSettings.image = image;
            if (title !== undefined) link.popupSettings.title = title;
            if (buttonText !== undefined) link.popupSettings.buttonText = buttonText;
            if (subtitle !== undefined) link.popupSettings.subtitle = subtitle;
            await link.save();
        } else {
            const popupSettings = await PopupSettings.findOne();
            if (popupSettings) {
                if (image !== undefined) popupSettings.image = image;
                if (title !== undefined) popupSettings.title = title;
                if (buttonText !== undefined) popupSettings.buttonText = buttonText;
                if (subtitle !== undefined) popupSettings.subtitle = subtitle;
                await popupSettings.save();
            }
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Popup update error:', error);
        res.status(500).json({ error: 'Failed to update popup settings' });
    }
});

app.get('/api/popup-settings/:linkId?', async (req, res) => {
    try {
        const { linkId } = req.params;
        
        if (linkId) {
            const link = await Link.findOne({ id: linkId });
            if (!link) {
                return res.status(404).json({ error: 'Link not found' });
            }
            const settings = link.popupSettings || {
                image: null,
                title: '🎁 Claim Your Reward',
                buttonText: 'Claim Now',
                subtitle: 'Tap below to unlock your reward'
            };
            return res.json(settings);
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

// ==================== LINK ROUTES ====================
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
        if (video && !urlRegex.test(video)) {
            return res.status(400).json({ error: 'Invalid video URL format' });
        }
        if (claim && claim !== '#' && !urlRegex.test(claim)) {
            return res.status(400).json({ error: 'Invalid claim URL format' });
        }
        
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
        
        const link = await Link.findOne({ id: id });
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }
        
        if (name && (name.length < 1 || name.length > 100)) {
            return res.status(400).json({ error: 'Invalid link name' });
        }
        
        const urlRegex = /^(https?:\/\/[^\s]+)$/;
        if (video && !urlRegex.test(video)) {
            return res.status(400).json({ error: 'Invalid video URL' });
        }
        if (claim && claim !== '#' && !urlRegex.test(claim)) {
            return res.status(400).json({ error: 'Invalid claim URL' });
        }
        
        if (name !== undefined) link.name = name.substring(0, 100);
        if (video !== undefined) link.video = video;
        if (claim !== undefined) link.claim = claim;
        if (buttonText !== undefined) link.buttonText = buttonText.substring(0, 50);
        if (headline !== undefined) link.headline = headline.substring(0, 200);
        if (status !== undefined && ['active', 'suspended', 'disabled'].includes(status)) {
            link.status = status;
        }
        if (expiryDate !== undefined) link.expiryDate = expiryDate;
        if (popupSettings !== undefined) {
            link.popupSettings = { ...link.popupSettings, ...popupSettings };
        }
        
        await link.save();
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
        
        if (!['active', 'suspended', 'disabled'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        const link = await Link.findOne({ id: id });
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }
        
        link.status = status;
        await link.save();
        res.json(link);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update status' });
    }
});

app.delete('/api/links/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        await Link.findOneAndDelete({ id: id });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete link' });
    }
});

// ==================== PUBLIC LINK ====================
app.get('/api/link/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const link = await Link.findOne({ id: id });
        
        if (!link) {
            return res.status(404).json({
                error: 'not_found',
                message: 'Link not found'
            });
        }
        
        if (link.status === 'suspended') {
            return res.status(403).json({
                error: 'suspended',
                message: 'This link has been suspended by the admin',
                status: 'suspended'
            });
        }
        if (link.status === 'disabled') {
            return res.status(403).json({
                error: 'disabled',
                message: 'This link has been permanently disabled',
                status: 'disabled'
            });
        }
        if (link.expiryDate && new Date() > new Date(link.expiryDate)) {
            return res.status(403).json({
                error: 'expired',
                message: 'This link has expired',
                status: 'expired'
            });
        }
        if (link.status !== 'active') {
            return res.status(403).json({
                error: 'inactive',
                message: 'This link is not active',
                status: 'inactive'
            });
        }
        
        const deviceId = getDeviceId(req);
        const today = new Date().toISOString().split('T')[0];
        let stats = await Stats.findOne();
        if (!stats) {
            stats = await Stats.create({});
        }
        
        const uniqueKey = deviceId + '_' + today;
        const uniqueVisitors = stats.uniqueVisitors || new Map();
        
        if (!uniqueVisitors.has(uniqueKey) || 
            (Date.now() - uniqueVisitors.get(uniqueKey) > 48 * 60 * 60 * 1000)) {
            uniqueVisitors.set(uniqueKey, Date.now());
            stats.totalVisitors = (stats.totalVisitors || 0) + 1;
            stats.dailyVisitors.set(today, (stats.dailyVisitors.get(today) || 0) + 1);
            link.visits = (link.visits || 0) + 1;
            link.dailyVisits.set(today, (link.dailyVisits.get(today) || 0) + 1);
            
            await link.save();
            await stats.save();
            console.log('👤 New unique visitor (48hr):', deviceId.substring(0, 10));
        }
        
        const popupSettings = link.popupSettings || {
            image: null,
            title: '🎁 Claim Your Reward',
            buttonText: 'Claim Now',
            subtitle: 'Tap below to unlock your reward'
        };
        
        res.json({
            id: link.id,
            video: link.video,
            claim: link.claim,
            buttonText: link.buttonText,
            headline: link.headline,
            status: link.status,
            popupSettings: popupSettings
        });
    } catch (error) {
        console.error('❌ Fetch link error:', error);
        res.status(500).json({ error: 'Failed to fetch link' });
    }
});

// ==================== TRACK CLAIM ====================
app.post('/api/track-claim/:linkId', async (req, res) => {
    try {
        const { linkId } = req.params;
        const link = await Link.findOne({ id: linkId });
        
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }
        
        const deviceId = getDeviceId(req);
        const today = new Date().toISOString().split('T')[0];
        let stats = await Stats.findOne();
        if (!stats) {
            stats = await Stats.create({});
        }
        
        const uniqueKey = deviceId + '_' + today;
        const uniqueClaims = stats.uniqueClaims || new Map();
        
        if (!uniqueClaims.has(uniqueKey) || 
            (Date.now() - uniqueClaims.get(uniqueKey) > 48 * 60 * 60 * 1000)) {
            uniqueClaims.set(uniqueKey, Date.now());
            stats.totalClaims = (stats.totalClaims || 0) + 1;
            stats.dailyClaims.set(today, (stats.dailyClaims.get(today) || 0) + 1);
            link.claims = (link.claims || 0) + 1;
            link.dailyClaims.set(today, (link.dailyClaims.get(today) || 0) + 1);
            
            await link.save();
            await stats.save();
            console.log('🎁 New unique claim (48hr):', deviceId.substring(0, 10));
        }
        
        res.json({
            success: true,
            claims: stats.totalClaims || 0
        });
    } catch (error) {
        console.error('❌ Track claim error:', error);
        res.status(500).json({ error: 'Failed to track claim' });
    }
});

// ==================== STATS ====================
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

app.get('/api/stats/:linkId', authMiddleware, async (req, res) => {
    try {
        const { linkId } = req.params;
        const link = await Link.findOne({ id: linkId });
        
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }
        
        const today = new Date().toISOString().split('T')[0];
        
        res.json({
            linkId: link.id,
            name: link.name,
            totalVisitors: link.visits || 0,
            totalClaims: link.claims || 0,
            todayVisits: link.dailyVisits?.get(today) || 0,
            todayClaims: link.dailyClaims?.get(today) || 0,
            dailyVisits: Object.fromEntries(link.dailyVisits || new Map()),
            dailyClaims: Object.fromEntries(link.dailyClaims || new Map()),
            status: link.status,
            expiryDate: link.expiryDate || null
        });
    } catch (error) {
        console.error('❌ Stats error:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// ==================== USER DASHBOARD ====================
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
            const linkId = 'dashboard_' + Date.now() + '_' + crypto.randomBytes(8).toString('hex');
            res.json({
                url: '/user-dashboard/' + linkId,
                linkName: null,
                linkId: null
            });
        }
    } catch (error) {
        console.error('❌ Dashboard link error:', error);
        res.status(500).json({ error: 'Failed to generate dashboard link' });
    }
});

// ==================== VISIT STATS ====================
app.get('/api/visit-stats/:linkId', async (req, res) => {
    try {
        const { linkId } = req.params;
        console.log('📊 Fetching stats for linkId:', linkId);
        
        let link = await Link.findOne({ id: linkId });
        
        if (!link) {
            link = await Link.findOne({ dashboardId: linkId });
        }
        
        if (!link) {
            const allLinks = await Link.find({});
            const matched = allLinks.find(l => 
                l.id.includes(linkId) || 
                (l.dashboardId && l.dashboardId.includes(linkId)) ||
                linkId.includes(l.id)
            );
            if (matched) {
                link = matched;
            }
        }
        
        if (!link) {
            console.log('⚠️ Link not found with ID:', linkId);
            return res.status(404).json({ 
                error: 'Link not found',
                message: 'No link found with this ID'
            });
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

// ==================== RENEWAL ====================

app.post('/api/renewal/request-from-dashboard', async (req, res) => {
    try {
        const { linkId, linkName, plan, days, amount } = req.body;
        
        if (!linkId || !plan) {
            return res.status(400).json({ error: 'Link ID and plan required' });
        }
        
        const existing = await RenewalRequest.findOne({ 
            linkId: linkId, 
            status: { $in: ['pending', 'paid'] } 
        });
        
        if (existing) {
            return res.status(400).json({
                error: 'You already have a pending renewal request',
                existingRequest: existing
            });
        }
        
        const renewalRequest = new RenewalRequest({
            id: 'renewal_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex'),
            linkId: linkId,
            linkName: linkName || 'Unknown',
            plan: plan,
            days: days || 0,
            amount: amount || 0,
            status: 'pending',
            createdAt: new Date(),
            paidAt: null,
            approvedAt: null,
            transactionId: null,
            upiId: 'pending'
        });
        
        await renewalRequest.save();
        
        res.json({
            success: true,
            requestId: renewalRequest.id,
            message: 'Renewal request created successfully'
        });
        
    } catch (error) {
        console.error('❌ Renewal request error:', error);
        res.status(500).json({ error: 'Failed to create renewal request' });
    }
});

app.get('/api/renewal/history/:linkId', async (req, res) => {
    try {
        const { linkId } = req.params;
        const history = await RenewalRequest.find({ linkId: linkId })
            .sort({ createdAt: -1 });
        
        res.json({
            history: history,
            count: history.length
        });
    } catch (error) {
        console.error('❌ Renewal history error:', error);
        res.status(500).json({ error: 'Failed to fetch history' });
    }
});

app.post('/api/renewal/request', async (req, res) => {
    try {
        const { linkId, plan } = req.body;
        const link = await Link.findOne({ id: linkId });
        
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }
        
        const pricingDoc = await Pricing.findOne();
        const pricing = pricingDoc?.pricing || {};
        
        const planDays = {
            '3days': 3,
            '7days': 7,
            '15days': 15,
            '1month': 30,
            '3months': 90,
            '6months': 180,
            '12months': 365
        };
        
        const days = planDays[plan];
        if (!days) {
            return res.status(400).json({ error: 'Invalid plan' });
        }
        
        const amount = pricing[plan] || 0;
        if (amount === 0) {
            return res.status(400).json({ error: 'Price not set for this plan' });
        }
        
        const existing = await RenewalRequest.findOne({ 
            linkId: linkId, 
            status: { $in: ['pending', 'paid'] } 
        });
        
        if (existing) {
            return res.status(400).json({
                error: 'You already have a pending renewal request',
                existingRequest: existing
            });
        }
        
        res.json({
            success: true,
            message: 'Please complete payment to submit renewal request',
            amount: amount,
            plan: plan,
            days: days,
            requiresPayment: true
        });
    } catch (error) {
        console.error('❌ Renewal request error:', error);
        res.status(500).json({ error: 'Failed to process request' });
    }
});

app.post('/api/renewal/confirm-payment', async (req, res) => {
    try {
        const { linkId, plan, transactionId } = req.body;
        const link = await Link.findOne({ id: linkId });
        
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }
        
        const pricingDoc = await Pricing.findOne();
        const pricing = pricingDoc?.pricing || {};
        const paymentSettings = pricingDoc?.paymentSettings || {};
        
        const planDays = {
            '3days': 3,
            '7days': 7,
            '15days': 15,
            '1month': 30,
            '3months': 90,
            '6months': 180,
            '12months': 365
        };
        
        const days = planDays[plan];
        const amount = pricing[plan] || 0;
        
        const renewalRequest = new RenewalRequest({
            id: 'renewal_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex'),
            linkId: linkId,
            linkName: link.name,
            plan: plan,
            days: days,
            amount: amount,
            status: 'paid',
            paidAt: new Date(),
            transactionId: transactionId || 'TXN_' + Date.now(),
            upiId: paymentSettings?.details?.upiId || 'admin@upi'
        });
        
        await renewalRequest.save();
        
        res.json({
            success: true,
            requestId: renewalRequest.id,
            message: 'Payment confirmed! Waiting for admin approval.'
        });
    } catch (error) {
        console.error('❌ Confirm payment error:', error);
        res.status(500).json({ error: 'Failed to confirm payment' });
    }
});

app.get('/api/renewal/requests', authMiddleware, async (req, res) => {
    try {
        const requests = await RenewalRequest.find({ 
            status: { $in: ['pending', 'paid'] } 
        }).sort({ createdAt: -1 });
        res.json(requests);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch requests' });
    }
});

app.get('/api/renewal/status/:linkId', async (req, res) => {
    try {
        const { linkId } = req.params;
        const request = await RenewalRequest.findOne({ linkId: linkId })
            .sort({ createdAt: -1 });
        
        res.json({
            hasRequest: !!request,
            request: request || null,
            status: request?.status || 'none'
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch status' });
    }
});

app.post('/api/renewal/pay/:requestId', authMiddleware, async (req, res) => {
    try {
        const { requestId } = req.params;
        const request = await RenewalRequest.findOne({ id: requestId });
        
        if (!request) {
            return res.status(404).json({ error: 'Request not found' });
        }
        if (request.status === 'approved' || request.status === 'rejected') {
            return res.status(400).json({ error: 'Request already processed' });
        }
        
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
        const { requestId } = req.params;
        const request = await RenewalRequest.findOne({ id: requestId });
        
        if (!request) {
            return res.status(404).json({ error: 'Request not found' });
        }
        if (request.status !== 'paid') {
            return res.status(400).json({ error: 'Payment not confirmed yet' });
        }
        
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
        
        res.json({ success: true, message: 'Renewal approved! Link extended.' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to approve renewal' });
    }
});

app.post('/api/renewal/reject/:requestId', authMiddleware, async (req, res) => {
    try {
        const { requestId } = req.params;
        const request = await RenewalRequest.findOne({ id: requestId });
        
        if (!request) {
            return res.status(404).json({ error: 'Request not found' });
        }
        
        request.status = 'rejected';
        await request.save();
        
        res.json({ success: true, message: 'Renewal rejected' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to reject renewal' });
    }
});

app.delete('/api/renewal/request/:requestId', authMiddleware, async (req, res) => {
    try {
        const { requestId } = req.params;
        await RenewalRequest.findOneAndDelete({ id: requestId });
        res.json({ success: true, message: 'Request removed' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to remove request' });
    }
});

app.post('/api/admin/pricing', authMiddleware, async (req, res) => {
    try {
        const { pricing, paymentSettings } = req.body;
        let pricingDoc = await Pricing.findOne();
        
        if (!pricingDoc) {
            pricingDoc = new Pricing();
        }
        
        if (pricing) pricingDoc.pricing = pricing;
        if (paymentSettings) pricingDoc.paymentSettings = paymentSettings;
        pricingDoc.updatedAt = new Date();
        
        await pricingDoc.save();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update pricing' });
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
    console.log('🗄️ Database: MongoDB Atlas');
    console.log('📊 Stats: 48hr Unique Visitor + Claim tracking');
    console.log('📱 WhatsApp: Renewal requests via WhatsApp');
    console.log('🔍 Dashboard Map: dashboard_xxx → link_xxx mapping');
    console.log('🔗 Dashboard Link Generator: Search by name/ID');
    console.log('═══════════════════════════════════════════');
});