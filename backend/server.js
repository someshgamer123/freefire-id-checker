const express = require('express');
const app = express();
const port = process.env.PORT || 3000;
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// ==================== TRUST PROXY ====================
app.set('trust proxy', 1);

// ==================== SECURITY HEADERS ====================
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

// ==================== CORS ====================
app.use(cors({
    origin: ['http://localhost:3000', 'https://freefire-id-checker.onrender.com', 'https://*.onrender.com'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

// ==================== RATE LIMITING ====================
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

// ==================== DATABASE ====================
const DB_FILE = path.join(__dirname, 'database.json');
let dbCache = null;
let dbLastRead = 0;

function readDB() {
    try {
        if (!fs.existsSync(DB_FILE)) {
            console.log('📁 Creating new database...');
            const db = getDefaultDB();
            writeDB(db);
            return db;
        }
        const data = fs.readFileSync(DB_FILE, 'utf8');
        if (!data || data.trim() === '') {
            console.warn('⚠️ Empty database, reinitializing...');
            const db = getDefaultDB();
            writeDB(db);
            return db;
        }
        const parsed = JSON.parse(data);
        if (!parsed.stats) { parsed.stats = getDefaultStats(); }
        if (!parsed.stats.uniqueVisitors) parsed.stats.uniqueVisitors = {};
        if (!parsed.stats.uniqueClaims) parsed.stats.uniqueClaims = {};
        if (!parsed.stats.dailyVisitors) parsed.stats.dailyVisitors = {};
        if (!parsed.stats.dailyClaims) parsed.stats.dailyClaims = {};
        if (parsed.stats.totalVisitors === undefined) parsed.stats.totalVisitors = 0;
        if (parsed.stats.totalClaims === undefined) parsed.stats.totalClaims = 0;
        if (!parsed.popupSettings) {
            parsed.popupSettings = {
                image: null,
                title: '🎁 Claim Your Reward',
                buttonText: 'Claim Now',
                subtitle: 'Tap below to unlock your reward'
            };
        }
        if (!parsed.settings) parsed.settings = {};
        if (parsed.settings.background === undefined) parsed.settings.background = null;
        if (parsed.links) {
            parsed.links.forEach(link => {
                if (!link.visits) link.visits = 0;
                if (!link.dailyVisits) link.dailyVisits = {};
                if (!link.claims) link.claims = 0;
                if (!link.dailyClaims) link.dailyClaims = {};
                if (!link.popupSettings) {
                    link.popupSettings = {
                        image: null,
                        title: '🎁 Claim Your Reward',
                        buttonText: 'Claim Now',
                        subtitle: 'Tap below to unlock your reward'
                    };
                }
            });
        }
        dbCache = parsed;
        dbLastRead = Date.now();
        return parsed;
    } catch (e) {
        console.error('❌ Database read error:', e);
        try {
            const db = getDefaultDB();
            writeDB(db);
            return db;
        } catch (e2) {
            console.error('❌ CRITICAL: Cannot recover database:', e2);
            return getDefaultDB();
        }
    }
}

function writeDB(data) {
    try {
        if (!data.stats) { data.stats = getDefaultStats(); }
        if (!data.stats.uniqueVisitors) data.stats.uniqueVisitors = {};
        if (!data.stats.uniqueClaims) data.stats.uniqueClaims = {};
        if (!data.stats.dailyVisitors) data.stats.dailyVisitors = {};
        if (!data.stats.dailyClaims) data.stats.dailyClaims = {};
        if (data.stats.totalVisitors === undefined) data.stats.totalVisitors = 0;
        if (data.stats.totalClaims === undefined) data.stats.totalClaims = 0;
        if (!data.settings) data.settings = {};
        if (data.settings.background === undefined) data.settings.background = null;
        if (data.links) {
            data.links.forEach(link => {
                if (!link.visits) link.visits = 0;
                if (!link.dailyVisits) link.dailyVisits = {};
                if (!link.claims) link.claims = 0;
                if (!link.dailyClaims) link.dailyClaims = {};
                if (!link.popupSettings) {
                    link.popupSettings = {
                        image: null,
                        title: '🎁 Claim Your Reward',
                        buttonText: 'Claim Now',
                        subtitle: 'Tap below to unlock your reward'
                    };
                }
            });
        }
        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
        dbCache = data;
        dbLastRead = Date.now();
        console.log('✅ Database saved at:', new Date().toISOString());
        return true;
    } catch (e) {
        console.error('❌ Database write error:', e);
        return false;
    }
}

function getDefaultStats() {
    return {
        totalVisitors: 0,
        totalClaims: 0,
        dailyVisitors: {},
        dailyClaims: {},
        uniqueVisitors: {},
        uniqueClaims: {}
    };
}

function getDefaultDB() {
    const hashedPasscode = bcrypt.hashSync('951753', 10);
    return {
        admin: {
            passcode: hashedPasscode,
            theme: 'light'
        },
        links: [],
        settings: {
            background: null
        },
        popupSettings: {
            image: null,
            title: '🎁 Claim Your Reward',
            buttonText: 'Claim Now',
            subtitle: 'Tap below to unlock your reward'
        },
        sessions: [],
        parentLink: null,
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
                upiId: 'admin@upi'
            }
        },
        renewalRequests: [],
        stats: getDefaultStats()
    };
}

function getPasscodeHash(passcode) {
    return bcrypt.hashSync(passcode, 10);
}

function verifyPasscode(passcode, hash) {
    try {
        return bcrypt.compareSync(passcode, hash);
    } catch (e) {
        console.error('❌ Verification error:', e);
        return false;
    }
}

function generateLinkId() {
    return 'link_' + Date.now() + '_' + crypto.randomBytes(8).toString('hex');
}

function getDeviceId(req) {
    const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';
    const fingerprint = crypto.createHash('sha256').update(ip + userAgent).digest('hex');
    return fingerprint;
}

function isUnique24hr(store, deviceId) {
    const now = Date.now();
    const today = new Date().toISOString().split('T')[0];
    for (const key in store) {
        if (store[key] && (now - store[key] > 24 * 60 * 60 * 1000)) {
            delete store[key];
        }
    }
    const key = deviceId + '_' + today;
    if (store[key]) { return false; }
    store[key] = now;
    return true;
}

// ==================== AUTH ====================
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRY = '7d';

function hashPasscode(passcode) {
    return bcrypt.hashSync(passcode, 10);
}

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

function authMiddleware(req, res, next) {
    const token = req.cookies?.adminToken;
    const csrfToken = req.headers['x-csrf-token'];
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
    const db = readDB();
    if (!db) {
        return res.status(500).json({ error: 'Database error' });
    }
    const session = db.sessions?.find(s => s.token === token);
    if (!session || session.csrfToken !== csrfToken) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    req.user = decoded;
    next();
}

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
        const db = readDB();
        if (!db) {
            return res.status(500).json({ error: 'Database error' });
        }
        const isValid = verifyPasscode(passcode, db.admin.passcode);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid passcode' });
        }
        const token = generateToken('admin');
        const csrfToken = generateCSRFToken();
        db.sessions = [];
        db.sessions.push({
            token: token,
            csrfToken: csrfToken,
            createdAt: Date.now(),
            expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000
        });
        writeDB(db);
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

app.post('/api/admin/logout', authMiddleware, (req, res) => {
    try {
        const db = readDB();
        const token = req.cookies?.adminToken;
        if (db && db.sessions) {
            db.sessions = db.sessions.filter(s => s.token !== token);
            writeDB(db);
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
        const db = readDB();
        if (!oldPasscode || !newPasscode) {
            return res.status(400).json({ error: 'Both passcodes required' });
        }
        if (!/^\d+$/.test(newPasscode) || newPasscode.length !== 6) {
            return res.status(400).json({ error: 'New passcode must be 6 digits' });
        }
        const isValid = verifyPasscode(oldPasscode, db.admin.passcode);
        if (!isValid) {
            return res.status(401).json({ error: 'Current passcode is incorrect' });
        }
        db.admin.passcode = hashPasscode(newPasscode);
        writeDB(db);
        db.sessions = [];
        writeDB(db);
        res.clearCookie('adminToken');
        res.json({ success: true, message: 'Passcode changed. Please login again.' });
    } catch (error) {
        console.error('❌ Passcode change error:', error);
        res.status(500).json({ error: 'Passcode change failed' });
    }
});

app.post('/api/admin/theme', authMiddleware, (req, res) => {
    try {
        const { theme } = req.body;
        const db = readDB();
        if (!['light', 'dark'].includes(theme)) {
            return res.status(400).json({ error: 'Invalid theme' });
        }
        db.admin.theme = theme;
        writeDB(db);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update theme' });
    }
});

app.post('/api/admin/background', authMiddleware, (req, res) => {
    try {
        const { background } = req.body;
        const db = readDB();
        if (background && !background.startsWith('data:image') && !background.startsWith('http')) {
            return res.status(400).json({ error: 'Invalid image format' });
        }
        db.settings.background = background || null;
        writeDB(db);
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Background update error:', error);
        res.status(500).json({ error: 'Failed to update background' });
    }
});

app.post('/api/admin/popup', authMiddleware, (req, res) => {
    try {
        const { image, title, buttonText, subtitle, linkId } = req.body;
        const db = readDB();
        if (linkId) {
            const link = db.links.find(l => l.id === linkId);
            if (!link) {
                return res.status(404).json({ error: 'Link not found' });
            }
            if (!link.popupSettings) link.popupSettings = {};
            if (image !== undefined) link.popupSettings.image = image;
            if (title !== undefined) link.popupSettings.title = title;
            if (buttonText !== undefined) link.popupSettings.buttonText = buttonText;
            if (subtitle !== undefined) link.popupSettings.subtitle = subtitle;
        } else {
            if (!db.popupSettings) db.popupSettings = {};
            if (image !== undefined) db.popupSettings.image = image;
            if (title !== undefined) db.popupSettings.title = title;
            if (buttonText !== undefined) db.popupSettings.buttonText = buttonText;
            if (subtitle !== undefined) db.popupSettings.subtitle = subtitle;
        }
        writeDB(db);
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Popup update error:', error);
        res.status(500).json({ error: 'Failed to update popup settings' });
    }
});

app.get('/api/popup-settings/:linkId?', (req, res) => {
    try {
        const { linkId } = req.params;
        const db = readDB();
        if (linkId) {
            const link = db.links.find(l => l.id === linkId);
            if (!link) {
                return res.status(404).json({ error: 'Link not found' });
            }
            const settings = link.popupSettings || db.popupSettings || {
                image: null,
                title: '🎁 Claim Your Reward',
                buttonText: 'Claim Now',
                subtitle: 'Tap below to unlock your reward'
            };
            return res.json(settings);
        }
        res.json(db.popupSettings || {
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
app.get('/api/links', authMiddleware, (req, res) => {
    try {
        const db = readDB();
        res.json(db?.links || []);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch links' });
    }
});

app.post('/api/links', authMiddleware, (req, res) => {
    try {
        const { name, video, claim, buttonText, headline, expiryDate, popupSettings } = req.body;
        const db = readDB();
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
        const newLink = {
            id: generateLinkId(),
            name: name.substring(0, 100),
            video: video || 'https://youtu.be/dQw4w9WgXcQ',
            claim: claim || '#',
            buttonText: (buttonText || 'Claim Now').substring(0, 50),
            headline: (headline || '').substring(0, 200),
            created: new Date().toISOString(),
            expiryDate: expiryDate || null,
            status: 'active',
            visits: 0,
            dailyVisits: {},
            claims: 0,
            dailyClaims: {},
            popupSettings: popupSettings || {
                image: null,
                title: '🎁 Claim Your Reward',
                buttonText: 'Claim Now',
                subtitle: 'Tap below to unlock your reward'
            }
        };
        db.links.push(newLink);
        writeDB(db);
        res.json(newLink);
    } catch (error) {
        console.error('❌ Create link error:', error);
        res.status(500).json({ error: 'Failed to create link' });
    }
});

app.put('/api/links/:id', authMiddleware, (req, res) => {
    try {
        const { id } = req.params;
        const { name, video, claim, buttonText, headline, status, expiryDate, popupSettings } = req.body;
        const db = readDB();
        const link = db.links.find(l => l.id === id);
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
        writeDB(db);
        res.json(link);
    } catch (error) {
        console.error('❌ Update link error:', error);
        res.status(500).json({ error: 'Failed to update link' });
    }
});

app.put('/api/links/:id/status', authMiddleware, (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        const db = readDB();
        if (!['active', 'suspended', 'disabled'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        const link = db.links.find(l => l.id === id);
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }
        link.status = status;
        writeDB(db);
        res.json(link);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update status' });
    }
});

app.delete('/api/links/:id', authMiddleware, (req, res) => {
    try {
        const { id } = req.params;
        const db = readDB();
        db.links = db.links.filter(l => l.id !== id);
        writeDB(db);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete link' });
    }
});

// ==================== PUBLIC LINK ====================
app.get('/api/link/:id', (req, res) => {
    try {
        const { id } = req.params;
        const db = readDB();
        const link = db.links.find(l => l.id === id);
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
        if (link.expiryDate) {
            const expiryDate = new Date(link.expiryDate);
            if (new Date() > expiryDate) {
                return res.status(403).json({
                    error: 'expired',
                    message: 'This link has expired',
                    status: 'expired'
                });
            }
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
        if (!db.stats) db.stats = getDefaultStats();
        if (!db.stats.uniqueVisitors) db.stats.uniqueVisitors = {};
        if (!db.stats.dailyVisitors) db.stats.dailyVisitors = {};
        if (isUnique24hr(db.stats.uniqueVisitors, deviceId)) {
            db.stats.totalVisitors = (db.stats.totalVisitors || 0) + 1;
            db.stats.dailyVisitors[today] = (db.stats.dailyVisitors[today] || 0) + 1;
            link.visits = (link.visits || 0) + 1;
            if (!link.dailyVisits) link.dailyVisits = {};
            link.dailyVisits[today] = (link.dailyVisits[today] || 0) + 1;
            console.log('👤 New unique visitor:', deviceId.substring(0, 10));
        }
        const popupSettings = link.popupSettings || db.popupSettings || {
            image: null,
            title: '🎁 Claim Your Reward',
            buttonText: 'Claim Now',
            subtitle: 'Tap below to unlock your reward'
        };
        writeDB(db);
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
app.post('/api/track-claim/:linkId', (req, res) => {
    try {
        const { linkId } = req.params;
        const db = readDB();
        const link = db.links.find(l => l.id === linkId);
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }
        const deviceId = getDeviceId(req);
        const today = new Date().toISOString().split('T')[0];
        if (!db.stats) db.stats = getDefaultStats();
        if (!db.stats.uniqueClaims) db.stats.uniqueClaims = {};
        if (!db.stats.dailyClaims) db.stats.dailyClaims = {};
        if (isUnique24hr(db.stats.uniqueClaims, deviceId)) {
            db.stats.totalClaims = (db.stats.totalClaims || 0) + 1;
            db.stats.dailyClaims[today] = (db.stats.dailyClaims[today] || 0) + 1;
            link.claims = (link.claims || 0) + 1;
            if (!link.dailyClaims) link.dailyClaims = {};
            link.dailyClaims[today] = (link.dailyClaims[today] || 0) + 1;
            console.log('🎁 New unique claim:', deviceId.substring(0, 10));
        }
        writeDB(db);
        res.json({
            success: true,
            claims: db.stats.totalClaims || 0
        });
    } catch (error) {
        console.error('❌ Track claim error:', error);
        res.status(500).json({ error: 'Failed to track claim' });
    }
});

// ==================== STATS ====================
app.get('/api/all-stats', authMiddleware, (req, res) => {
    try {
        const db = readDB();
        const today = new Date().toISOString().split('T')[0];
        const linkStats = db.links.map(link => ({
            id: link.id,
            name: link.name,
            visits: link.visits || 0,
            claims: link.claims || 0,
            dailyVisits: link.dailyVisits || {},
            dailyClaims: link.dailyClaims || {},
            todayVisits: link.dailyVisits?.[today] || 0,
            todayClaims: link.dailyClaims?.[today] || 0,
            status: link.status,
            expiryDate: link.expiryDate || null
        }));
        res.json({
            global: {
                totalVisitors: db.stats?.totalVisitors || 0,
                totalClaims: db.stats?.totalClaims || 0,
                todayVisitors: db.stats?.dailyVisitors?.[today] || 0,
                todayClaims: db.stats?.dailyClaims?.[today] || 0,
                dailyVisitors: db.stats?.dailyVisitors || {},
                dailyClaims: db.stats?.dailyClaims || {}
            },
            links: linkStats
        });
    } catch (error) {
        console.error('❌ Stats error:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

app.get('/api/stats/:linkId', authMiddleware, (req, res) => {
    try {
        const { linkId } = req.params;
        const db = readDB();
        const link = db.links.find(l => l.id === linkId);
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }
        const today = new Date().toISOString().split('T')[0];
        res.json({
            linkId: link.id,
            name: link.name,
            totalVisitors: link.visits || 0,
            totalClaims: link.claims || 0,
            todayVisits: link.dailyVisits?.[today] || 0,
            todayClaims: link.dailyClaims?.[today] || 0,
            dailyVisits: link.dailyVisits || {},
            dailyClaims: link.dailyClaims || {},
            status: link.status,
            expiryDate: link.expiryDate || null
        });
    } catch (error) {
        console.error('❌ Stats error:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// ==================== USER DASHBOARD ====================
app.get('/api/parent-link', (req, res) => {
    try {
        const db = readDB();
        if (!db) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!db.parentLink) {
            db.parentLink = {
                url: '/user-dashboard/' + generateLinkId(),
                createdAt: new Date().toISOString()
            };
            writeDB(db);
        }
        res.json(db.parentLink);
    } catch (error) {
        console.error('❌ Dashboard link error:', error);
        res.status(500).json({ error: 'Failed to generate dashboard link' });
    }
});

app.get('/api/visit-stats/:linkId', (req, res) => {
    try {
        const { linkId } = req.params;
        const db = readDB();
        const link = db.links.find(l => l.id === linkId);
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }
        res.json({
            linkId: link.id,
            name: link.name,
            totalVisits: link.visits || 0,
            totalClaims: link.claims || 0,
            dailyVisits: link.dailyVisits || {},
            dailyClaims: link.dailyClaims || {},
            status: link.status,
            expiryDate: link.expiryDate || null
        });
    } catch (error) {
        console.error('❌ Visit stats error:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// ==================== RENEWAL ====================
app.post('/api/renewal/request', (req, res) => {
    try {
        const { linkId, plan } = req.body;
        const db = readDB();
        const link = db.links.find(l => l.id === linkId);
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }
        const pricing = db.pricing || {};
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
        const existing = db.renewalRequests?.find(r => r.linkId === linkId && (r.status === 'pending' || r.status === 'paid'));
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

app.post('/api/renewal/confirm-payment', (req, res) => {
    try {
        const { linkId, plan, transactionId } = req.body;
        const db = readDB();
        const link = db.links.find(l => l.id === linkId);
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }
        const pricing = db.pricing || {};
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
        const renewalRequest = {
            id: 'renewal_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex'),
            linkId: linkId,
            linkName: link.name,
            plan: plan,
            days: days,
            amount: amount,
            status: 'paid',
            createdAt: new Date().toISOString(),
            paidAt: new Date().toISOString(),
            approvedAt: null,
            transactionId: transactionId || 'TXN_' + Date.now(),
            upiId: db.paymentSettings?.details?.upiId || 'admin@upi'
        };
        if (!db.renewalRequests) db.renewalRequests = [];
        db.renewalRequests.push(renewalRequest);
        writeDB(db);
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

app.get('/api/renewal/requests', authMiddleware, (req, res) => {
    try {
        const db = readDB();
        const activeRequests = db.renewalRequests?.filter(r => r.status === 'pending' || r.status === 'paid') || [];
        res.json(activeRequests);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch requests' });
    }
});

app.get('/api/renewal/status/:linkId', (req, res) => {
    try {
        const { linkId } = req.params;
        const db = readDB();
        const requests = db.renewalRequests?.filter(r => r.linkId === linkId) || [];
        const latest = requests.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];
        res.json({
            hasRequest: !!latest,
            request: latest || null,
            status: latest?.status || 'none'
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch status' });
    }
});

app.post('/api/renewal/pay/:requestId', authMiddleware, (req, res) => {
    try {
        const { requestId } = req.params;
        const db = readDB();
        const request = db.renewalRequests?.find(r => r.id === requestId);
        if (!request) {
            return res.status(404).json({ error: 'Request not found' });
        }
        if (request.status === 'approved' || request.status === 'rejected') {
            return res.status(400).json({ error: 'Request already processed' });
        }
        request.status = 'paid';
        request.paidAt = new Date().toISOString();
        writeDB(db);
        res.json({ success: true, message: 'Payment marked as paid' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to mark payment' });
    }
});

app.post('/api/renewal/approve/:requestId', authMiddleware, (req, res) => {
    try {
        const { requestId } = req.params;
        const db = readDB();
        const request = db.renewalRequests?.find(r => r.id === requestId);
        if (!request) {
            return res.status(404).json({ error: 'Request not found' });
        }
        if (request.status !== 'paid') {
            return res.status(400).json({ error: 'Payment not confirmed yet' });
        }
        const link = db.links.find(l => l.id === request.linkId);
        if (link) {
            const currentExpiry = link.expiryDate ? new Date(link.expiryDate) : new Date();
            const newExpiry = new Date(currentExpiry);
            newExpiry.setDate(newExpiry.getDate() + request.days);
            link.expiryDate = newExpiry.toISOString();
            link.status = 'active';
        }
        request.status = 'approved';
        request.approvedAt = new Date().toISOString();
        writeDB(db);
        res.json({ success: true, message: 'Renewal approved! Link extended.' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to approve renewal' });
    }
});

app.post('/api/renewal/reject/:requestId', authMiddleware, (req, res) => {
    try {
        const { requestId } = req.params;
        const db = readDB();
        const request = db.renewalRequests?.find(r => r.id === requestId);
        if (!request) {
            return res.status(404).json({ error: 'Request not found' });
        }
        request.status = 'rejected';
        writeDB(db);
        res.json({ success: true, message: 'Renewal rejected' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to reject renewal' });
    }
});

app.delete('/api/renewal/request/:requestId', authMiddleware, (req, res) => {
    try {
        const { requestId } = req.params;
        const db = readDB();
        const index = db.renewalRequests?.findIndex(r => r.id === requestId);
        if (index === -1 || index === undefined) {
            return res.status(404).json({ error: 'Request not found' });
        }
        db.renewalRequests.splice(index, 1);
        writeDB(db);
        res.json({ success: true, message: 'Request removed' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to remove request' });
    }
});

app.post('/api/admin/pricing', authMiddleware, (req, res) => {
    try {
        const { pricing, paymentSettings } = req.body;
        const db = readDB();
        if (pricing) db.pricing = pricing;
        if (paymentSettings) db.paymentSettings = paymentSettings;
        writeDB(db);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update pricing' });
    }
});

app.get('/api/pricing', (req, res) => {
    try {
        const db = readDB();
        res.json({
            pricing: db.pricing || {},
            paymentSettings: db.paymentSettings || { method: 'UPI', details: { upiId: 'admin@upi' } }
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch pricing' });
    }
});

app.get('/api/settings', (req, res) => {
    try {
        const db = readDB();
        res.json({
            theme: db.admin?.theme || 'light',
            background: db.settings?.background || null,
            popupSettings: db.popupSettings || {
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

// ==================== START ====================
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
    console.log('💾 Data: Permanent storage with auto-recovery');
    console.log('📊 Stats: 24hr Unique Visitor + Claim tracking');
    console.log('📱 Popup: Per-link customizable');
    console.log('═══════════════════════════════════════════');
});