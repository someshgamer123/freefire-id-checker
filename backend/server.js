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

// ==================== SECURITY HEADERS (UPDATED CSP) ====================
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

function initDB() {
    if (!fs.existsSync(DB_FILE)) {
        const hashedPasscode = getPasscodeHash('951753');
        const db = {
            admin: {
                passcode: hashedPasscode,
                theme: 'light'
            },
            links: [],
            settings: {
                background: null
            },
            sessions: []
        };
        fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
        console.log('═══════════════════════════════════════════');
        console.log('✅ DATABASE CREATED SUCCESSFULLY!');
        console.log('🔑 PASSCODE: 951753');
        console.log('═══════════════════════════════════════════');
    }
}

function readDB() {
    initDB();
    try {
        const data = fs.readFileSync(DB_FILE, 'utf8');
        return JSON.parse(data);
    } catch (e) {
        console.error('❌ Database read error:', e);
        return null;
    }
}

function writeDB(data) {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
    } catch (e) {
        console.error('❌ Database write error:', e);
    }
}

function generateLinkId() {
    return 'link_' + Date.now() + '_' + crypto.randomBytes(8).toString('hex');
}

// ==================== AUTH FUNCTIONS ====================
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

// ==================== AUTH MIDDLEWARE ====================
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

// ==================== ROUTES ====================

// ===== ADMIN LOGIN =====
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

// ===== ADMIN LOGOUT =====
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

// ===== CHANGE PASSCODE =====
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
        res.status(500).json({ error: 'Passcode change failed' });
    }
});

// ===== GET ALL LINKS =====
app.get('/api/links', authMiddleware, (req, res) => {
    try {
        const db = readDB();
        res.json(db?.links || []);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch links' });
    }
});

// ===== CREATE LINK =====
app.post('/api/links', authMiddleware, (req, res) => {
    try {
        const { name, video, claim, buttonText, headline, expiryDate } = req.body;
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
            visits: 0
        };

        db.links.push(newLink);
        writeDB(db);
        res.json(newLink);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create link' });
    }
});

// ===== UPDATE LINK =====
app.put('/api/links/:id', authMiddleware, (req, res) => {
    try {
        const { id } = req.params;
        const { name, video, claim, buttonText, headline, status, expiryDate } = req.body;
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

        writeDB(db);
        res.json(link);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update link' });
    }
});

// ===== UPDATE LINK STATUS =====
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

// ===== DELETE LINK =====
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

// ===== GET LINK BY ID (PUBLIC) =====
app.get('/api/link/:id', (req, res) => {
    try {
        const { id } = req.params;
        const db = readDB();

        const link = db.links.find(l => l.id === id);
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }

        if (link.status !== 'active') {
            return res.status(403).json({ error: `Link is ${link.status}` });
        }

        link.visits++;
        writeDB(db);

        res.json({
            id: link.id,
            video: link.video,
            claim: link.claim,
            buttonText: link.buttonText,
            headline: link.headline
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch link' });
    }
});

// ===== UPDATE THEME =====
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

// ===== UPDATE BACKGROUND =====
app.post('/api/admin/background', authMiddleware, (req, res) => {
    try {
        const { background } = req.body;
        const db = readDB();

        if (background && !/^data:image\/(jpeg|png|gif|webp);base64,/.test(background)) {
            return res.status(400).json({ error: 'Invalid image format' });
        }

        if (background && Buffer.from(background.split(',')[1], 'base64').length > 1024 * 1024) {
            return res.status(400).json({ error: 'Image too large (max 1MB)' });
        }

        db.settings.background = background;
        writeDB(db);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update background' });
    }
});

// ===== GET SETTINGS (PUBLIC) =====
app.get('/api/settings', (req, res) => {
    try {
        const db = readDB();
        res.json({
            theme: db.admin?.theme || 'light',
            background: db.settings?.background || null
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

// ===== SERVE PAGES =====
app.get('/uid', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'uid-checker.html'));
});

app.get('/v/:id', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'video-lock.html'));
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

// ===== START SERVER =====
app.listen(port, '0.0.0.0', () => {
    console.log('═══════════════════════════════════════════');
    console.log('🔒 SECURE SERVER STARTED SUCCESSFULLY!');
    console.log('═══════════════════════════════════════════');
    console.log(`🔧 Admin Panel: http://localhost:${port}/admin/login.html`);
    console.log(`📊 API: http://localhost:${port}/api/links`);
    console.log('═══════════════════════════════════════════');
    console.log('🔑 ADMIN PASSCODE: 951753');
    console.log('⏰ Session: 7 DAYS');
    console.log('═══════════════════════════════════════════');
});