const express = require('express');
const app = express();
const port = process.env.PORT || 3000;
const path = require('path');
const fs = require('fs');

app.use(express.static('.'));
app.use(express.json());

// Database file
const DB_FILE = path.join(__dirname, 'database.json');

// Initialize database
function initDB() {
    if (!fs.existsSync(DB_FILE)) {
        const db = {
            admin: {
                password: 'somesh5363',
                theme: 'light'
            },
            links: [],
            settings: {
                background: null // 9:16 background image URL
            }
        };
        fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
        console.log('✅ Database created!');
    }
}

function readDB() {
    initDB();
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function generateLinkId() {
    return 'link_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
}

// ==================== API ROUTES ====================

// Get all links
app.get('/api/links', (req, res) => {
    const db = readDB();
    res.json(db.links);
});

// Create new link
app.post('/api/links', (req, res) => {
    const db = readDB();
    const { name, video, claim, buttonText, headline, expiryDate } = req.body;
    
    const newLink = {
        id: generateLinkId(),
        name: name || 'Link ' + (db.links.length + 1),
        video: video || 'https://youtu.be/dQw4w9WgXcQ',
        claim: claim || '#',
        buttonText: buttonText || 'Claim Now',
        headline: headline || '',
        created: new Date().toISOString(),
        expiryDate: expiryDate || null,
        status: 'active',
        visits: 0
    };
    
    db.links.push(newLink);
    writeDB(db);
    res.json(newLink);
});

// Update link
app.put('/api/links/:id', (req, res) => {
    const db = readDB();
    const { name, video, claim, buttonText, headline, status, expiryDate } = req.body;
    const link = db.links.find(l => l.id === req.params.id);
    if (link) {
        if (name !== undefined) link.name = name;
        if (video !== undefined) link.video = video;
        if (claim !== undefined) link.claim = claim;
        if (buttonText !== undefined) link.buttonText = buttonText;
        if (headline !== undefined) link.headline = headline;
        if (status !== undefined) link.status = status;
        if (expiryDate !== undefined) link.expiryDate = expiryDate;
        writeDB(db);
        res.json(link);
    } else {
        res.status(404).json({ error: 'Link not found' });
    }
});

// Update link status
app.put('/api/links/:id/status', (req, res) => {
    const db = readDB();
    const { status } = req.body;
    const link = db.links.find(l => l.id === req.params.id);
    if (link) {
        link.status = status;
        writeDB(db);
        res.json(link);
    } else {
        res.status(404).json({ error: 'Link not found' });
    }
});

// Delete link
app.delete('/api/links/:id', (req, res) => {
    const db = readDB();
    db.links = db.links.filter(l => l.id !== req.params.id);
    writeDB(db);
    res.json({ success: true });
});

// Get link by ID
app.get('/api/link/:id', (req, res) => {
    const db = readDB();
    const link = db.links.find(l => l.id === req.params.id);
    if (link && link.status === 'active') {
        link.visits++;
        writeDB(db);
        res.json(link);
    } else if (link && link.status === 'suspended') {
        res.status(403).json({ error: 'Link is suspended' });
    } else if (link && link.status === 'disabled') {
        res.status(403).json({ error: 'Link is disabled' });
    } else {
        res.status(404).json({ error: 'Link not found' });
    }
});

// Admin login
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    const db = readDB();
    if (password === db.admin.password) {
        res.json({ success: true, token: 'admin_' + Date.now() });
    } else {
        res.status(401).json({ success: false, error: 'Invalid password' });
    }
});

// Update admin password
app.post('/api/admin/password', (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const db = readDB();
    if (oldPassword === db.admin.password) {
        db.admin.password = newPassword;
        writeDB(db);
        res.json({ success: true });
    } else {
        res.status(401).json({ success: false, error: 'Invalid password' });
    }
});

// Update theme
app.post('/api/admin/theme', (req, res) => {
    const { theme } = req.body;
    const db = readDB();
    db.admin.theme = theme;
    writeDB(db);
    res.json({ success: true });
});

// Get settings
app.get('/api/settings', (req, res) => {
    const db = readDB();
    res.json({ theme: db.admin.theme, background: db.settings.background || null });
});

// Update background
app.post('/api/admin/background', (req, res) => {
    const { background } = req.body;
    const db = readDB();
    db.settings.background = background;
    writeDB(db);
    res.json({ success: true });
});

// Serve visitor pages
app.get('/uid', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'uid-checker.html'));
});

app.get('/v/:id', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'video-lock.html'));
});

// Root - Redirect to admin
app.get('/', (req, res) => {
    res.redirect('/admin/login.html');
});

app.listen(port, () => {
    console.log('═══════════════════════════════════════════');
    console.log('✅ SERVER STARTED SUCCESSFULLY!');
    console.log('═══════════════════════════════════════════');
    console.log(`🔧 Admin Panel: http://localhost:${port}/admin/login.html`);
    console.log(`📊 API: http://localhost:${port}/api/links`);
    console.log('═══════════════════════════════════════════');
});