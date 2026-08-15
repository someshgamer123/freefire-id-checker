const mongoose = require('mongoose');

const AdminLogSchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true
    },
    action: {
        type: String,
        required: true,
        enum: [
            // Authentication
            'LOGIN', 'LOGOUT', 'LOGIN_FAILED', 'LOGIN_LOCKED', 'CSRF_ATTEMPT', 'IP_BLOCKED',
            // Link Management
            'CREATE_LINK', 'UPDATE_LINK', 'DELETE_LINK', 'CREATE_DASHBOARD_LINK',
            'UPDATE_STATUS', 'CREATE_USER', 'UPDATE_USER', 'DELETE_USER',
            // Settings
            'UPDATE_SETTINGS', 'UPDATE_PRICING', 'UPDATE_WHATSAPP',
            // Renewal
            'APPROVE_RENEWAL', 'REJECT_RENEWAL', 'MARK_PAID', 'DELETE_RENEWAL',
            // Admin
            'PASSCODE_CHANGE', 'PASSCODE_CHANGE_FAILED', 'THEME_CHANGE', 'BACKGROUND_CHANGE',
            // 2FA
            '2FA_ENABLE', '2FA_DISABLE', '2FA_VERIFIED', '2FA_FAILED', '2FA_SETUP_STARTED'
        ]
    },
    details: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },
    ip: {
        type: String,
        default: null
    },
    userAgent: {
        type: String,
        default: null
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
});

// ===== Indexes for faster queries =====
AdminLogSchema.index({ userId: 1, timestamp: -1 });
AdminLogSchema.index({ action: 1 });
AdminLogSchema.index({ timestamp: -1 });
AdminLogSchema.index({ ip: 1 });

// ===== Methods =====

// Get formatted timestamp
AdminLogSchema.methods.getFormattedTime = function() {
    return this.timestamp.toLocaleString();
};

// Get short description of action
AdminLogSchema.methods.getActionDescription = function() {
    const descriptions = {
        'LOGIN': 'Admin logged in',
        'LOGOUT': 'Admin logged out',
        'LOGIN_FAILED': 'Failed login attempt',
        'LOGIN_LOCKED': 'Login locked due to too many attempts',
        'CSRF_ATTEMPT': 'CSRF token validation failed',
        'IP_BLOCKED': 'IP address blocked',
        'CREATE_LINK': 'Created new link',
        'UPDATE_LINK': 'Updated link',
        'DELETE_LINK': 'Deleted link',
        'CREATE_DASHBOARD_LINK': 'Generated dashboard link',
        'UPDATE_STATUS': 'Updated link status',
        'CREATE_USER': 'Created new user',
        'UPDATE_USER': 'Updated user',
        'DELETE_USER': 'Deleted user',
        'UPDATE_SETTINGS': 'Updated settings',
        'UPDATE_PRICING': 'Updated pricing plans',
        'UPDATE_WHATSAPP': 'Updated WhatsApp number',
        'APPROVE_RENEWAL': 'Approved renewal request',
        'REJECT_RENEWAL': 'Rejected renewal request',
        'MARK_PAID': 'Marked renewal as paid',
        'DELETE_RENEWAL': 'Deleted renewal request',
        'PASSCODE_CHANGE': 'Changed passcode',
        'PASSCODE_CHANGE_FAILED': 'Failed passcode change attempt',
        'THEME_CHANGE': 'Changed theme',
        'BACKGROUND_CHANGE': 'Changed background',
        '2FA_ENABLE': 'Enabled 2FA',
        '2FA_DISABLE': 'Disabled 2FA',
        '2FA_VERIFIED': '2FA verified successfully',
        '2FA_FAILED': '2FA verification failed',
        '2FA_SETUP_STARTED': 'Started 2FA setup'
    };
    return descriptions[this.action] || this.action;
};

// ===== Static Methods =====

// Get recent logs
AdminLogSchema.statics.getRecentLogs = async function(limit = 50) {
    return this.find()
        .sort({ timestamp: -1 })
        .limit(limit);
};

// Get logs by action
AdminLogSchema.statics.getLogsByAction = async function(action, limit = 50) {
    return this.find({ action: action })
        .sort({ timestamp: -1 })
        .limit(limit);
};

// Get logs by date range
AdminLogSchema.statics.getLogsByDateRange = async function(startDate, endDate) {
    return this.find({
        timestamp: {
            $gte: new Date(startDate),
            $lte: new Date(endDate)
        }
    }).sort({ timestamp: -1 });
};

// Get logs by IP
AdminLogSchema.statics.getLogsByIP = async function(ip, limit = 50) {
    return this.find({ ip: ip })
        .sort({ timestamp: -1 })
        .limit(limit);
};

// Get action statistics
AdminLogSchema.statics.getActionStats = async function() {
    return this.aggregate([
        {
            $group: {
                _id: '$action',
                count: { $sum: 1 },
                lastOccurrence: { $max: '$timestamp' },
                uniqueIPs: { $addToSet: '$ip' }
            }
        },
        {
            $project: {
                action: '$_id',
                count: 1,
                lastOccurrence: 1,
                uniqueIPCount: { $size: '$uniqueIPs' }
            }
        },
        { $sort: { count: -1 } }
    ]);
};

// Get today's logs
AdminLogSchema.statics.getTodayLogs = async function() {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    return this.find({
        timestamp: {
            $gte: today,
            $lt: tomorrow
        }
    }).sort({ timestamp: -1 });
};

// Delete old logs (older than days)
AdminLogSchema.statics.deleteOldLogs = async function(days = 30) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);
    
    return this.deleteMany({
        timestamp: { $lt: cutoffDate }
    });
};

module.exports = mongoose.model('AdminLog', AdminLogSchema);