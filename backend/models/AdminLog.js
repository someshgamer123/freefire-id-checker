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
            'LOGIN', 'LOGOUT', 'LOGIN_FAILED', 'LOGIN_LOCKED', 'CSRF_ATTEMPT', 'IP_BLOCKED',
            'CREATE_LINK', 'UPDATE_LINK', 'DELETE_LINK', 'CREATE_DASHBOARD_LINK',
            'UPDATE_STATUS', 'CREATE_USER', 'UPDATE_USER', 'DELETE_USER',
            'UPDATE_SETTINGS', 'UPDATE_PRICING', 'UPDATE_WHATSAPP',
            'APPROVE_RENEWAL', 'REJECT_RENEWAL', 'MARK_PAID', 'DELETE_RENEWAL',
            'PASSCODE_CHANGE', 'PASSCODE_CHANGE_FAILED', 'THEME_CHANGE', 'BACKGROUND_CHANGE',
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

// Indexes
AdminLogSchema.index({ userId: 1, timestamp: -1 });
AdminLogSchema.index({ action: 1 });
AdminLogSchema.index({ timestamp: -1 });

module.exports = mongoose.model('AdminLog', AdminLogSchema);