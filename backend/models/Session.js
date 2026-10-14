const mongoose = require('mongoose');

const SessionSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true,
        unique: true
    },
    userId: {
        type: String,
        required: true
    },
    deviceKey: {
        type: String,
        default: null
    },
    fingerprint: {
        type: String,
        default: null
    },
    csrfToken: {
        type: String,
        default: null
    },
    ip: {
        type: String,
        default: null
    },
    userAgent: {
        type: String,
        default: null
    },
    deviceName: {
        type: String,
        default: 'Unknown Device'
    },
    deviceType: {
        type: String,
        default: 'Desktop'
    },
    isActive: {
        type: Boolean,
        default: true
    },
    lastActivity: {
        type: Date,
        default: Date.now
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    expiresAt: {
        type: Date,
        required: true
    }
});

// ✅ FIXED: Removed duplicate index on `token` (unique: true already creates it)
// Compound and single-field indexes for session queries
SessionSchema.index({ expiresAt: 1 });
SessionSchema.index({ userId: 1, isActive: 1 });
SessionSchema.index({ deviceKey: 1 });
SessionSchema.index({ fingerprint: 1 });
SessionSchema.index({ lastActivity: -1 });

module.exports = mongoose.model('Session', SessionSchema);
