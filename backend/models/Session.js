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
    createdAt: {
        type: Date,
        default: Date.now
    },
    expiresAt: {
        type: Date,
        required: true
    },
    lastActivity: {
        type: Date,
        default: Date.now
    },
    isActive: {
        type: Boolean,
        default: true
    }
});

SessionSchema.index({ token: 1 });
SessionSchema.index({ expiresAt: 1 });
SessionSchema.index({ userId: 1, isActive: 1 });

module.exports = mongoose.model('Session', SessionSchema);