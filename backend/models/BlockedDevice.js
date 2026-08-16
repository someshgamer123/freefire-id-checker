const mongoose = require('mongoose');

const BlockedDeviceSchema = new mongoose.Schema({
    fingerprint: {
        type: String,
        required: true,
        unique: true
    },
    ip: {
        type: String,
        required: true
    },
    deviceName: {
        type: String,
        default: 'Unknown Device'
    },
    deviceType: {
        type: String,
        default: 'Unknown'
    },
    os: {
        type: String,
        default: 'Unknown'
    },
    browser: {
        type: String,
        default: 'Unknown'
    },
    attempts: {
        type: Number,
        default: 0
    },
    reason: {
        type: String,
        default: 'Too many failed attempts'
    },
    blockedUntil: {
        type: Date,
        default: null
    },
    isPermanent: {
        type: Boolean,
        default: false
    },
    permanentBlockedAt: {
        type: Date,
        default: null
    },
    unblockedAt: {
        type: Date,
        default: null
    },
    lastAttempt: {
        type: Date,
        default: Date.now
    },
    lastEmail: {
        type: String,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

BlockedDeviceSchema.index({ fingerprint: 1 });
BlockedDeviceSchema.index({ ip: 1 });
BlockedDeviceSchema.index({ isPermanent: 1 });
BlockedDeviceSchema.index({ lastAttempt: -1 });

module.exports = mongoose.model('BlockedDevice', BlockedDeviceSchema);