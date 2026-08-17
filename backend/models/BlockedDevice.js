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
        enum: ['attacker', 'admin', 'visitor'],
        default: 'visitor'
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
    blockLevel: {
        type: Number,
        default: 0 // 0 = Not blocked, 1 = 48h, 2 = 7 days, 3 = Permanent
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
    createdAt: {
        type: Date,
        default: Date.now
    }
});

BlockedDeviceSchema.index({ fingerprint: 1 });
BlockedDeviceSchema.index({ ip: 1 });
BlockedDeviceSchema.index({ deviceType: 1 });
BlockedDeviceSchema.index({ isPermanent: 1 });

module.exports = mongoose.model('BlockedDevice', BlockedDeviceSchema);