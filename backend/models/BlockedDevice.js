const mongoose = require('mongoose');

const BlockedDeviceSchema = new mongoose.Schema({
    deviceKey: {
        type: String,
        required: true,
        unique: true
    },
    fingerprint: {
        type: String,
        required: true
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
    isPermanent: {
        type: Boolean,
        default: false
    },
    lastAttempt: {
        type: Date,
        default: Date.now
    }
});

BlockedDeviceSchema.index({ fingerprint: 1 });
BlockedDeviceSchema.index({ ip: 1 });
BlockedDeviceSchema.index({ blockedUntil: 1 });

module.exports = mongoose.model('BlockedDevice', BlockedDeviceSchema);
