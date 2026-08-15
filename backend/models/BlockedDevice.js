const mongoose = require('mongoose');

const BlockedDeviceSchema = new mongoose.Schema({
    fingerprint: {
        type: String,
        required: true
    },
    ip: {
        type: String,
        required: true
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
BlockedDeviceSchema.index({ blockedUntil: 1 });

module.exports = mongoose.model('BlockedDevice', BlockedDeviceSchema);