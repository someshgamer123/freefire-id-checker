const mongoose = require('mongoose');

const AdminSessionSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true,
        unique: true
    },
    ip: {
        type: String,
        required: true
    },
    userAgent: {
        type: String,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 86400 // 24 hours (automatic expiry)
    },
    expiresAt: {
        type: Date,
        required: true
    },
    isActive: {
        type: Boolean,
        default: true
    }
});

// Indexes for faster queries
AdminSessionSchema.index({ token: 1 });
AdminSessionSchema.index({ expiresAt: 1 });
AdminSessionSchema.index({ ip: 1 });

module.exports = mongoose.model('AdminSession', AdminSessionSchema);