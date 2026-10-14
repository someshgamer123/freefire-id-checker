const mongoose = require('mongoose');

const LoginAttemptSchema = new mongoose.Schema({
    ip: {
        type: String,
        required: true,
        unique: true
    },
    attempts: {
        type: Number,
        default: 0
    },
    lockedUntil: {
        type: Date,
        default: null
    },
    lastAttempt: {
        type: Date,
        default: Date.now
    }
});

// ✅ FIXED: Removed duplicate index on `ip` (unique: true handles it automatically)
LoginAttemptSchema.index({ lockedUntil: 1 });

module.exports = mongoose.model('LoginAttempt', LoginAttemptSchema);
