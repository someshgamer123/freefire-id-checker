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
    firstAttempt: {
        type: Date,
        default: Date.now
    },
    lastAttempt: {
        type: Date,
        default: Date.now
    }
});

// Indexes
LoginAttemptSchema.index({ ip: 1 });
LoginAttemptSchema.index({ lockedUntil: 1 });

module.exports = mongoose.model('LoginAttempt', LoginAttemptSchema);