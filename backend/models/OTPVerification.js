const mongoose = require('mongoose');

const OTPVerificationSchema = new mongoose.Schema({
    phone: {
        type: String,
        required: true
    },
    deviceId: {
        type: String,
        default: null
    },
    otp: {
        type: String,
        required: true
    },
    expiresAt: {
        type: Date,
        required: true
    },
    verified: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// TTL index to auto-delete expired OTPs
OTPVerificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
OTPVerificationSchema.index({ phone: 1 });

module.exports = mongoose.model('OTPVerification', OTPVerificationSchema);
