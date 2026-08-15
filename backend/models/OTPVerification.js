const mongoose = require('mongoose');

const OTPVerificationSchema = new mongoose.Schema({
    deviceId: {
        type: String,
        required: true
    },
    otp: {
        type: String,
        required: true
    },
    method: {
        type: String,
        enum: ['email', 'sms'],
        required: true
    },
    contact: {
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
    verifiedAt: {
        type: Date,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

OTPVerificationSchema.index({ deviceId: 1 });
OTPVerificationSchema.index({ expiresAt: 1 });

module.exports = mongoose.model('OTPVerification', OTPVerificationSchema);