const mongoose = require('mongoose');

const OTPVerificationSchema = new mongoose.Schema({
    deviceId: { type: String, required: true },
    otp: { type: String, required: true },
    expiresAt: { type: Date, required: true },
    verified: { type: Boolean, default: false }
});

OTPVerificationSchema.index({ expiresAt: 1 });

module.exports = mongoose.model('OTPVerification', OTPVerificationSchema);
