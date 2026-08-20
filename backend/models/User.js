const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    passcode: {
        type: String,
        required: true,
    },
    theme: {
        type: String,
        default: 'light',
        enum: ['light', 'dark']
    },
    email: {
        type: String,
        default: ''
    },
    phone: {
        type: String,
        default: ''
    },
    fingerprint: {
        type: String,
        default: null
    },
    secretKey: {
        type: String,
        default: '@somu93370899'
    },
    rememberToken: {
        type: String,
        default: null
    },
    rememberTokenExpiry: {
        type: Date,
        default: null
    },
    // ✅ NEW: Saved Devices (Remember Me)
    savedDevices: [{
        fingerprint: { type: String, required: true },
        deviceName: { type: String, default: 'Unknown Device' },
        deviceType: { type: String, default: 'Browser' },
        lastUsed: { type: Date, default: Date.now },
        expiry: { type: Date, default: null },
        createdAt: { type: Date, default: Date.now }
    }],
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('User', UserSchema);