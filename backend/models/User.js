const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    passcode: {
        type: String,
        required: true,
    },
    theme: {
        type: String,
        default: 'dark',
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
    ip: {
        type: String,
        default: null
    },
    secretKey: {
        type: String,
        default: 'admin@2024'
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('User', UserSchema);
