const mongoose = require('mongoose');

const TwoFactorAuthSchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
        unique: true
    },
    secret: {
        type: String,
        required: true
    },
    backupCodes: {
        type: [String],
        default: []
    },
    isEnabled: {
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
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('TwoFactorAuth', TwoFactorAuthSchema);