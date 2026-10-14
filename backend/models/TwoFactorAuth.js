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
        type: Array,
        default: []
    },
    isEnabled: {
        type: Boolean,
        default: false
    },
    verifiedAt: {
        type: Date,
        default: null
    }
});

// ✅ FIXED: Removed duplicate index on `userId` (unique: true handles it automatically)

module.exports = mongoose.model('TwoFactorAuth', TwoFactorAuthSchema);
