const mongoose = require('mongoose');

const TwoFactorAuthSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    secret: { type: String, required: true },
    isEnabled: { type: Boolean, default: false }
});

module.exports = mongoose.model('TwoFactorAuth', TwoFactorAuthSchema);
