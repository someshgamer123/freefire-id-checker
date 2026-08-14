const mongoose = require('mongoose');

const PopupSettingsSchema = new mongoose.Schema({
    image: {
        type: String,
        default: null
    },
    title: {
        type: String,
        default: '🎁 Claim Your Reward'
    },
    buttonText: {
        type: String,
        default: 'Claim Now'
    },
    subtitle: {
        type: String,
        default: 'Tap below to unlock your reward'
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('PopupSettings', PopupSettingsSchema);