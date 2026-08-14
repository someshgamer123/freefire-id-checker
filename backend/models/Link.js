const mongoose = require('mongoose');

const LinkSchema = new mongoose.Schema({
    id: {
        type: String,
        required: true,
        unique: true
    },
    name: {
        type: String,
        required: true,
        maxlength: 100
    },
    video: {
        type: String,
        default: 'https://youtu.be/dQw4w9WgXcQ'
    },
    claim: {
        type: String,
        default: '#'
    },
    buttonText: {
        type: String,
        default: 'Claim Now',
        maxlength: 50
    },
    headline: {
        type: String,
        default: '🎬 Watch Video',
        maxlength: 200
    },
    status: {
        type: String,
        enum: ['active', 'suspended', 'disabled'],
        default: 'active'
    },
    expiryDate: {
        type: Date,
        default: null
    },
    visits: {
        type: Number,
        default: 0
    },
    claims: {
        type: Number,
        default: 0
    },
    dailyVisits: {
        type: Map,
        of: Number,
        default: {}
    },
    dailyClaims: {
        type: Map,
        of: Number,
        default: {}
    },
    popupSettings: {
        image: { type: String, default: null },
        title: { type: String, default: '🎁 Claim Your Reward' },
        buttonText: { type: String, default: 'Claim Now' },
        subtitle: { type: String, default: 'Tap below to unlock your reward' }
    },
    created: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Link', LinkSchema);