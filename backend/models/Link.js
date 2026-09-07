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
        default: 'Claim Now'
    },
    headline: {
        type: String,
        default: '🎬 Watch Video'
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
    dashboardId: {
        type: String,
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
    created: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Link', LinkSchema);
