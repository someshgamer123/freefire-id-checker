const mongoose = require('mongoose');

const ShortLinkSchema = new mongoose.Schema({
    code: {
        type: String,
        required: true,
        unique: true
    },
    originalUrl: {
        type: String,
        required: true
    },
    title: {
        type: String,
        default: 'Untitled Link'
    },
    visits: {
        type: Number,
        default: 0
    },
    clicks24h: {
        type: Number,
        default: 0
    },
    status: {
        type: String,
        enum: ['active', 'disabled'],
        default: 'active'
    },
    appOpen: {
        type: Boolean,
        default: false
    },
    appScheme: {
        type: String,
        default: ''
    },
    appStoreLink: {
        type: String,
        default: ''
    },
    expiryDate: {
        type: Date,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

ShortLinkSchema.index({ createdAt: -1 });

module.exports = mongoose.model('ShortLink', ShortLinkSchema);
