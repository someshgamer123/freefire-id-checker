const mongoose = require('mongoose');

const ShortLinkSchema = new mongoose.Schema({
    code: {
        type: String,
        required: true,
        unique: true // Unique index automatically created
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
    createdBy: {
        type: String,
        default: 'admin'
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastClicked: {
        type: Date,
        default: null
    }
});

// Duplicate code index hata diya gaya hai:
ShortLinkSchema.index({ createdAt: -1 });
ShortLinkSchema.index({ expiryDate: 1 });

module.exports = mongoose.model('ShortLink', ShortLinkSchema);
