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
    // ✅ NEW: App Open Mode
    appOpen: {
        type: Boolean,
        default: false
    },
    // ✅ NEW: Schedule Expiry
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

ShortLinkSchema.index({ code: 1 });
ShortLinkSchema.index({ createdAt: -1 });
ShortLinkSchema.index({ expiryDate: 1 });

module.exports = mongoose.model('ShortLink', ShortLinkSchema);