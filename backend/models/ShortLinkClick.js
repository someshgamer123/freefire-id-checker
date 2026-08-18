const mongoose = require('mongoose');

const ShortLinkClickSchema = new mongoose.Schema({
    shortLinkId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'ShortLink',
        required: true
    },
    ip: {
        type: String,
        default: null
    },
    userAgent: {
        type: String,
        default: null
    },
    deviceName: {
        type: String,
        default: 'Unknown'
    },
    deviceType: {
        type: String,
        default: 'Browser'
    },
    referer: {
        type: String,
        default: null
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
});

ShortLinkClickSchema.index({ shortLinkId: 1, timestamp: -1 });

module.exports = mongoose.model('ShortLinkClick', ShortLinkClickSchema);