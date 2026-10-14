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
    userName: {
        type: String,
        default: ''
    },
    assignedUser: {
        type: String,
        default: ''
    },
    creator: {
        type: String,
        default: ''
    },
    linkName: {
        type: String,
        default: 'Link'
    },
    title: {
        type: String,
        default: 'Link'
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
        enum: ['active', 'suspended', 'disabled', 'inactive'],
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
    dailyVisits: {
        type: Object,
        default: {}
    },
    dailyClaims: {
        type: Object,
        default: {}
    },
    uidChecking: {
        type: Boolean,
        default: true
    },
    popupSettings: {
        type: Object,
        default: {}
    },
    image: {
        type: String,
        default: null
    },
    created: {
        type: Date,
        default: Date.now
    }
});

// ✅ FIXED: Removed duplicate index on `id` (unique: true already creates it)
// Added useful indexes for query performance
LinkSchema.index({ assignedUser: 1 });
LinkSchema.index({ userName: 1 });
LinkSchema.index({ status: 1 });
LinkSchema.index({ dashboardId: 1 });
LinkSchema.index({ created: -1 });

module.exports = mongoose.model('Link', LinkSchema);
