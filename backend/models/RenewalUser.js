const mongoose = require('mongoose');

const RenewalUserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: false,
        default: '',
        trim: true
    },
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true
    },
    phone: {
        type: String,
        required: false,  // ✅ FIX: ab required nahi
        default: '',
        trim: true
    },
    googleId: {
        type: String,
        default: null
    },
    authMethod: {
        type: String,
        enum: ['email', 'google'],
        default: 'google'
    },
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending'
    },
    currentPlan: {
        type: String,
        default: 'none'
    },
    planStartDate: {
        type: Date,
        default: null
    },
    planExpiryDate: {
        type: Date,
        default: null
    },
    lifetimeUnlimited: {
        type: Boolean,
        default: false
    },
    freeTrialUsed: {
        type: Boolean,
        default: false
    },
    freeTrialActivatedAt: {
        type: Date,
        default: null
    },
    linksCreatedThisCycle: {
        type: Number,
        default: 0
    },
    visitorsThisCycle: {
        type: Number,
        default: 0
    },
    profileCompleted: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    approvedAt: {
        type: Date,
        default: null
    }
});

// Indexes
RenewalUserSchema.index({ email: 1 }, { unique: true, sparse: true });
RenewalUserSchema.index({ googleId: 1 }, { sparse: true });
RenewalUserSchema.index({ status: 1 });
RenewalUserSchema.index({ createdAt: -1 });

module.exports = mongoose.model('RenewalUser', RenewalUserSchema);
