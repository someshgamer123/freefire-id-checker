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
        required: false,
        default: '',
        trim: true
    },
    googleId: {
        type: String,
        default: null
    },
    // ✅ FIX: Added 'otp' to allowed enum values
    authMethod: {
        type: String,
        enum: ['email', 'google', 'otp'],
        default: 'otp'
    },
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending'
    },
    profileCompleted: {
        type: Boolean,
        default: false
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
    createdAt: {
        type: Date,
        default: Date.now
    },
    approvedAt: {
        type: Date,
        default: null
    }
});

RenewalUserSchema.index({ email: 1 }, { unique: true });
RenewalUserSchema.index({ googleId: 1 }, { sparse: true });
RenewalUserSchema.index({ status: 1 });
RenewalUserSchema.index({ createdAt: -1 });
RenewalUserSchema.index({ status: 1, createdAt: -1 });

module.exports = mongoose.model('RenewalUser', RenewalUserSchema);
