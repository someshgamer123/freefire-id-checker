const mongoose = require('mongoose');

const RenewalUserSchema = new mongoose.Schema({
    // 👤 Basic Info
    name: {
        type: String,
        required: false,       // ✅ Google signup ke waqt empty ho sakta hai
        default: '',
        trim: true
    },
    email: {
        type: String,
        required: true,        // ✅ Email always required (Google se milta hai)
        trim: true,
        lowercase: true
    },
    phone: {
        type: String,
        required: false,       // ✅ Profile complete hone tak empty rahega
        default: '',
        trim: true
    },
    googleId: {
        type: String,
        default: null,
        sparse: true           // ✅ Unique index with sparse (null allowed)
    },
    authMethod: {
        type: String,
        enum: ['email', 'google'],
        default: 'google'
    },

    // 📊 Account Status
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending'
    },
    profileCompleted: {
        type: Boolean,
        default: false
    },

    // 💎 Plan Info
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

    // 📈 Usage Tracking
    linksCreatedThisCycle: {
        type: Number,
        default: 0
    },
    visitorsThisCycle: {
        type: Number,
        default: 0
    },

    // 🕒 Timestamps
    createdAt: {
        type: Date,
        default: Date.now
    },
    approvedAt: {
        type: Date,
        default: null
    }
});

// ==================== INDEXES (No Duplicates) ====================
// ✅ Email index (not unique — allows same email? No, unique hai)
RenewalUserSchema.index({ email: 1 }, { unique: true });

// ✅ googleId sparse index (allows multiple null)
RenewalUserSchema.index({ googleId: 1 }, { sparse: true });

// ✅ Status index (for quick filter)
RenewalUserSchema.index({ status: 1 });

// ✅ Created date index (for sorting)
RenewalUserSchema.index({ createdAt: -1 });

// ✅ Compound index for common queries
RenewalUserSchema.index({ status: 1, createdAt: -1 });

module.exports = mongoose.model('RenewalUser', RenewalUserSchema);
