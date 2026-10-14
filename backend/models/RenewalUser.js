const mongoose = require('mongoose');

const RenewalUserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
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
        required: true,
        trim: true
    },
    googleId: {
        type: String,
        default: null
    },
    authMethod: {
        type: String,
        enum: ['email', 'google'],
        default: 'email'
    },
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending'
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

// ✅ Compound index for unique email+phone combination
RenewalUserSchema.index({ email: 1, phone: 1 });
RenewalUserSchema.index({ status: 1 });
RenewalUserSchema.index({ createdAt: -1 });
RenewalUserSchema.index({ googleId: 1 }, { sparse: true });

module.exports = mongoose.model('RenewalUser', RenewalUserSchema);
