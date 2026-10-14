const mongoose = require('mongoose');

const RenewalRequestSchema = new mongoose.Schema({
    id: {
        type: String,
        required: true,
        unique: true
    },
    linkId: {
        type: String,
        required: true,
        index: true
    },
    linkName: {
        type: String,
        required: true
    },
    plan: {
        type: String,
        required: true
    },
    days: {
        type: Number,
        required: true
    },
    amount: {
        type: Number,
        required: true
    },
    transactionId: {
        type: String,
        default: null
    },
    status: {
        type: String,
        enum: ['pending', 'paid', 'approved', 'rejected'],
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

// ✅ FIXED: No duplicate index on `id` (unique: true handles it automatically)
RenewalRequestSchema.index({ status: 1 });
RenewalRequestSchema.index({ createdAt: -1 });

module.exports = mongoose.model('RenewalRequest', RenewalRequestSchema);
