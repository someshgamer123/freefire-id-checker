const mongoose = require('mongoose');

const RenewalRequestSchema = new mongoose.Schema({
    id: {
        type: String,
        required: true,
        unique: true
    },
    linkId: {
        type: String,
        required: true
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
    status: {
        type: String,
        enum: ['pending', 'paid', 'approved', 'rejected'],
        default: 'pending'
    },
    transactionId: {
        type: String,
        default: null
    },
    upiId: {
        type: String,
        default: 'admin@upi'
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    paidAt: {
        type: Date,
        default: null
    },
    approvedAt: {
        type: Date,
        default: null
    }
});

module.exports = mongoose.model('RenewalRequest', RenewalRequestSchema);