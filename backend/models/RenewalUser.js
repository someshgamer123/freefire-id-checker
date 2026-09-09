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
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending'
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

RenewalUserSchema.index({ email: 1, phone: 1 });
RenewalUserSchema.index({ status: 1 });

module.exports = mongoose.model('RenewalUser', RenewalUserSchema);