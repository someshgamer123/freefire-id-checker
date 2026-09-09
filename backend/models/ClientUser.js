const mongoose = require('mongoose');

const ClientUserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true,
        unique: true
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
    },
    approvedAt: {
        type: Date,
        default: null
    }
});

ClientUserSchema.index({ email: 1 });
ClientUserSchema.index({ phone: 1 });
ClientUserSchema.index({ status: 1 });

module.exports = mongoose.model('ClientUser', ClientUserSchema);
