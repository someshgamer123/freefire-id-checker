const mongoose = require('mongoose');

const RenewalRequestSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    linkId: { type: String, required: true },
    linkName: { type: String, required: true },
    plan: { type: String, required: true },
    days: { type: Number, required: true },
    amount: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'paid', 'approved', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('RenewalRequest', RenewalRequestSchema);
