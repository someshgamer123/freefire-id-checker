const mongoose = require('mongoose');

const PricingSchema = new mongoose.Schema({
    pricing: {
        '3days': { type: Number, default: 50 },
        '7days': { type: Number, default: 100 },
        '15days': { type: Number, default: 200 },
        '1month': { type: Number, default: 500 },
        '3months': { type: Number, default: 1200 },
        '6months': { type: Number, default: 2000 },
        '12months': { type: Number, default: 3500 }
    },
    paymentSettings: {
        method: { type: String, default: 'UPI' },
        details: {
            upiId: { type: String, default: 'admin@upi' },
            qrCode: { type: String, default: null },
            text: { type: String, default: '' }
        }
    },
    whatsappNumber: {
        type: String,
        default: '916372923348'
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Pricing', PricingSchema);